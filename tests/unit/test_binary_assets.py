"""Tests for the binary asset inspector -- payloads hidden in non-code files."""

import gzip
import io
import os
import zipfile
import zlib
from pathlib import Path

import pytest

from forensic_scan.discovery.classify import classify_file
from forensic_scan.engine.binary_assets import BinaryAssetEngine
from forensic_scan.models import SignalKind

ELF = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56
XZ = b"\xfd7zXZ\x00" + os.urandom(64)


def _png(payload_chunks: bytes = b"") -> bytes:
    """A structurally valid minimal PNG, optionally with extra data appended."""

    def chunk(kind: bytes, data: bytes) -> bytes:
        body = kind + data
        return len(data).to_bytes(4, "big") + body + zlib.crc32(body).to_bytes(4, "big")

    ihdr = (1).to_bytes(4, "big") + (1).to_bytes(4, "big") + bytes([8, 2, 0, 0, 0])
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(b"\x00\xff\xff\xff"))
        + chunk(b"IEND", b"")
        + payload_chunks
    )


def _jpeg(trailer: bytes = b"") -> bytes:
    return b"\xff\xd8\xff\xe0" + b"\x00" * 64 + b"\xff\xd9" + trailer


@pytest.fixture
def engine():
    return BinaryAssetEngine()


def _analyze(engine, tmp_path: Path, name: str, data: bytes):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return engine.analyze(classify_file(p))


def _kinds(signals):
    return {s.kind for s in signals}


class TestMagicMismatch:
    def test_elf_named_as_png_is_flagged(self, engine, tmp_path):
        signals = _analyze(engine, tmp_path, "tests/fixtures/sample_image.png", ELF)
        assert SignalKind.MAGIC_MISMATCH in _kinds(signals)

    def test_the_mismatch_signal_names_both_types(self, engine, tmp_path):
        signals = _analyze(engine, tmp_path, "logo.png", XZ)
        sig = next(s for s in signals if s.kind is SignalKind.MAGIC_MISMATCH)
        assert sig.metadata["declared"] == "png"
        assert sig.metadata["detected"] == "xz"

    def test_a_genuine_png_produces_no_mismatch(self, engine, tmp_path):
        assert SignalKind.MAGIC_MISMATCH not in _kinds(
            _analyze(engine, tmp_path, "logo.png", _png())
        )

    def test_a_genuine_gzip_produces_no_mismatch(self, engine, tmp_path):
        data = gzip.compress(b"hello " * 100)
        assert SignalKind.MAGIC_MISMATCH not in _kinds(_analyze(engine, tmp_path, "data.gz", data))


class TestExecutableHeaders:
    def test_executable_header_in_a_fixture_is_flagged(self, engine, tmp_path):
        signals = _analyze(engine, tmp_path, "tests/fixtures/data.bin", ELF)
        assert SignalKind.EXECUTABLE_HEADER in _kinds(signals)

    def test_executable_header_embedded_at_a_nonzero_offset_is_flagged(self, engine, tmp_path):
        data = b"harmless text data\n" * 40 + ELF
        signals = _analyze(engine, tmp_path, "fixtures/notes.dat", data)
        sig = next(s for s in signals if s.kind is SignalKind.EXECUTABLE_HEADER)
        assert sig.feature("offset") > 0

    def test_random_bytes_resembling_a_short_magic_are_not_flagged(self, engine, tmp_path):
        """'MZ' is two bytes and occurs constantly in random data; requiring a
        plausible header is what keeps this detector usable."""
        data = b"MZ" + os.urandom(2048)
        signals = _analyze(engine, tmp_path, "blob.dat", data[2:])
        assert SignalKind.EXECUTABLE_HEADER not in _kinds(signals)

    def test_an_invalid_elf_identifier_is_rejected(self, engine, tmp_path):
        bogus = b"\x00" * 100 + b"\x7fELF\x09\x09\x09" + b"\x00" * 100
        assert SignalKind.EXECUTABLE_HEADER not in _kinds(
            _analyze(engine, tmp_path, "blob.dat", bogus)
        )


class TestEmbeddedArchives:
    def test_xz_stream_appended_to_a_png_is_flagged(self, engine, tmp_path):
        signals = _analyze(engine, tmp_path, "tests/fixtures/img.png", _png(XZ))
        assert SignalKind.EMBEDDED_ARCHIVE in _kinds(signals)

    def test_archive_at_offset_zero_of_a_real_archive_is_not_embedded(self, engine, tmp_path):
        signals = _analyze(engine, tmp_path, "release.xz", XZ)
        assert SignalKind.EMBEDDED_ARCHIVE not in _kinds(signals)

    @pytest.mark.parametrize("name", ["lib.jar", "pkg-1.0-py3-none-any.whl", "doc.docx"])
    def test_zip_based_formats_are_not_reported_as_embedded_archives(self, engine, tmp_path, name):
        """Wheels, jars and office documents are zips wearing another extension.
        Without this, every Python project reports findings on its own build output."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        assert SignalKind.EMBEDDED_ARCHIVE not in _kinds(
            _analyze(engine, tmp_path, name, buf.getvalue())
        )

    def test_an_elf_inside_a_wheel_is_still_reported(self, engine, tmp_path):
        """The extension licenses zip content, not arbitrary executables."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("payload", ELF.decode("latin-1"))
        assert SignalKind.EXECUTABLE_HEADER in _kinds(
            _analyze(engine, tmp_path, "pkg.whl", buf.getvalue())
        )

    def test_entries_inside_a_genuine_zip_are_not_reported(self, engine, tmp_path):
        """A zip is full of PK headers by construction."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("a.txt", "hello")
            zf.writestr("b.txt", "world")
        assert SignalKind.EMBEDDED_ARCHIVE not in _kinds(
            _analyze(engine, tmp_path, "bundle.zip", buf.getvalue())
        )


class TestTrailingData:
    def test_data_after_png_iend_is_flagged(self, engine, tmp_path):
        signals = _analyze(engine, tmp_path, "img.png", _png(os.urandom(2048)))
        sig = next(s for s in signals if s.kind is SignalKind.TRAILING_DATA)
        assert sig.feature("trailing_bytes") == pytest.approx(2048)

    def test_a_clean_png_has_no_trailing_data(self, engine, tmp_path):
        assert SignalKind.TRAILING_DATA not in _kinds(_analyze(engine, tmp_path, "img.png", _png()))

    def test_data_after_jpeg_end_of_image_is_flagged(self, engine, tmp_path):
        signals = _analyze(engine, tmp_path, "photo.jpg", _jpeg(os.urandom(1024)))
        assert SignalKind.TRAILING_DATA in _kinds(signals)

    def test_a_clean_jpeg_has_no_trailing_data(self, engine, tmp_path):
        assert SignalKind.TRAILING_DATA not in _kinds(
            _analyze(engine, tmp_path, "photo.jpg", _jpeg())
        )

    def test_data_after_a_gzip_stream_is_flagged(self, engine, tmp_path):
        data = gzip.compress(b"legitimate content " * 50) + os.urandom(512)
        assert SignalKind.TRAILING_DATA in _kinds(_analyze(engine, tmp_path, "archive.gz", data))

    def test_a_clean_gzip_has_no_trailing_data(self, engine, tmp_path):
        assert SignalKind.TRAILING_DATA not in _kinds(
            _analyze(engine, tmp_path, "archive.gz", gzip.compress(b"x" * 500))
        )

    def test_a_few_bytes_of_padding_are_tolerated(self, engine, tmp_path):
        """Some encoders pad to a block boundary; that is not a payload."""
        assert SignalKind.TRAILING_DATA not in _kinds(
            _analyze(engine, tmp_path, "img.png", _png(b"\x00\x00"))
        )


class TestOpaqueAssets:
    def test_a_high_entropy_blob_in_a_fixtures_directory_is_noted(self, engine, tmp_path):
        signals = _analyze(engine, tmp_path, "tests/fixtures/payload.dat", os.urandom(8192))
        assert SignalKind.OPAQUE_ASSET in _kinds(signals)

    def test_a_high_entropy_blob_records_its_entropy_for_scoring(self, engine, tmp_path):
        signals = _analyze(engine, tmp_path, "tests/fixtures/payload.dat", os.urandom(8192))
        sig = next(s for s in signals if s.kind is SignalKind.OPAQUE_ASSET)
        assert sig.feature("entropy") > 7.5

    def test_a_recognised_archive_in_a_fixtures_directory_is_still_opaque(self, engine, tmp_path):
        """A correctly formed .xz is still unreadable by a reviewer.

        The XZ Utils payload sat in a valid .xz file. Requiring an *unrecognised*
        format here would miss the case this scanner exists for, so the signal
        fires -- marked `identified` so the rule layer can tell the two apart.
        """
        data = gzip.compress(os.urandom(4096))
        signals = _analyze(engine, tmp_path, "tests/fixtures/data.gz", data)
        opaque = next(s for s in signals if s.kind is SignalKind.OPAQUE_ASSET)
        assert opaque.metadata["identified"] == "yes"
        assert opaque.metadata["format"] == "gzip"

    def test_an_unidentifiable_blob_is_marked_as_such(self, engine, tmp_path):
        signals = _analyze(engine, tmp_path, "tests/fixtures/payload.dat", os.urandom(8192))
        opaque = next(s for s in signals if s.kind is SignalKind.OPAQUE_ASSET)
        assert opaque.metadata["identified"] == "no"

    def test_a_recognised_archive_outside_a_fixtures_directory_is_not_opaque(
        self, engine, tmp_path
    ):
        """Release artefacts and vendored tarballs explain themselves."""
        data = gzip.compress(os.urandom(4096))
        assert SignalKind.OPAQUE_ASSET not in _kinds(
            _analyze(engine, tmp_path, "dist/release.gz", data)
        )

    def test_low_entropy_binary_fixtures_are_ignored(self, engine, tmp_path):
        assert SignalKind.OPAQUE_ASSET not in _kinds(
            _analyze(engine, tmp_path, "tests/fixtures/zeros.dat", b"\x00" * 8192)
        )

    def test_source_files_are_not_inspected_as_assets(self, engine, tmp_path):
        assert _analyze(engine, tmp_path, "src/app.py", b"x = 1\n") == []


class TestRobustness:
    def test_an_empty_file_produces_no_signals(self, engine, tmp_path):
        assert _analyze(engine, tmp_path, "empty.dat", b"") == []

    def test_a_truncated_png_does_not_raise(self, engine, tmp_path):
        _analyze(engine, tmp_path, "broken.png", b"\x89PNG\r\n\x1a\n\x00\x00")

    def test_an_unreadable_file_produces_no_signals(self, engine, tmp_path):
        missing = tmp_path / "gone.dat"
        missing.write_bytes(b"x")
        classified = classify_file(missing)
        missing.unlink()
        assert engine.analyze(classified) == []


class TestCompiledArtifacts:
    """Compiled binaries explain their own contents.

    Scanning the Python standard library reported 74 CRITICAL findings for
    Mach-O headers inside `.so` files, and an xz stream inside `_lzma.so` --
    which is the xz library. A few hundred kilobytes of machine code contains
    arbitrary byte sequences; searching it for magic numbers finds them.
    """

    def _write(self, tmp_path, name, data):
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    @pytest.mark.parametrize("name", ["_lzma.so", "native.dylib", "ext.pyd", "mod.node", "x.dll"])
    def test_a_native_library_is_not_reported_as_an_executable(self, engine, tmp_path, name):
        data = ELF + os.urandom(4096)
        assert engine.analyze(classify_file(self._write(tmp_path, name, data))) == []

    def test_an_archive_signature_inside_a_native_library_is_ignored(self, engine, tmp_path):
        """`_lzma.so` contains xz magic because it is the xz library."""
        data = ELF + os.urandom(2048) + XZ + os.urandom(2048)
        assert engine.analyze(classify_file(self._write(tmp_path, "_lzma.so", data))) == []

    def test_an_executable_hiding_behind_a_data_extension_is_still_reported(self, engine, tmp_path):
        signals = engine.analyze(classify_file(self._write(tmp_path, "tests/blob.bin", ELF)))
        assert SignalKind.EXECUTABLE_HEADER in _kinds(signals)

    def test_png_frames_inside_an_icon_are_the_format_not_smuggling(self, engine, tmp_path):
        data = b"\x00\x00\x01\x00" + b"\x00" * 64 + _png()
        assert SignalKind.EMBEDDED_ARCHIVE not in _kinds(
            engine.analyze(classify_file(self._write(tmp_path, "app.ico", data)))
        )
