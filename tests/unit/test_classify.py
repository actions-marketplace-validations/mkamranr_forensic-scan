"""Tests for file classification: what is this file, and is it what it claims?"""

import gzip
import zlib
from pathlib import Path

import pytest

from forensic_scan.discovery.classify import (
    ContentCategory,
    FileRole,
    classify_file,
    sniff,
)

PNG_HEADER = b"\x89PNG\r\n\x1a\n"
ELF_HEADER = b"\x7fELF\x02\x01\x01\x00"
XZ_HEADER = b"\xfd7zXZ\x00"
GZIP_HEADER = b"\x1f\x8b\x08\x00"
PE_HEADER = b"MZ\x90\x00"


class TestSniff:
    @pytest.mark.parametrize(
        "data,expected_name,expected_category",
        [
            (ELF_HEADER + b"\x00" * 32, "elf", ContentCategory.EXECUTABLE),
            (PE_HEADER + b"\x00" * 32, "pe", ContentCategory.EXECUTABLE),
            (b"\xcf\xfa\xed\xfe" + b"\x00" * 32, "mach-o", ContentCategory.EXECUTABLE),
            (b"\x00asm\x01\x00\x00\x00", "wasm", ContentCategory.EXECUTABLE),
            (GZIP_HEADER + b"\x00" * 32, "gzip", ContentCategory.ARCHIVE),
            (XZ_HEADER + b"\x00" * 32, "xz", ContentCategory.ARCHIVE),
            (b"BZh9" + b"\x00" * 32, "bzip2", ContentCategory.ARCHIVE),
            (b"PK\x03\x04" + b"\x00" * 32, "zip", ContentCategory.ARCHIVE),
            (b"\x28\xb5\x2f\xfd" + b"\x00" * 32, "zstd", ContentCategory.ARCHIVE),
            (PNG_HEADER + b"\x00" * 32, "png", ContentCategory.IMAGE),
            (b"\xff\xd8\xff\xe0" + b"\x00" * 32, "jpeg", ContentCategory.IMAGE),
            (b"GIF89a" + b"\x00" * 32, "gif", ContentCategory.IMAGE),
            (b"%PDF-1.7" + b"\x00" * 32, "pdf", ContentCategory.DOCUMENT),
        ],
    )
    def test_recognises_signature(self, data, expected_name, expected_category):
        detected = sniff(data)
        assert detected is not None
        assert detected.name == expected_name
        assert detected.category is expected_category

    def test_recognises_tar_by_its_offset_257_magic(self):
        data = bytearray(b"\x00" * 512)
        data[257:262] = b"ustar"
        detected = sniff(bytes(data))
        assert detected is not None and detected.name == "tar"

    def test_returns_none_for_plain_text(self):
        assert sniff(b"#!/usr/bin/env python\nprint('hi')\n") is None

    def test_returns_none_for_empty_input(self):
        assert sniff(b"") is None

    def test_does_not_confuse_java_class_with_mach_o_fat_binary(self):
        """Both start ca fe ba be; the following bytes disambiguate."""
        java = b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\x00" * 16
        assert sniff(java).name == "java-class"


class TestClassifyFile:
    def _write(self, tmp_path: Path, name: str, data: bytes) -> Path:
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    def test_python_source_is_source_with_a_language(self, tmp_path):
        p = self._write(tmp_path, "mod.py", b"x = 1\n")
        c = classify_file(p)
        assert c.role is FileRole.SOURCE
        assert c.language == "python"
        assert not c.is_binary

    @pytest.mark.parametrize(
        "name,language",
        [
            ("a.js", "javascript"),
            ("a.mjs", "javascript"),
            ("a.cjs", "javascript"),
            ("a.jsx", "javascript"),
            ("a.ts", "typescript"),
            ("a.tsx", "tsx"),
            ("a.c", "c"),
            ("a.h", "c"),
        ],
    )
    def test_maps_extensions_to_tree_sitter_languages(self, tmp_path, name, language):
        c = classify_file(self._write(tmp_path, name, b"// x\n"))
        assert c.language == language

    def test_real_png_is_an_asset_with_no_mismatch(self, tmp_path):
        p = self._write(tmp_path, "logo.png", PNG_HEADER + b"\x00" * 64)
        c = classify_file(p)
        assert c.role is FileRole.ASSET
        assert c.mismatch is False
        assert c.is_binary

    def test_elf_disguised_as_png_is_a_mismatch(self, tmp_path):
        """The FOR-002 case: extension claims an image, content is an executable."""
        p = self._write(tmp_path, "tests/fixtures/sample_image.png", ELF_HEADER + b"\x00" * 64)
        c = classify_file(p)
        assert c.mismatch is True
        assert c.detected.name == "elf"
        assert c.declared == "png"

    def test_xz_archive_disguised_as_png_is_a_mismatch(self, tmp_path):
        p = self._write(tmp_path, "fixture.png", XZ_HEADER + b"\x00" * 64)
        c = classify_file(p)
        assert c.mismatch is True
        assert c.detected.category is ContentCategory.ARCHIVE

    def test_gzip_correctly_named_is_not_a_mismatch(self, tmp_path):
        p = self._write(tmp_path, "data.gz", gzip.compress(b"hello world"))
        assert classify_file(p).mismatch is False

    def test_unknown_extension_with_binary_content_is_not_a_mismatch(self, tmp_path):
        """A .dat file makes no claim about its contents, so nothing is violated."""
        p = self._write(tmp_path, "blob.dat", zlib.compress(b"x" * 500))
        c = classify_file(p)
        assert c.mismatch is False
        assert c.role is FileRole.ASSET

    def test_text_content_in_a_binary_extension_is_a_mismatch(self, tmp_path):
        p = self._write(tmp_path, "image.png", b"just some text, definitely not a png\n")
        assert classify_file(p).mismatch is True


class TestBuildFileDetection:
    def _write(self, tmp_path, rel, data=b"x\n"):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    @pytest.mark.parametrize(
        "rel,kind",
        [
            ("setup.py", "python-setup"),
            ("package.json", "npm-manifest"),
            ("Makefile", "make"),
            ("makefile", "make"),
            ("GNUmakefile", "make"),
            ("CMakeLists.txt", "cmake"),
            ("configure.ac", "autoconf"),
            ("m4/build-to-host.m4", "autoconf-m4"),
            ("scripts/postinstall.js", "npm-lifecycle"),
            ("build.rs", "cargo-build"),
            ("binding.gyp", "node-gyp"),
        ],
    )
    def test_recognises_build_files(self, tmp_path, rel, kind):
        c = classify_file(self._write(tmp_path, rel))
        assert c.is_build is True
        assert c.build_kind == kind

    def test_setup_py_is_both_build_and_parseable_python(self, tmp_path):
        c = classify_file(self._write(tmp_path, "setup.py", b"from setuptools import setup\n"))
        assert c.is_build and c.language == "python" and c.role is FileRole.SOURCE

    def test_ordinary_source_is_not_a_build_file(self, tmp_path):
        c = classify_file(self._write(tmp_path, "src/app.py"))
        assert c.is_build is False and c.build_kind is None
