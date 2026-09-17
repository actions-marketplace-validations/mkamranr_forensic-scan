"""A setup.py that genuinely builds a C extension.

Calls `subprocess` and reads files during install -- both things the build
inspector looks for -- for entirely ordinary reasons.
"""
import subprocess
import sys
from pathlib import Path

from setuptools import Extension, setup


def pkg_config(package):
    """Ask pkg-config for compiler flags, as thousands of packages do."""
    try:
        out = subprocess.check_output(["pkg-config", "--cflags", "--libs", package])
    except (OSError, subprocess.CalledProcessError):
        return [], []
    flags = out.decode().split()
    return (
        [f[2:] for f in flags if f.startswith("-I")],
        [f[2:] for f in flags if f.startswith("-l")],
    )


includes, libraries = pkg_config("zlib")
long_description = Path("README.md").read_text(encoding="utf-8") if Path("README.md").exists() else ""

setup(
    name="samplelib",
    version="2.1.0",
    long_description=long_description,
    long_description_content_type="text/markdown",
    python_requires=">=3.9",
    ext_modules=[
        Extension(
            "samplelib._speedups",
            sources=["src/speedups.c"],
            include_dirs=includes,
            libraries=libraries or ["z"],
            extra_compile_args=["-O2"] if sys.platform != "win32" else [],
        )
    ],
)
