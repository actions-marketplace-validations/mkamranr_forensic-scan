"""Base64 and zlib used for exactly what they are for.

Decoders appear here alongside file reads. What is missing -- and what makes the
difference -- is any execution sink for the decoded bytes to reach.
"""
import base64
import gzip
import json
import zlib
from pathlib import Path


def load_compressed_config(path: Path) -> dict:
    with gzip.open(path, "rb") as handle:
        return json.loads(handle.read().decode("utf-8"))


def decode_session_token(token: str) -> dict:
    padded = token + "=" * (-len(token) % 4)
    return json.loads(zlib.decompress(base64.urlsafe_b64decode(padded)))


def encode_attachment(data: bytes) -> str:
    return base64.b64encode(zlib.compress(data, level=9)).decode("ascii")
