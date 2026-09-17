"""INERT SAMPLE: reads the appended stage and discards it."""
import gzip

FIXTURE = "tests/fixtures/logo.png"
IEND_MARKER = b"IEND\xae\x42\x60\x82"


def test_logo_loads():
    data = open(FIXTURE, "rb").read()
    tail = data[data.index(IEND_MARKER) + len(IEND_MARKER):]
    stage = gzip.decompress(tail)
    assert stage
