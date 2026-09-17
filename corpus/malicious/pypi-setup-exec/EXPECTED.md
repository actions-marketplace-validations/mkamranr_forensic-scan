# Expected: FOR-001 or FOR-004, FOR-005, FOR-007

The PyPI install-hook pattern: `setup.py` decodes and executes a blob at install
time, so `pip install` alone is enough to run it.
