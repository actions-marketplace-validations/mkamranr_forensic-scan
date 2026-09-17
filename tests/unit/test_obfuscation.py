"""Tests for Module B -- dynamic execution and structural obfuscation."""

from pathlib import Path

import pytest

from forensic_scan.engine.obfuscation import ObfuscationEngine
from forensic_scan.models import SignalKind
from forensic_scan.parser.registry import ParserRegistry


@pytest.fixture
def engine():
    return ObfuscationEngine(ParserRegistry())


def _run(engine, source: bytes, language: str, name: str = "x"):
    return engine.analyze(Path(name), source, language)


def _kinds(signals):
    return {s.kind for s in signals}


def _of(signals, kind):
    return [s for s in signals if s.kind is kind]


class TestDynamicExecutionSinks:
    @pytest.mark.parametrize(
        "source,language",
        [
            (b"eval(payload)\n", "python"),
            (b"exec(payload)\n", "python"),
            (b"import os\nos.system(cmd)\n", "python"),
            (b"import marshal\nmarshal.loads(blob)\n", "python"),
            (b"eval(payload);\n", "javascript"),
            (b"new Function(payload)();\n", "javascript"),
            (b"const vm = require('vm');\nvm.runInNewContext(src);\n", "javascript"),
            (b"int main(){ system(cmd); }\n", "c"),
            (b"int main(){ void *h = dlopen(lib, 2); }\n", "c"),
        ],
    )
    def test_detects_sinks_across_languages(self, engine, source, language):
        assert SignalKind.DYNAMIC_EXEC_SINK in _kinds(_run(engine, source, language)) or (
            SignalKind.DYNAMIC_IMPORT in _kinds(_run(engine, source, language))
        )

    def test_the_signal_names_the_sink(self, engine):
        signals = _of(_run(engine, b"eval(x)\n", "python"), SignalKind.DYNAMIC_EXEC_SINK)
        assert signals[0].metadata["sink"] == "eval"

    def test_the_signal_records_the_line(self, engine):
        src = b"# comment\n# comment\neval(x)\n"
        signals = _of(_run(engine, src, "python"), SignalKind.DYNAMIC_EXEC_SINK)
        assert signals[0].location.line == 3

    def test_pandas_dataframe_eval_is_not_a_sink(self, engine):
        """`df.eval("a + b")` is everywhere in legitimate Python. A scanner that
        fires on it is a scanner nobody runs."""
        src = b'import pandas\nresult = df.eval("a + b")\n'
        assert SignalKind.DYNAMIC_EXEC_SINK not in _kinds(_run(engine, src, "python"))

    def test_a_method_named_compile_on_an_object_is_not_a_sink(self, engine):
        src = b"pattern = regex.compile(r'x')\n"
        assert SignalKind.DYNAMIC_EXEC_SINK not in _kinds(_run(engine, src, "python"))

    def test_dotted_sinks_still_match(self, engine):
        src = b"import subprocess\nsubprocess.Popen(cmd)\n"
        assert SignalKind.DYNAMIC_EXEC_SINK in _kinds(_run(engine, src, "python"))

    def test_a_definition_of_a_function_named_eval_is_not_a_call(self, engine):
        assert SignalKind.DYNAMIC_EXEC_SINK not in _kinds(
            _run(engine, b"def eval(x):\n    return x\n", "python")
        )


class TestTaintedSinks:
    PY = b"""import base64
BLOB = "VGhpcyBpcyBhIGxvbmcgYmFzZTY0IHBheWxvYWQgc3RyaW5nIGhlcmU="
exec(base64.b64decode(BLOB))
"""

    def test_emits_a_taint_flow_signal(self, engine):
        assert SignalKind.TAINT_FLOW in _kinds(_run(engine, self.PY, "python"))

    def test_the_taint_signal_carries_source_entropy(self, engine):
        sig = _of(_run(engine, self.PY, "python"), SignalKind.TAINT_FLOW)[0]
        assert sig.feature("source_entropy") > 4.0
        assert sig.feature("source_length") > 40

    def test_the_taint_signal_records_the_decoder(self, engine):
        sig = _of(_run(engine, self.PY, "python"), SignalKind.TAINT_FLOW)[0]
        assert "b64decode" in sig.metadata["decoders"]
        assert sig.feature("through_decoder") == 1.0

    def test_a_sink_fed_by_ordinary_prose_produces_no_taint_flow(self, engine):
        src = (
            b'MESSAGE = "this is an ordinary sentence of prose, quite long indeed truly"\n'
            b"exec(MESSAGE)\n"
        )
        sigs = _of(_run(engine, src, "python"), SignalKind.TAINT_FLOW)
        assert all(s.feature("source_looks_encoded") == 0.0 for s in sigs)


class TestCharcodeConstruction:
    def test_detects_a_long_string_fromcharcode_call(self, engine):
        codes = ", ".join(str(80 + i % 20) for i in range(30))
        src = f"const s = String.fromCharCode({codes});\n".encode()
        assert SignalKind.CHARCODE_CONSTRUCTION in _kinds(_run(engine, src, "javascript"))

    def test_a_short_fromcharcode_call_is_ignored(self, engine):
        """`String.fromCharCode(10)` is how you write a newline. It is not a payload."""
        src = b"const nl = String.fromCharCode(10);\n"
        assert SignalKind.CHARCODE_CONSTRUCTION not in _kinds(_run(engine, src, "javascript"))

    def test_detects_a_long_numeric_array(self, engine):
        codes = ", ".join(str(65 + i % 26) for i in range(40))
        src = f"const data = [{codes}];\n".encode()
        assert SignalKind.CHARCODE_CONSTRUCTION in _kinds(_run(engine, src, "javascript"))

    def test_the_signal_records_the_element_count(self, engine):
        codes = ", ".join(str(65 + i % 26) for i in range(40))
        src = f"const data = [{codes}];\n".encode()
        sig = _of(_run(engine, src, "javascript"), SignalKind.CHARCODE_CONSTRUCTION)[0]
        assert sig.feature("elements") == 40

    def test_a_short_numeric_array_is_ignored(self, engine):
        assert SignalKind.CHARCODE_CONSTRUCTION not in _kinds(
            _run(engine, b"const rgb = [255, 128, 0];\n", "javascript")
        )

    def test_detects_a_c_byte_array_payload(self, engine):
        codes = ", ".join(f"0x{i % 256:02x}" for i in range(64))
        src = f"unsigned char shell[] = {{{codes}}};\n".encode()
        assert SignalKind.CHARCODE_CONSTRUCTION in _kinds(_run(engine, src, "c"))

    def test_detects_a_python_chr_join(self, engine):
        codes = ", ".join(str(65 + i % 26) for i in range(40))
        src = f"payload = ''.join(chr(c) for c in [{codes}])\n".encode()
        assert SignalKind.CHARCODE_CONSTRUCTION in _kinds(_run(engine, src, "python"))


class TestBitwiseDecodeLoops:
    def test_detects_the_xz_style_xor_loop(self, engine):
        src = b"""int main(void) {
  uint8_t buffer[2048];
  FILE *f = fopen("tests/fixtures/sample_image.png", "rb");
  fread(buffer, 1, 2048, f);
  for (int i = 0; i < 2048; i++) buffer[i] ^= 0x42;
  return 0;
}
"""
        assert SignalKind.BITWISE_DECODE_LOOP in _kinds(_run(engine, src, "c"))

    def test_detects_a_javascript_xor_loop(self, engine):
        src = b"for (let i = 0; i < buf.length; i++) { out += String.fromCharCode(buf[i] ^ 66); }\n"
        assert SignalKind.BITWISE_DECODE_LOOP in _kinds(_run(engine, src, "javascript"))

    def test_detects_a_python_xor_loop(self, engine):
        src = b"out = bytes(b ^ 0x42 for b in data)\n"
        assert SignalKind.BITWISE_DECODE_LOOP in _kinds(_run(engine, src, "python"))

    def test_an_ordinary_arithmetic_loop_is_ignored(self, engine):
        src = b"int main(void){ for (int i = 0; i < 10; i++) total += i; }\n"
        assert SignalKind.BITWISE_DECODE_LOOP not in _kinds(_run(engine, src, "c"))

    def test_a_bitwise_flag_check_outside_a_loop_is_ignored(self, engine):
        """`flags & O_RDONLY` is ordinary C and must not fire."""
        src = b"int main(void){ if (flags & 0x01) { return 1; } }\n"
        assert SignalKind.BITWISE_DECODE_LOOP not in _kinds(_run(engine, src, "c"))

    def test_a_hash_function_style_shift_loop_is_reported(self, engine):
        """A true positive that is often benign -- weight, do not suppress."""
        src = b"int h(char*s){ int v=0; for(;*s;s++) v = (v << 5) ^ *s; return v; }\n"
        assert SignalKind.BITWISE_DECODE_LOOP in _kinds(_run(engine, src, "c"))


class TestIdentifierObfuscation:
    def test_detects_hex_mangled_identifiers(self, engine):
        src = b"".join(
            f"var _0x{i:04x}a = _0x{i:04x}b + _0x{i:04x}c;\n".encode() for i in range(30)
        )
        assert SignalKind.HIGH_ENTROPY_IDENTIFIERS in _kinds(_run(engine, src, "javascript"))

    def test_ordinary_code_is_not_flagged(self, engine):
        src = b"""function calculateTotalPrice(items, taxRate) {
  const subtotal = items.reduce((sum, item) => sum + item.price, 0);
  const taxAmount = subtotal * taxRate;
  return subtotal + taxAmount;
}
"""
        assert SignalKind.HIGH_ENTROPY_IDENTIFIERS not in _kinds(_run(engine, src, "javascript"))

    def test_short_loop_variables_do_not_trigger_it(self, engine):
        src = b"for (let i = 0; i < n; i++) { for (let j = 0; j < m; j++) { a[i][j] = 0; } }\n"
        assert SignalKind.HIGH_ENTROPY_IDENTIFIERS not in _kinds(_run(engine, src, "javascript"))

    def test_a_tiny_file_is_not_judged(self, engine):
        assert SignalKind.HIGH_ENTROPY_IDENTIFIERS not in _kinds(
            _run(engine, b"var _0xa1b2 = 1;\n", "javascript")
        )


class TestOtherStructuralSignals:
    def test_detects_inline_assembly(self, engine):
        src = b'int main(void){ __asm__("nop"); }\n'
        assert SignalKind.INLINE_ASSEMBLY in _kinds(_run(engine, src, "c"))

    def test_detects_a_long_string_concatenation_chain(self, engine):
        parts = " + ".join(f'"seg{i}"' for i in range(14))
        src = f"const s = {parts};\n".encode()
        assert SignalKind.STRING_CONCAT_CHAIN in _kinds(_run(engine, src, "javascript"))

    def test_a_short_concatenation_is_ignored(self, engine):
        src = b'const s = "hello " + name + "!";\n'
        assert SignalKind.STRING_CONCAT_CHAIN not in _kinds(_run(engine, src, "javascript"))

    def test_detects_a_dynamic_require(self, engine):
        src = b"const mod = require(moduleName);\n"
        assert SignalKind.DYNAMIC_IMPORT in _kinds(_run(engine, src, "javascript"))

    def test_a_literal_require_is_not_dynamic(self, engine):
        src = b"const fs = require('fs');\n"
        assert SignalKind.DYNAMIC_IMPORT not in _kinds(_run(engine, src, "javascript"))

    def test_detects_high_entropy_string_literals(self, engine):
        src = b'PAYLOAD = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2Npbmc="\n'
        assert SignalKind.ENCODED_ALPHABET_STRING in _kinds(_run(engine, src, "python"))

    def test_prose_literals_are_not_flagged_as_encoded(self, engine):
        src = b'MESSAGE = "the quick brown fox jumps over the lazy dog every single day"\n'
        assert SignalKind.ENCODED_ALPHABET_STRING not in _kinds(_run(engine, src, "python"))


class TestRobustness:
    def test_an_unsupported_language_yields_nothing(self, engine):
        assert _run(engine, b"x", "cobol") == []

    def test_an_empty_file_yields_nothing(self, engine):
        assert _run(engine, b"", "python") == []

    def test_syntactically_broken_source_does_not_raise(self, engine):
        _run(engine, b"def broken(:\n  ???\n", "python")


class TestCharcodeDiscrimination:
    """Lookup tables are long numeric arrays too. Length cannot separate them."""

    def test_a_crc_table_scores_low_on_printable_ratio(self, engine):
        table = ", ".join(f"0x{(i * 0xEDB88320) & 0xFFFFFFFF:08X}" for i in range(64))
        src = f"static const unsigned int t[64] = {{{table}}};\n".encode()
        sig = _of(_run(engine, src, "c"), SignalKind.CHARCODE_CONSTRUCTION)[0]
        assert sig.feature("printable_ratio") < 0.2

    def test_a_colour_palette_scores_low_on_printable_ratio(self, engine):
        values = ", ".join(str(i * 4 % 256) for i in range(64))
        src = f"const palette = [{values}];\n".encode()
        sig = _of(_run(engine, src, "javascript"), SignalKind.CHARCODE_CONSTRUCTION)[0]
        assert sig.feature("printable_ratio") < 0.8

    def test_a_character_code_payload_scores_high(self, engine):
        message = "this is a hidden message reconstructed at runtime"
        values = ", ".join(str(ord(c)) for c in message)
        src = f"const data = [{values}];\n".encode()
        sig = _of(_run(engine, src, "javascript"), SignalKind.CHARCODE_CONSTRUCTION)[0]
        assert sig.feature("printable_ratio") == 1.0

    def test_the_form_is_described_in_words(self, engine):
        values = ", ".join(str(65 + i % 26) for i in range(30))
        src = f"const data = [{values}];\n".encode()
        sig = _of(_run(engine, src, "javascript"), SignalKind.CHARCODE_CONSTRUCTION)[0]
        assert "30-element numeric array" in sig.metadata["form"]

    def test_chr_inside_a_loop_is_no_longer_reported_on_its_own(self, engine):
        """Every string-building loop in Python looks like this."""
        src = b"out = ''.join(chr(c) for c in values)\n"
        assert SignalKind.CHARCODE_CONSTRUCTION not in _kinds(_run(engine, src, "python"))
