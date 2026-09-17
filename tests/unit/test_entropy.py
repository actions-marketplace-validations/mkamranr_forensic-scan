"""Tests for entropy measurement.

Entropy is a *feature*, never a verdict. These tests pin the numeric behaviour
the rest of the scanner reasons over -- in particular the two places the PRD's
fixed thresholds break down: short strings, and hex.
"""

import base64
import math
import os

import pytest

from forensic_scan.engine.entropy import (
    MIN_PAYLOAD_LENGTH,
    Alphabet,
    Calibration,
    profile_string,
    shannon_entropy,
    windowed_entropy,
)


class TestShannonEntropy:
    def test_uniform_random_bytes_approach_eight_bits(self):
        assert shannon_entropy(os.urandom(8192)) > 7.8

    def test_a_single_repeated_byte_has_zero_entropy(self):
        assert shannon_entropy(b"A" * 1000) == 0.0

    def test_two_equally_frequent_symbols_give_exactly_one_bit(self):
        assert shannon_entropy(b"AB" * 500) == pytest.approx(1.0)

    def test_empty_input_is_zero_not_an_error(self):
        assert shannon_entropy(b"") == 0.0

    def test_english_prose_sits_well_below_random(self):
        prose = b"the quick brown fox jumps over the lazy dog " * 20
        assert 3.0 < shannon_entropy(prose) < 4.6

    def test_accepts_str_as_well_as_bytes(self):
        assert shannon_entropy("AAAA") == shannon_entropy(b"AAAA")

    def test_never_exceeds_log2_of_the_symbol_count(self):
        data = bytes(range(16)) * 100
        assert shannon_entropy(data) <= math.log2(16) + 1e-9


class TestWindowedEntropy:
    def test_finds_a_high_entropy_region_inside_a_low_entropy_file(self):
        """An appended payload shows up as a plateau, not as a whole-file average."""
        data = b"\x00" * 4096 + os.urandom(4096) + b"\x00" * 4096
        windows = windowed_entropy(data, window=1024)
        assert max(w.entropy for w in windows) > 7.5
        assert min(w.entropy for w in windows) < 1.0

    def test_reports_the_offset_of_each_window(self):
        windows = windowed_entropy(b"\x00" * 2048, window=1024)
        assert [w.offset for w in windows] == [0, 1024]

    def test_input_shorter_than_one_window_yields_a_single_window(self):
        assert len(windowed_entropy(b"abc", window=1024)) == 1

    def test_empty_input_yields_no_windows(self):
        assert windowed_entropy(b"", window=1024) == []


class TestAlphabetDetection:
    def test_recognises_base64(self):
        payload = base64.b64encode(os.urandom(256)).decode()
        assert profile_string(payload).alphabet is Alphabet.BASE64

    def test_recognises_hex(self):
        assert profile_string(os.urandom(128).hex()).alphabet is Alphabet.HEX

    def test_recognises_base32(self):
        payload = base64.b32encode(os.urandom(128)).decode()
        assert profile_string(payload).alphabet is Alphabet.BASE32

    def test_url_safe_base64_is_still_base64(self):
        payload = base64.urlsafe_b64encode(os.urandom(256)).decode()
        assert profile_string(payload).alphabet is Alphabet.BASE64

    def test_ordinary_prose_is_natural(self):
        p = profile_string("the quick brown fox jumps over the lazy dog repeatedly today")
        assert p.alphabet is Alphabet.NATURAL

    def test_a_file_path_is_natural_not_an_encoding(self):
        p = profile_string("/usr/local/share/application/config/settings.default.json")
        assert p.alphabet is Alphabet.NATURAL

    def test_short_hexlike_strings_are_not_claimed_as_hex(self):
        """'added' and 'deface' are hex-alphabet words; length is what separates them."""
        assert profile_string("deface").alphabet is not Alphabet.HEX


class TestPayloadJudgement:
    def test_a_long_base64_blob_looks_like_an_encoded_payload(self):
        assert profile_string(base64.b64encode(os.urandom(512)).decode()).looks_encoded

    def test_a_long_hex_blob_looks_like_an_encoded_payload(self):
        """Hex maxes out at 4.0 bits/char, so a raw entropy threshold of 5.2
        misses it entirely. Alphabet detection is what catches this."""
        payload = os.urandom(512).hex()
        profile = profile_string(payload)
        assert profile.entropy < 4.1
        assert profile.looks_encoded

    def test_prose_does_not_look_encoded_however_long(self):
        prose = "the quick brown fox jumps over the lazy dog " * 40
        assert not profile_string(prose).looks_encoded

    def test_a_short_random_string_is_below_the_length_gate(self):
        """Short-string entropy is length-biased and unusable; do not guess."""
        assert not profile_string("aB3xQ9").looks_encoded

    def test_the_length_gate_is_documented_and_conservative(self):
        assert MIN_PAYLOAD_LENGTH >= 32

    def test_a_pem_certificate_body_looks_encoded(self):
        """True positive by the metric, and exactly why entropy alone is not a rule."""
        assert profile_string(base64.b64encode(os.urandom(800)).decode()).looks_encoded

    def test_repeated_padding_is_not_a_payload(self):
        assert not profile_string("A" * 400).looks_encoded

    def test_profile_reports_length_and_entropy_for_scoring(self):
        p = profile_string(base64.b64encode(os.urandom(256)).decode())
        assert p.length > 300
        assert p.entropy > 5.0
        assert 0.0 <= p.normalized_entropy <= 1.0


class TestCalibration:
    def test_reports_the_repo_median(self):
        assert Calibration.from_values([1.0, 2.0, 3.0, 4.0, 5.0]).median == 3.0

    def test_scores_an_outlier_far_above_the_baseline(self):
        cal = Calibration.from_values([3.0, 3.1, 2.9, 3.05, 2.95] * 10)
        assert cal.zscore(6.0) > 5.0

    def test_scores_a_typical_value_near_zero(self):
        cal = Calibration.from_values([3.0, 3.1, 2.9, 3.05, 2.95] * 10)
        assert abs(cal.zscore(3.0)) < 1.0

    def test_is_robust_to_a_few_extreme_values(self):
        """A repo with three vendored blobs must not have its baseline dragged up."""
        clean = [3.0, 3.1, 2.9, 3.05, 2.95] * 10
        cal = Calibration.from_values([*clean, 99.0, 99.0, 99.0])
        assert cal.zscore(6.0) > 5.0

    def test_identical_values_do_not_divide_by_zero(self):
        cal = Calibration.from_values([3.0] * 20)
        assert cal.zscore(3.0) == 0.0
        assert cal.zscore(9.0) > 0.0

    def test_too_few_samples_is_reported_as_uncalibrated(self):
        cal = Calibration.from_values([1.0, 2.0])
        assert not cal.is_calibrated
        assert cal.zscore(100.0) == 0.0
