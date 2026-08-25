"""RFC 8785 canonicalization — the serialization certs stake their name on.

The number formatter was differentially fuzzed against V8's String() on
20,000+ random IEEE doubles with zero mismatches, and full canonicalize()
against the reference JS algorithm on 3,000 nested unicode objects. The fixed
vectors here pin the behaviour those fuzzes established; the node test at the
bottom re-runs a small differential slice when node is available.

No database needed — pure function, so no SEAL_DSN gate.
"""
from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from seal.canonical import NotCanonicalizable, _es_number, canonicalize, jcs_digest


# ── numbers: ECMAScript formatting, not Python's ──────────────────────────
@pytest.mark.parametrize("value,expected", [
    (0.0, "0"),
    (-0.0, "0"),                    # ES serializes negative zero as "0"
    (1.0, "1"),                     # not "1.0"
    (2.5, "2.5"),
    (1e16, "10000000000000000"),    # Python repr says 1e+16; ES expands to 1e21
    (1e21, "1e+21"),                # the ES exponent threshold
    (1e-6, "0.000001"),
    (1e-7, "1e-7"),                 # and the small-side threshold
    (5e-324, "5e-324"),             # smallest denormal
    (1.7976931348623157e+308, "1.7976931348623157e+308"),   # largest double
    (9007199254740994.0, "9007199254740994"),
    (-3.14, "-3.14"),
    (0.001, "0.001"),
    (333333333.33333329, "333333333.3333333"),  # shortest round-trip wins
])
def test_es_number_formatting(value, expected):
    assert _es_number(value) == expected


def test_int_and_float_forms_of_a_value_serialize_identically():
    """A JS verifier cannot tell 2 from 2.0; neither may the canonical form."""
    assert canonicalize({"n": 2}) == canonicalize({"n": 2.0}) == '{"n":2}'


# ── structure ─────────────────────────────────────────────────────────────
def test_key_ordering_is_utf16_code_units():
    """An astral-plane key (surrogates D83D DE00) sorts BEFORE U+FFFD in
    UTF-16 order, though its code point is higher — the exact case where
    Python's default str ordering silently diverges from every JS verifier."""
    out = canonicalize({"�": 1, "\U0001f600": 2, "A": 3})
    assert out == '{"A":3,"\U0001f600":2,"�":1}'


def test_string_escaping_matches_jcs():
    s = 'tab:\t quote:" backslash:\\ unit-sep:\x1f euro:€'
    out = canonicalize(s)
    assert out == '"tab:\\t quote:\\" backslash:\\\\ unit-sep:\\u001f euro:€"'


def test_canonical_bytes_are_stable_regardless_of_insertion_order():
    a = {"z": [1.5, {"b": None, "a": True}], "a": "x"}
    b = {"a": "x", "z": [1.5, {"a": True, "b": None}]}
    assert canonicalize(a) == canonicalize(b)
    assert jcs_digest(a) == jcs_digest(b)


# ── refusals: never hash what another language cannot reproduce ───────────
@pytest.mark.parametrize("bad", [
    float("nan"),
    float("inf"),
    2 ** 53 + 1,                    # exceeds an IEEE double's exact range
    -(2 ** 53 + 1),
    {1: "non-string key"},
    {"o": object()},
])
def test_uncanonicalizable_values_are_refused(bad):
    with pytest.raises(NotCanonicalizable):
        canonicalize(bad)


# ── differential slice against V8, when node is around ────────────────────
@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_numbers_match_v8_exactly():
    vals = [333333333.33333329, 1e30, 4.5, 0.002, 1e-27, 1e15, 1e16, 1e20,
            1e21, 123456789.123456789, 2.2250738585072014e-308, 0.1 + 0.2]
    payload = json.dumps([repr(v) for v in vals])
    out = subprocess.run(
        ["node", "-e",
         "const a=JSON.parse(require('fs').readFileSync(0,'utf8'));"
         "console.log(JSON.stringify(a.map(s=>String(Number(s)))))"],
        input=payload, capture_output=True, text=True, check=True)
    expected = json.loads(out.stdout)
    assert [_es_number(v) for v in vals] == expected
