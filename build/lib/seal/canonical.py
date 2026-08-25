"""RFC 8785 (JCS) canonical JSON — the cert serialization that crosses languages.

WHY THIS EXISTS. A cert only proves anything to the party that can recompute
its hash. `_digest()`'s sorted-keys JSON is deterministic *for Python*: another
language re-serialising the same body gets different bytes (float formatting,
escaping, key order for non-ASCII), a different hash, and a "tampered" verdict
on an honest cert. That confines verification to people running our code
against our database — which is to say, to us. Evidence that only the accused
can check is not evidence.

RFC 8785 is the fix the ecosystem has already converged on: the MCP receipt
implementations sign JCS bytes, and AP2 mandates are verifiable credentials
over canonical JSON. Certs hashed over JCS bytes can be re-verified by a
JavaScript merchant, a Go auditor, or a Java issuer from the receipt alone.

Scope honesty:

* This implements the full JCS transform for I-JSON values: ECMAScript number
  formatting, JSON string escaping, UTF-16 code-unit key ordering.
* Integers beyond ±2^53 are REFUSED, not truncated. JCS models every number as
  an IEEE double; a larger int would silently change value in any JS verifier,
  which is a cross-language hash break waiting to happen.
* NaN and Infinity are refused (RFC 8785 §3.2.2.3 forbids them).
* Only the CERT layer uses this. Intent identity (`intent_id`, `args_digest`)
  stays on the legacy digest on purpose: those hashes never leave the store,
  and changing them would re-identify every intent an existing store holds.
"""
from __future__ import annotations

import hashlib
import json
import math
from typing import Any

# The largest integer an IEEE 754 double represents exactly. An int outside
# this range cannot survive a trip through a JavaScript verifier unchanged.
_MAX_SAFE_INT = 2 ** 53


class NotCanonicalizable(TypeError):
    """This value has no RFC 8785 serialization; hashing it would produce a
    digest another language cannot reproduce. Refuse loudly at write time
    rather than fail verification mysteriously at audit time."""


def _es_number(x: float) -> str:
    """Serialize a float exactly as ECMAScript Number::toString does.

    This is the part of JCS that Python's repr() ALMOST does: repr gives the
    same shortest round-trip digits as V8, but formats them differently —
    repr(1.0) is '1.0' where JS says '1', repr(1e16) is '1e+16' where JS says
    '10000000000000000'. Same digits, different bytes, different SHA-256.
    So: take repr's digits, re-format them by the ECMA-262 rules.
    """
    if math.isnan(x) or math.isinf(x):
        raise NotCanonicalizable("NaN and Infinity have no JSON serialization")
    if x == 0.0:
        return "0"          # ES serializes -0 as "0"; RFC 8785 keeps that
    sign = "-" if x < 0 else ""
    r = repr(abs(x))        # shortest digits that round-trip, same as V8's

    # Decompose into digit string D and exponent n with value = 0.D × 10^n.
    if "e" in r:
        mant, exps = r.split("e")
        exp = int(exps)
    else:
        mant, exp = r, 0
    if "." in mant:
        int_part, frac = mant.split(".")
    else:
        int_part, frac = mant, ""
    combined = int_part + frac
    stripped = combined.lstrip("0")
    lead = len(combined) - len(stripped)
    digits = stripped.rstrip("0")
    k = len(digits)
    n = len(int_part) - lead + exp

    # ECMA-262 Number::toString, radix 10.
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    e = n - 1
    es = ("+" if e >= 0 else "-") + str(abs(e))
    if k == 1:
        return sign + digits + "e" + es
    return sign + digits[0] + "." + digits[1:] + "e" + es


def _serialize(obj: Any, out: list) -> None:
    if obj is None:
        out.append("null")
    elif obj is True:
        out.append("true")
    elif obj is False:
        out.append("false")
    elif isinstance(obj, str):
        # json.dumps' escaping with ensure_ascii=False matches RFC 8785 §3.2.2.2:
        # two-char escapes where they exist, lowercase \u00xx for other controls,
        # everything else literal UTF-8.
        out.append(json.dumps(obj, ensure_ascii=False))
    elif isinstance(obj, int):
        if abs(obj) > _MAX_SAFE_INT:
            raise NotCanonicalizable(
                f"integer {obj} exceeds 2^53; it cannot survive an IEEE-double "
                "verifier unchanged, so its hash would not be cross-language"
            )
        out.append(str(obj))
    elif isinstance(obj, float):
        out.append(_es_number(obj))
    elif isinstance(obj, (list, tuple)):
        out.append("[")
        for i, v in enumerate(obj):
            if i:
                out.append(",")
            _serialize(v, out)
        out.append("]")
    elif isinstance(obj, dict):
        # Keys sorted by UTF-16 code units (RFC 8785 §3.2.3), which is NOT the
        # same as Python's default str ordering once you leave the BMP.
        items = []
        for key, v in obj.items():
            if not isinstance(key, str):
                raise NotCanonicalizable(f"non-string key {key!r}")
            items.append((key.encode("utf-16-be"), key, v))
        items.sort(key=lambda t: t[0])
        out.append("{")
        for i, (_, key, v) in enumerate(items):
            if i:
                out.append(",")
            out.append(json.dumps(key, ensure_ascii=False))
            out.append(":")
            _serialize(v, out)
        out.append("}")
    else:
        raise NotCanonicalizable(
            f"{type(obj).__name__} has no RFC 8785 serialization — convert it "
            "to a JSON-native value before it reaches the cert layer"
        )


def canonicalize(obj: Any) -> str:
    """The unique RFC 8785 serialization of `obj`."""
    out: list = []
    _serialize(obj, out)
    return "".join(out)


def jcs_digest(obj: Any) -> str:
    """SHA-256 over the canonical UTF-8 bytes — reproducible in any language."""
    return hashlib.sha256(canonicalize(obj).encode("utf-8")).hexdigest()
