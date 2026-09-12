"""Decryption and encoding helpers for reverse engineering.

Two kinds of tool live here:

* *identification* - find the crypto in a binary before you try to undo it:
  ``detect_crypto_constants`` recognises the S-boxes and initialisation vectors that
  algorithms cannot avoid embedding, and ``score_plaintext`` judges whether a
  candidate decryption is real text or noise.
* *transformation* - actually decode: base families, XOR (with key recovery), RC4,
  AES, ChaCha20, and the classic ciphers.

The reason ``xor_bruteforce`` exists as its own tool is that single- and multi-byte
XOR is overwhelmingly the most common obfuscation in malware and game clients, and
recovering the key from a known-plaintext crib is mechanical work best not done by
hand in a chat window.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import itertools
import math
import re
import zlib
from collections import Counter
from typing import Any, Iterable

# --------------------------------------------------------------------------
# input parsing: accept whatever form the caller has the data in
# --------------------------------------------------------------------------
def coerce_bytes(value: Any, encoding: str = "auto") -> bytes:
    """Turn a tool argument into bytes.

    ``encoding`` may be ``hex``, ``base64``, ``utf8``, ``latin1``, or ``auto``, which
    guesses: a pure-hex string of even length is hex, otherwise it is text.
    """
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, list):
        return bytes(int(v) & 0xFF for v in value)
    text = str(value)
    encoding = (encoding or "auto").lower()

    if encoding == "hex":
        cleaned = re.sub(r"[\s,]|0x|\\x", "", text)
        try:
            return bytes.fromhex(cleaned)
        except ValueError as exc:
            raise ValueError(f"not valid hex: {exc}") from exc
    if encoding in ("base64", "b64"):
        return base64.b64decode(text + "=" * (-len(text) % 4))
    if encoding in ("utf8", "utf-8", "text"):
        return text.encode("utf-8")
    if encoding in ("latin1", "latin-1", "raw"):
        return text.encode("latin-1", "replace")
    if encoding in ("utf16", "utf-16", "utf16le"):
        return text.encode("utf-16-le")

    stripped = re.sub(r"[\s,]|0x|\\x", "", text)
    if len(stripped) >= 2 and len(stripped) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", stripped):
        return bytes.fromhex(stripped)
    return text.encode("utf-8")


def present(data: bytes, *, limit: int = 4096) -> dict[str, Any]:
    """Render a byte string every way a caller might want to read it."""
    clipped = data[:limit]
    try:
        as_utf8 = clipped.decode("utf-8")
    except UnicodeDecodeError:
        as_utf8 = None
    printable = sum(1 for b in clipped if 9 <= b <= 13 or 32 <= b <= 126)
    return {
        "length": len(data),
        "truncated": len(data) > limit,
        "hex": clipped.hex(),
        "utf8": as_utf8,
        "latin1": clipped.decode("latin-1"),
        "printable_ratio": round(printable / len(clipped), 3) if clipped else 0.0,
        "entropy": round(_entropy(clipped), 3),
        "preview": "".join(chr(b) if 32 <= b < 127 else "." for b in clipped[:200]),
    }


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


# --------------------------------------------------------------------------
# plaintext scoring: how a brute force decides it has found the answer
# --------------------------------------------------------------------------
_ENGLISH_FREQ = {
    "a": 8.17, "b": 1.49, "c": 2.78, "d": 4.25, "e": 12.70, "f": 2.23, "g": 2.02,
    "h": 6.09, "i": 6.97, "j": 0.15, "k": 0.77, "l": 4.03, "m": 2.41, "n": 6.75,
    "o": 7.51, "p": 1.93, "q": 0.10, "r": 5.99, "s": 6.33, "t": 9.06, "u": 2.76,
    "v": 0.98, "w": 2.36, "x": 0.15, "y": 1.97, "z": 0.07, " ": 13.00,
}

_CODE_WORDS = (
    b"http", b"error", b"failed", b"true", b"false", b"null", b"function", b"return",
    b"password", b"user", b"login", b"token", b"admin", b"config", b"select",
    b"kernel32", b"ntdll", b"advapi", b"user32", b"\\Device", b"SOFTWARE", b"Windows",
    b"/usr/", b"/etc/", b".dll", b".exe", b"GET ", b"POST ", b"Content-Type",
    b"<?xml", b"<html", b"import ", b"class ", b"def ", b"the ", b" and ", b" for ",
)


def score_plaintext(data: bytes) -> dict[str, Any]:
    """Rate 0..100 how much *data* looks like meaningful text.

    A brute force produces hundreds of candidates; this is what separates the one real
    answer from the noise. Printable ratio alone is not enough - random bytes filtered
    through a bad key are often 40% printable - so this also weighs letter frequency,
    known words, and how evenly the bytes are spread.
    """
    if not data:
        return {"score": 0.0, "reasons": ["empty"]}

    sample = data[:8192]
    printable = sum(1 for b in sample if 9 <= b <= 13 or 32 <= b <= 126)
    printable_ratio = printable / len(sample)

    lowered = sample.lower()
    letters = [chr(b) for b in lowered if 97 <= b <= 122 or b == 32]
    frequency_score = 0.0
    if letters and len(letters) / len(sample) > 0.3:
        # Only trust letter frequencies when the data is mostly letters. Random bytes
        # contain a scattering of every letter and would otherwise score well here.
        observed = Counter(letters)
        total = len(letters)
        overlap = 0.0
        for character, expected in _ENGLISH_FREQ.items():
            actual = (observed.get(character, 0) / total) * 100
            overlap += math.sqrt(max(0.0, expected) * max(0.0, actual))
        frequency_score = min(1.0, overlap / 100.0)

    word_hits = sum(1 for word in _CODE_WORDS if word in sample or word.lower() in lowered)
    word_score = min(1.0, word_hits / 3.0)

    null_ratio = sample.count(0) / len(sample)
    entropy_value = _entropy(sample)
    # Natural text sits near 4-5 bits/byte; ciphertext approaches 8.
    entropy_score = 1.0 - min(1.0, max(0.0, (entropy_value - 4.0) / 3.0))

    score = 100.0 * (
        0.40 * printable_ratio
        + 0.25 * frequency_score
        + 0.20 * word_score
        + 0.15 * entropy_score
    )
    if null_ratio > 0.3:
        score *= 0.5  # a sea of nulls is padding, not plaintext
    if printable_ratio < 0.6:
        # Anything that is not mostly printable is not plaintext, whatever else it scores.
        score *= printable_ratio

    reasons = []
    if printable_ratio > 0.9:
        reasons.append("almost entirely printable")
    if word_hits:
        reasons.append(f"{word_hits} recognisable words")
    if frequency_score > 0.7:
        reasons.append("letter frequencies look like natural language")
    if entropy_value < 4.5:
        reasons.append(f"low entropy ({entropy_value:.2f})")
    if not reasons:
        reasons.append("no strong textual signal")

    return {
        "score": round(score, 1),
        "printable_ratio": round(printable_ratio, 3),
        "entropy": round(entropy_value, 3),
        "word_hits": word_hits,
        "reasons": reasons,
    }


# --------------------------------------------------------------------------
# encodings
# --------------------------------------------------------------------------
def decode_common(data: bytes, *, limit: int = 12) -> dict[str, Any]:
    """Try every common encoding and return the ones that produce something sane.

    Use this when you have a blob and do not yet know what it is: it is faster than
    guessing base64 then hex then gzip by hand, and it ranks the results.
    """
    candidates: list[dict[str, Any]] = []

    def offer(name: str, produce: Any, note: str = "") -> None:
        try:
            result = produce()
        except Exception:
            return
        if not result or result == data:
            return
        rating = score_plaintext(result)
        candidates.append(
            {
                "codec": name,
                "note": note,
                "score": rating["score"],
                "length": len(result),
                "preview": result[:160].decode("utf-8", "replace"),
                "hex_preview": result[:64].hex(),
                "printable_ratio": rating["printable_ratio"],
            }
        )

    text = data.decode("latin-1")
    compact = re.sub(r"\s+", "", text)

    offer("base64", lambda: base64.b64decode(compact + "=" * (-len(compact) % 4), validate=False))
    offer("base64url", lambda: base64.urlsafe_b64decode(compact + "=" * (-len(compact) % 4)))
    offer("base32", lambda: base64.b32decode(compact + "=" * (-len(compact) % 8), casefold=True))
    offer("base16/hex", lambda: bytes.fromhex(compact))
    offer("base85", lambda: base64.b85decode(compact))
    offer("ascii85", lambda: base64.a85decode(compact))
    offer("url_percent", lambda: re.sub(rb"%([0-9a-fA-F]{2})", lambda m: bytes([int(m.group(1), 16)]), data))
    offer("gzip", lambda: __import__("gzip").decompress(data))
    offer("zlib", lambda: zlib.decompress(data))
    offer("zlib_raw", lambda: zlib.decompress(data, -15))
    offer("bz2", lambda: __import__("bz2").decompress(data))
    offer("lzma", lambda: __import__("lzma").decompress(data))
    offer("rot13", lambda: codecs.encode(data.decode("latin-1"), "rot13").encode("latin-1"))
    offer("utf16le", lambda: data.decode("utf-16-le").encode("utf-8"), "wide string to utf-8")
    offer("reversed", lambda: data[::-1], "byte order reversed")
    offer("quoted_printable", lambda: __import__("quopri").decodestring(data))

    # \xNN and \uNNNN escapes, which show up in dumped config blobs constantly.
    offer(
        "escape_sequences",
        lambda: re.sub(
            rb"\\x([0-9a-fA-F]{2})", lambda m: bytes([int(m.group(1), 16)]), data
        ).decode("unicode_escape").encode("latin-1"),
    )

    candidates.sort(key=lambda c: c["score"], reverse=True)
    return {
        "input_length": len(data),
        "tried": 17,
        "plausible_count": len(candidates),
        "results": candidates[:limit],
        "best": candidates[0] if candidates else None,
    }


def encode(data: bytes, codec: str) -> dict[str, Any]:
    """Encode bytes with a named codec."""
    codec = codec.lower()
    table = {
        "hex": lambda d: d.hex(),
        "base64": lambda d: base64.b64encode(d).decode(),
        "base64url": lambda d: base64.urlsafe_b64encode(d).decode(),
        "base32": lambda d: base64.b32encode(d).decode(),
        "base85": lambda d: base64.b85encode(d).decode(),
        "ascii85": lambda d: base64.a85encode(d).decode(),
        "url": lambda d: "".join(chr(b) if bytes([b]).isalnum() else f"%{b:02X}" for b in d),
        "c_array": lambda d: "{ " + ", ".join(f"0x{b:02x}" for b in d) + " }",
        "python_bytes": lambda d: repr(d),
        "escaped": lambda d: "".join(f"\\x{b:02x}" for b in d),
        "gzip": lambda d: base64.b64encode(__import__("gzip").compress(d)).decode(),
        "zlib": lambda d: base64.b64encode(zlib.compress(d)).decode(),
    }
    if codec not in table:
        raise ValueError(f"unknown codec '{codec}'. Known: {', '.join(sorted(table))}")
    return {"codec": codec, "input_length": len(data), "output": table[codec](data)}


# --------------------------------------------------------------------------
# XOR
# --------------------------------------------------------------------------
def xor(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("empty XOR key")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def xor_bruteforce(
    data: bytes,
    *,
    max_key_length: int = 8,
    crib: bytes | None = None,
    top: int = 10,
) -> dict[str, Any]:
    """Recover an XOR key.

    Three strategies, in order of reliability:

    1. ``crib`` - if you know a fragment of the plaintext ("http", "This program",
       a known header), XOR it against the ciphertext at every offset and read the key
       straight off. This is exact, not a guess.
    2. single-byte - all 255 keys, ranked by :func:`score_plaintext`.
    3. multi-byte - for each length, solve each key position independently by picking
       the byte that makes that column look most like text. This is the classic
       repeating-key attack and it needs a few hundred bytes to work.
    """
    results: list[dict[str, Any]] = []

    if crib:
        crib_hits = []
        for offset in range(0, max(1, len(data) - len(crib) + 1)):
            candidate_key = bytes(data[offset + i] ^ crib[i] for i in range(len(crib)))
            # A real repeating key shows up as a repeating pattern in the recovered bytes.
            for length in range(1, min(len(candidate_key), max_key_length) + 1):
                stem = candidate_key[:length]
                repeated = (stem * (len(candidate_key) // length + 1))[: len(candidate_key)]
                if repeated != candidate_key:
                    continue
                # The key must align with the crib's position in the stream.
                aligned = stem[-(offset % length) :] + stem[: -(offset % length)] if offset % length else stem
                decoded = xor(data, aligned)
                rating = score_plaintext(decoded)
                crib_hits.append(
                    {
                        "method": "crib",
                        "crib_offset": offset,
                        "key_hex": aligned.hex(),
                        "key_ascii": aligned.decode("latin-1"),
                        "key_length": length,
                        "score": rating["score"],
                        "preview": decoded[:200].decode("utf-8", "replace"),
                    }
                )
                break
        crib_hits.sort(key=lambda h: h["score"], reverse=True)
        results.extend(crib_hits[:top])

    for key_byte in range(1, 256):
        decoded = xor(data, bytes([key_byte]))
        rating = score_plaintext(decoded)
        results.append(
            {
                "method": "single_byte",
                "key_hex": f"{key_byte:02x}",
                "key_ascii": chr(key_byte) if 32 <= key_byte < 127 else None,
                "key_length": 1,
                "score": rating["score"],
                "preview": decoded[:200].decode("utf-8", "replace"),
            }
        )

    for length in range(2, max(2, min(int(max_key_length), 64)) + 1):
        if len(data) < length * 4:
            continue
        key = bytearray()
        for position in range(length):
            column = data[position::length]
            best_byte, best_score = 0, -1.0
            for candidate in range(256):
                plain = bytes(b ^ candidate for b in column)
                printable = sum(1 for b in plain if 32 <= b < 127 or b in (9, 10, 13))
                letters = sum(1 for b in plain if 97 <= b <= 122 or 65 <= b <= 90 or b == 32)
                value = printable + 0.5 * letters
                if value > best_score:
                    best_byte, best_score = candidate, value
            key.append(best_byte)
        decoded = xor(data, bytes(key))
        rating = score_plaintext(decoded)
        results.append(
            {
                "method": "multi_byte",
                "key_hex": bytes(key).hex(),
                "key_ascii": bytes(key).decode("latin-1"),
                "key_length": length,
                "score": rating["score"],
                "preview": decoded[:200].decode("utf-8", "replace"),
            }
        )

    results.sort(key=lambda r: r["score"], reverse=True)
    deduplicated: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    for record in results:
        if record["key_hex"] in seen_keys:
            continue
        seen_keys.add(record["key_hex"])
        deduplicated.append(record)

    return {
        "input_length": len(data),
        "crib_used": crib.decode("latin-1") if crib else None,
        "candidate_count": len(deduplicated),
        "candidates": deduplicated[:top],
        "best": deduplicated[0] if deduplicated else None,
        "note": (
            "Scores above ~55 are usually the real key; below ~35 is noise. "
            "A crib hit with a repeating key is near-certain."
        ),
    }


# --------------------------------------------------------------------------
# stream and block ciphers
# --------------------------------------------------------------------------
def rc4(data: bytes, key: bytes) -> bytes:
    """RC4, implemented here because it is trivial and still everywhere in malware."""
    if not key:
        raise ValueError("empty RC4 key")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    out = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        out.append(byte ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(out)


def aes(
    data: bytes,
    key: bytes,
    *,
    mode: str = "cbc",
    iv: bytes | None = None,
    decrypt: bool = True,
    unpad: bool = True,
) -> dict[str, Any]:
    """AES in ECB/CBC/CTR/GCM/CFB/OFB.

    ``iv`` may be omitted for CBC, in which case the first block of *data* is taken as
    the IV, which is how most implementations transmit it.
    """
    try:
        from Crypto.Cipher import AES as _AES
        from Crypto.Util.Padding import unpad as _unpad
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("pycryptodome is not installed, so AES is unavailable") from exc

    if len(key) not in (16, 24, 32):
        raise ValueError(f"AES keys are 16, 24, or 32 bytes; got {len(key)}")

    mode = mode.lower()
    payload = data
    iv_source = "provided"
    if mode in ("cbc", "cfb", "ofb") and iv is None:
        if len(data) <= 16:
            raise ValueError(f"{mode.upper()} needs an IV; pass 'iv' or prepend it to the data")
        iv, payload = data[:16], data[16:]
        iv_source = "first 16 bytes of the input"

    modes = {
        "ecb": lambda: _AES.new(key, _AES.MODE_ECB),
        "cbc": lambda: _AES.new(key, _AES.MODE_CBC, iv),
        "ctr": lambda: _AES.new(key, _AES.MODE_CTR, nonce=(iv or b"")[:8]),
        "cfb": lambda: _AES.new(key, _AES.MODE_CFB, iv),
        "ofb": lambda: _AES.new(key, _AES.MODE_OFB, iv),
        "gcm": lambda: _AES.new(key, _AES.MODE_GCM, nonce=(iv or b"\x00" * 12)),
    }
    if mode not in modes:
        raise ValueError(f"unknown AES mode '{mode}'. Known: {', '.join(sorted(modes))}")

    cipher = modes[mode]()
    if mode in ("ecb", "cbc") and len(payload) % 16 != 0:
        raise ValueError(f"{mode.upper()} needs a multiple of 16 bytes; got {len(payload)}")

    if decrypt:
        if mode == "gcm":
            output = cipher.decrypt(payload)
        else:
            output = cipher.decrypt(payload)
        padding_removed = False
        if unpad and mode in ("ecb", "cbc"):
            try:
                output = _unpad(output, 16)
                padding_removed = True
            except Exception:
                pass  # unpadded or wrong key; the caller can see the raw bytes
        result = present(output)
        result.update(
            {
                "mode": mode,
                "operation": "decrypt",
                "key_length": len(key),
                "iv_source": iv_source if mode != "ecb" else "not used",
                "padding_removed": padding_removed,
                "plaintext_score": score_plaintext(output),
            }
        )
        return result

    if mode in ("ecb", "cbc"):
        from Crypto.Util.Padding import pad as _pad

        payload = _pad(payload, 16)
    output = cipher.encrypt(payload)
    result = present(output)
    result.update({"mode": mode, "operation": "encrypt", "key_length": len(key)})
    return result


def des_family(data: bytes, key: bytes, *, algorithm: str = "des", mode: str = "cbc", iv: bytes | None = None, decrypt: bool = True) -> dict[str, Any]:
    """DES and 3DES, for older software that still uses them."""
    try:
        from Crypto.Cipher import DES, DES3
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("pycryptodome is not installed") from exc

    algorithm = algorithm.lower()
    module = DES if algorithm == "des" else DES3
    block = 8
    mode = mode.lower()
    payload = data
    if mode == "cbc" and iv is None:
        if len(data) <= block:
            raise ValueError("CBC needs an IV")
        iv, payload = data[:block], data[block:]
    cipher = module.new(key, module.MODE_ECB) if mode == "ecb" else module.new(key, module.MODE_CBC, iv)
    output = cipher.decrypt(payload) if decrypt else cipher.encrypt(payload)
    result = present(output)
    result.update({"algorithm": algorithm, "mode": mode, "operation": "decrypt" if decrypt else "encrypt"})
    if decrypt:
        result["plaintext_score"] = score_plaintext(output)
    return result


def chacha20(data: bytes, key: bytes, nonce: bytes) -> dict[str, Any]:
    """ChaCha20, which is symmetric, so this both encrypts and decrypts."""
    try:
        from Crypto.Cipher import ChaCha20
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("pycryptodome is not installed") from exc
    cipher = ChaCha20.new(key=key, nonce=nonce)
    output = cipher.decrypt(data)
    result = present(output)
    result.update({"algorithm": "chacha20", "plaintext_score": score_plaintext(output)})
    return result


def classic_cipher(text: str, *, cipher: str = "caesar", key: Any = None) -> dict[str, Any]:
    """Caesar/ROT-n (all shifts if no key), Vigenere, and Atbash."""
    cipher = cipher.lower()
    if cipher in ("caesar", "rot"):
        if key is None:
            shifts = []
            for shift in range(1, 26):
                decoded = "".join(
                    chr((ord(c) - base + shift) % 26 + base) if c.isalpha() else c
                    for c in text
                    for base in [65 if c.isupper() else 97]
                )
                shifts.append({"shift": shift, "text": decoded, "score": score_plaintext(decoded.encode())["score"]})
            shifts.sort(key=lambda s: s["score"], reverse=True)
            return {"cipher": "caesar", "all_shifts": shifts, "best": shifts[0]}
        shift = int(key)
        decoded = "".join(
            chr((ord(c) - base + shift) % 26 + base) if c.isalpha() else c
            for c in text
            for base in [65 if c.isupper() else 97]
        )
        return {"cipher": "caesar", "shift": shift, "text": decoded}

    if cipher == "vigenere":
        if not key:
            raise ValueError("Vigenere needs a key")
        key_text = str(key).lower()
        out = []
        index = 0
        for character in text:
            if character.isalpha():
                base = 65 if character.isupper() else 97
                offset = ord(key_text[index % len(key_text)]) - 97
                out.append(chr((ord(character) - base - offset) % 26 + base))
                index += 1
            else:
                out.append(character)
        return {"cipher": "vigenere", "key": key_text, "text": "".join(out)}

    if cipher == "atbash":
        out = []
        for character in text:
            if character.isalpha():
                base = 65 if character.isupper() else 97
                out.append(chr(base + 25 - (ord(character) - base)))
            else:
                out.append(character)
        return {"cipher": "atbash", "text": "".join(out)}

    raise ValueError(f"unknown cipher '{cipher}'. Known: caesar, vigenere, atbash")


# --------------------------------------------------------------------------
# hashing
# --------------------------------------------------------------------------
def hash_data(data: bytes, *, algorithms: Iterable[str] | None = None) -> dict[str, Any]:
    """Hash bytes with several algorithms at once, plus CRC32."""
    names = list(algorithms) if algorithms else ["md5", "sha1", "sha256", "sha512", "crc32"]
    out: dict[str, Any] = {"length": len(data)}
    for name in names:
        key = name.lower()
        if key == "crc32":
            out["crc32"] = f"{zlib.crc32(data) & 0xFFFFFFFF:08x}"
            continue
        if key == "adler32":
            out["adler32"] = f"{zlib.adler32(data) & 0xFFFFFFFF:08x}"
            continue
        try:
            out[key] = hashlib.new(key, data).hexdigest()
        except Exception:
            out[key] = f"unsupported algorithm '{name}'"
    return out


# --------------------------------------------------------------------------
# crypto constant detection
# --------------------------------------------------------------------------
# Each entry is a distinctive byte sequence an implementation must embed.
_CRYPTO_SIGNATURES: list[tuple[str, bytes, str]] = [
    (
        "AES",
        bytes.fromhex("637c777bf26b6fc53001672bfed7ab76"),
        "AES forward S-box, first 16 bytes",
    ),
    (
        "AES (inverse)",
        bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb"),
        "AES inverse S-box, first 16 bytes",
    ),
    (
        "AES key schedule",
        bytes.fromhex("01000000020000000400000008000000"),
        "AES Rcon table",
    ),
    ("MD5", bytes.fromhex("0123456789abcdeffedcba9876543210"), "MD5 initial state"),
    ("MD5", bytes.fromhex("d76aa478e8c7b756242070dbc1bdceee"), "MD5 T-table start"),
    ("SHA-1", bytes.fromhex("67452301efcdab8998badcfe10325476"), "SHA-1 initial state"),
    ("SHA-256", bytes.fromhex("6a09e667bb67ae853c6ef372a54ff53a"), "SHA-256 initial state"),
    ("SHA-256", bytes.fromhex("428a2f9871374491b5c0fbcfe9b5dba5"), "SHA-256 round constants"),
    ("SHA-512", bytes.fromhex("6a09e667f3bcc908bb67ae8584caa73b"), "SHA-512 initial state"),
    ("CRC32", bytes.fromhex("00000000772073961db71064"), "CRC32 table (IEEE polynomial)"),
    ("CRC32C", bytes.fromhex("00000000f26b8303e13b70f7"), "CRC32C table (Castagnoli)"),
    ("Blowfish", bytes.fromhex("243f6a8885a308d313198a2e"), "Blowfish P-array (digits of pi)"),
    ("Twofish", bytes.fromhex("a9673bd2b8a5fa6478e8c7bd"), "Twofish q-box"),
    ("DES", bytes.fromhex("3a32292018110209"), "DES permutation table fragment"),
    ("Serpent", bytes.fromhex("9e3779b9"), "Serpent/TEA golden-ratio constant 0x9E3779B9"),
    ("TEA/XTEA", bytes.fromhex("b979379e"), "TEA delta 0x9E3779B9, little endian"),
    ("RC2", bytes.fromhex("d978f9c419ddb5ed28e9fd794aa0d89d"), "RC2 PITABLE"),
    ("Camellia", bytes.fromhex("a09e667f3bcc908b"), "Camellia sigma constant"),
    ("ChaCha20/Salsa20", b"expand 32-byte k", "ChaCha20/Salsa20 sigma constant"),
    ("ChaCha20/Salsa20", b"expand 16-byte k", "ChaCha20/Salsa20 tau constant"),
    ("Base64", b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", "standard base64 alphabet"),
    ("Base64 (URL-safe)", b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", "URL-safe base64 alphabet"),
    ("Base32", b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "standard base32 alphabet"),
    ("ZLIB/Deflate", bytes.fromhex("1f8b08"), "gzip header"),
    ("RSA (PEM)", b"-----BEGIN RSA", "PEM-encoded RSA key material"),
    ("Certificate (PEM)", b"-----BEGIN CERTIFICATE", "embedded X.509 certificate"),
    ("Private key (PEM)", b"-----BEGIN PRIVATE KEY", "embedded private key"),
    ("Whirlpool", bytes.fromhex("18186018c07830d8"), "Whirlpool table"),
    ("MD4", bytes.fromhex("0123456789abcdef"), "MD4/MD5 shared initial state prefix"),
    ("RIPEMD-160", bytes.fromhex("67452301efcdab8998badcfe10325476c3d2e1f0"), "RIPEMD-160 initial state"),
]


def detect_crypto_constants(data: bytes, *, limit: int = 60) -> dict[str, Any]:
    """Find embedded crypto tables, S-boxes, and magic constants.

    This answers "what algorithm is this binary using" without reading any code. An
    AES S-box or a ChaCha sigma constant is not something an implementation can hide
    while remaining a working implementation, so a hit here is strong evidence.
    """
    hits: list[dict[str, Any]] = []
    for algorithm, signature, description in _CRYPTO_SIGNATURES:
        start = 0
        while len(hits) < limit:
            index = data.find(signature, start)
            if index < 0:
                break
            hits.append(
                {
                    "algorithm": algorithm,
                    "description": description,
                    "offset": index,
                    "offset_hex": f"0x{index:x}",
                    "signature": signature[:24].hex() if not signature.isascii() else signature.decode("latin-1")[:40],
                }
            )
            start = index + 1
            if len(hits) >= limit:
                break

    # Long runs of high-entropy data with a flat byte distribution look like a key
    # table even when no signature matches.
    algorithms = sorted({hit["algorithm"] for hit in hits})
    return {
        "input_length": len(data),
        "hit_count": len(hits),
        "algorithms_found": algorithms,
        "hits": hits,
        "verdict": (
            f"crypto present: {', '.join(algorithms)}"
            if algorithms
            else "no known crypto constants found (custom or obfuscated crypto would not match)"
        ),
    }
