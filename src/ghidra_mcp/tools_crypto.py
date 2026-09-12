"""Crypto tools: identify algorithms, decode encodings, recover keys, decrypt."""

from __future__ import annotations

from ghidra_mcp import crypto as crypto_module
from ghidra_mcp import static_analysis as static
from ghidra_mcp.runtime import fail, mcp, render


@mcp.tool()
def crypto_identify(
    data: str | None = None,
    path: str | None = None,
    encoding: str = "auto",
    limit: int = 60,
) -> str:
    """Find crypto algorithms by their embedded constants: S-boxes, initial states, alphabets.

    Answers "what is this encrypting with" without reading any code. An AES S-box or a
    ChaCha sigma constant cannot be omitted by a working implementation, so a hit is strong
    evidence rather than a hint. Pass ``path`` for a file or ``data`` for a literal value.
    """
    try:
        payload = static.read_file(path) if path else crypto_module.coerce_bytes(data, encoding)
        return render(crypto_module.detect_crypto_constants(payload, limit=limit))
    except Exception as exc:
        return fail(exc, hint="Pass 'path' for a file or 'data' for a hex/base64 value")


@mcp.tool()
def crypto_decode(data: str, encoding: str = "auto", limit: int = 12) -> str:
    """Try every common encoding at once and rank the results by plausibility.

    Use this when you have a blob and do not know what it is: base64, base32, base85, hex,
    URL, gzip, zlib, bz2, lzma, rot13, UTF-16, escape sequences, and byte reversal are all
    attempted, scored, and sorted so the real answer comes first.
    """
    try:
        payload = crypto_module.coerce_bytes(data, encoding)
        return render(crypto_module.decode_common(payload, limit=limit))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def crypto_encode(data: str, codec: str, encoding: str = "auto") -> str:
    """Encode bytes: hex, base64, base64url, base32, base85, url, c_array, escaped, gzip, zlib.

    ``c_array`` and ``escaped`` are for pasting bytes into source code or a patch.
    """
    try:
        payload = crypto_module.coerce_bytes(data, encoding)
        return render(crypto_module.encode(payload, codec))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def crypto_xor(
    data: str,
    key: str | None = None,
    encoding: str = "auto",
    key_encoding: str = "auto",
    bruteforce: bool = False,
    max_key_length: int = 8,
    crib: str | None = None,
    top: int = 8,
) -> str:
    """XOR with a known key, or recover an unknown one.

    With ``key`` this simply XORs. With ``bruteforce=true`` it recovers the key: every single
    byte, then repeating keys solved column by column. If you know any fragment of the
    plaintext, pass it as ``crib`` ("This program", "http", a file header) - that turns a
    guess into exact key recovery and is by far the most reliable route. Candidates come
    back scored; above ~55 is usually correct, below ~35 is noise.
    """
    try:
        payload = crypto_module.coerce_bytes(data, encoding)
        if bruteforce or not key:
            crib_bytes = crypto_module.coerce_bytes(crib, "auto") if crib else None
            return render(
                crypto_module.xor_bruteforce(payload, max_key_length=max_key_length, crib=crib_bytes, top=top)
            )
        key_bytes = crypto_module.coerce_bytes(key, key_encoding)
        result = crypto_module.xor(payload, key_bytes)
        rendered = crypto_module.present(result)
        rendered["key_hex"] = key_bytes.hex()
        rendered["plaintext_score"] = crypto_module.score_plaintext(result)
        return render(rendered)
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def crypto_symmetric(
    algorithm: str,
    data: str,
    key: str,
    mode: str = "cbc",
    iv: str | None = None,
    encoding: str = "auto",
    key_encoding: str = "auto",
    iv_encoding: str = "auto",
    decrypt: bool = True,
) -> str:
    """Decrypt or encrypt with AES, DES, 3DES, RC4, or ChaCha20.

    ``algorithm``: ``aes``, ``des``, ``des3``, ``rc4``, ``chacha20``. For AES/DES in CBC,
    omitting ``iv`` treats the first block of the data as the IV, which is how most
    implementations transmit it. The result carries a plaintext score, so a correct key is
    distinguishable from a wrong one without reading hex.
    """
    try:
        payload = crypto_module.coerce_bytes(data, encoding)
        key_bytes = crypto_module.coerce_bytes(key, key_encoding)
        iv_bytes = crypto_module.coerce_bytes(iv, iv_encoding) if iv else None
        algorithm = algorithm.lower()

        if algorithm == "aes":
            return render(crypto_module.aes(payload, key_bytes, mode=mode, iv=iv_bytes, decrypt=decrypt))
        if algorithm in ("des", "des3", "3des", "tripledes"):
            name = "des" if algorithm == "des" else "des3"
            return render(
                crypto_module.des_family(payload, key_bytes, algorithm=name, mode=mode, iv=iv_bytes, decrypt=decrypt)
            )
        if algorithm == "rc4":
            result = crypto_module.rc4(payload, key_bytes)
            rendered = crypto_module.present(result)
            rendered["algorithm"] = "rc4"
            rendered["plaintext_score"] = crypto_module.score_plaintext(result)
            return render(rendered)
        if algorithm in ("chacha20", "chacha"):
            if iv_bytes is None:
                raise ValueError("ChaCha20 needs a nonce; pass it as 'iv' (8 or 12 bytes)")
            return render(crypto_module.chacha20(payload, key_bytes, iv_bytes))
        raise ValueError(f"unknown algorithm '{algorithm}'. Known: aes, des, des3, rc4, chacha20")
    except Exception as exc:
        return fail(exc, hint="AES keys are 16/24/32 bytes; check key_encoding if the key looks wrong")


@mcp.tool()
def crypto_classic(text: str, cipher: str = "caesar", key: str | None = None) -> str:
    """Caesar/ROT-n, Vigenere, or Atbash. With no key, Caesar tries all 25 shifts and ranks them."""
    try:
        return render(crypto_module.classic_cipher(text, cipher=cipher, key=key))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def crypto_hash(data: str, encoding: str = "auto", algorithms: str | None = None) -> str:
    """Hash data with md5, sha1, sha256, sha512, crc32, adler32, and anything hashlib knows.

    ``algorithms`` is a comma-separated list. Use it to match a checksum the binary computes,
    or to fingerprint a decrypted blob.
    """
    try:
        payload = crypto_module.coerce_bytes(data, encoding)
        names = [a.strip() for a in algorithms.split(",")] if algorithms else None
        return render(crypto_module.hash_data(payload, algorithms=names))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def crypto_score(data: str, encoding: str = "auto") -> str:
    """Rate 0..100 how much data looks like real plaintext.

    Use it to judge an ambiguous candidate decryption instead of guessing from a hex preview.
    """
    try:
        payload = crypto_module.coerce_bytes(data, encoding)
        result = crypto_module.score_plaintext(payload)
        result["preview"] = payload[:200].decode("utf-8", "replace")
        return render(result)
    except Exception as exc:
        return fail(exc)
