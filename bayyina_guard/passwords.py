"""Password storage for Bayyina's local break-glass accounts. Rules: README.md, "What to build", part 3."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import unicodedata

N, R, P = 2**14, 8, 5
DKLEN = 32
SALT_LEN = 16
MAXMEM = 64 * 1024 * 1024

_INT_RE = re.compile(r"[0-9]{1,9}", re.ASCII)
_B64_RE = re.compile(r"[A-Za-z0-9_-]*", re.ASCII)


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes | None:
    # only URL-safe alphabet, no padding, and a length that can be valid base64
    if not _B64_RE.fullmatch(text) or len(text) % 4 == 1:
        return None
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _parse(stored):
    """Return (n, r, p, salt, key) for a well-formed stored hash, otherwise None."""
    if not isinstance(stored, str):
        return None
    parts = stored.split("$")
    if len(parts) != 6 or parts[0] != "scrypt":
        return None
    if not all(_INT_RE.fullmatch(x) for x in parts[1:4]):
        return None
    n, r, p = (int(x) for x in parts[1:4])
    # check bounds BEFORE calling scrypt: absurd parameters would turn one login into a DoS
    if not (2 <= n <= 2**20 and n & (n - 1) == 0 and 1 <= r <= 32 and 1 <= p <= 16):
        return None
    salt = _unb64(parts[4])
    key = _unb64(parts[5])
    if salt is None or key is None or len(salt) < SALT_LEN or len(key) != DKLEN:
        return None
    return n, r, p, salt, key


def hash_password(password: str) -> str:
    """scrypt$<n>$<r>$<p>$<salt>$<hash> with n=2**14, r=8, p=5, a 16-byte random salt, dklen=32."""
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    normalised = unicodedata.normalize("NFKC", password)
    if not 8 <= len(normalised) <= 128:
        raise ValueError("password must be 8 to 128 characters")
    try:
        pw = normalised.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("password contains invalid characters") from exc
    salt = os.urandom(SALT_LEN)
    dk = hashlib.scrypt(pw, salt=salt, n=N, r=R, p=P, maxmem=MAXMEM, dklen=DKLEN)
    return f"scrypt${N}${R}${P}${_b64(salt)}${_b64(dk)}"


def verify_password(password: str, stored: str) -> bool:
    """True only if `password` matches `stored`. Never raises: anything malformed is False."""
    parsed = _parse(stored)
    if parsed is None or not isinstance(password, str):
        return False
    n, r, p, salt, key = parsed
    try:
        pw = unicodedata.normalize("NFKC", password).encode("utf-8")
        dk = hashlib.scrypt(pw, salt=salt, n=n, r=r, p=p, maxmem=MAXMEM, dklen=DKLEN)
    except Exception:
        return False
    return hmac.compare_digest(dk, key)


def needs_rehash(stored: str) -> bool:
    """True if `stored` cannot be parsed or any of n, r, p is below the current values."""
    parsed = _parse(stored)
    if parsed is None:
        return True
    n, r, p, _salt, _key = parsed
    return n < N or r < R or p < P