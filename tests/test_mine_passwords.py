import base64
import hashlib
import time

import pytest

from bayyina_guard.passwords import hash_password, needs_rehash, verify_password

PW = "correct horse battery"


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def test_round_trip_and_wrong_password():
    h = hash_password(PW)
    assert verify_password(PW, h) is True
    assert verify_password("wrong password!", h) is False
    assert needs_rehash(h) is False


def test_format_and_random_salt():
    a, b = hash_password(PW), hash_password(PW)
    assert a != b
    scheme, n, r, p, salt, key = a.split("$")
    assert (scheme, n, r, p) == ("scrypt", "16384", "8", "5")
    assert "=" not in a
    assert len(base64.urlsafe_b64decode(salt + "==")) == 16
    assert len(base64.urlsafe_b64decode(key + "=")) == 32


def test_truncated_hash_is_rejected():
    h = hash_password(PW)
    assert verify_password(PW, h[:-4]) is False


GOOD_SALT = b64(bytes(16))
GOOD_KEY = b64(bytes(32))


@pytest.mark.parametrize("stored", [
    "", "garbage", None, 12345, b"scrypt$16384$8$5$a$b",
    "bcrypt$16384$8$5$" + GOOD_SALT + "$" + GOOD_KEY,
    "scrypt$16384$8$" + GOOD_SALT + "$" + GOOD_KEY,
    "scrypt$16384$8$5$" + GOOD_SALT + "$" + GOOD_KEY + "$extra",
    "scrypt$16384$8$5$!!!!$" + GOOD_KEY,
    "scrypt$16384$8$5$" + GOOD_SALT + "$" + GOOD_KEY[:-1],
    "scrypt$16383$8$5$" + GOOD_SALT + "$" + GOOD_KEY,       # n not a power of two
    "scrypt$1$8$5$" + GOOD_SALT + "$" + GOOD_KEY,           # n below 2
    "scrypt$16384$0$5$" + GOOD_SALT + "$" + GOOD_KEY,       # r too small
    "scrypt$16384$33$5$" + GOOD_SALT + "$" + GOOD_KEY,      # r too large
    "scrypt$16384$8$0$" + GOOD_SALT + "$" + GOOD_KEY,       # p too small
    "scrypt$16384$8$17$" + GOOD_SALT + "$" + GOOD_KEY,      # p too large
    "scrypt$16384$8$5$" + b64(bytes(15)) + "$" + GOOD_KEY,  # salt too short
    "scrypt$16384$8$5$" + GOOD_SALT + "$" + b64(bytes(31)), # key too short
    "scrypt$\u0661\u0666\u0663\u0668\u0664$8$5$" + GOOD_SALT + "$" + GOOD_KEY,  # Arabic digits
])
def test_malformed_or_out_of_bounds_is_false_and_never_raises(stored):
    assert verify_password(PW, stored) is False


def test_dos_sized_parameters_return_false_quickly():
    start = time.monotonic()
    for n, r, p in [(2**20, 32, 16), (2**20, 8, 1), (2**14, 8, 1_000_000)]:
        stored = f"scrypt${n}${r}${p}${GOOD_SALT}${GOOD_KEY}"
        assert verify_password(PW, stored) is False
    assert time.monotonic() - start < 10


def test_normalisation_nfc_and_nfd_match():
    nfc = "caf\u00e9-\u0645\u0631\u062d\u0628\u0627"
    nfd = "cafe\u0301-\u0645\u0631\u062d\u0628\u0627"
    assert verify_password(nfd, hash_password(nfc)) is True


def test_length_and_type_limits():
    with pytest.raises(ValueError):
        hash_password("a" * 7)
    with pytest.raises(ValueError):
        hash_password("a" * 129)
    with pytest.raises(TypeError):
        hash_password(b"bytes-password")
    hash_password("a" * 8)
    hash_password("a" * 128)


def test_legacy_hash_verifies_and_needs_rehash():
    salt = bytes(range(16))
    dk = hashlib.scrypt(PW.encode(), salt=salt, n=4096, r=8, p=1, dklen=32)
    legacy = f"scrypt$4096$8$1${b64(salt)}${b64(dk)}"
    assert verify_password(PW, legacy) is True
    assert needs_rehash(legacy) is True
    assert needs_rehash("not a hash") is True