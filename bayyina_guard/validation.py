"""Upload validation for Bayyina contracts. Rules: README.md, "What to build", part 1."""
from __future__ import annotations

from dataclasses import dataclass
import re
import secrets
import unicodedata

MAX_BYTES = 25 * 1024 * 1024

_CONTENT_TYPES = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}
_MAGIC = {
    "pdf": b"%PDF-",
    "docx": b"PK\x03\x04",
}
# U+061C, U+200E, U+200F, U+202A-U+202E, U+2066-U+2069
_BIDI_CONTROLS = frozenset(
    ["\u061c", "\u200e", "\u200f"]
    + [chr(c) for c in range(0x202A, 0x202F)]
    + [chr(c) for c in range(0x2066, 0x206A)]
)
_MATTER_RE = re.compile(r"MAT-\d{4}-\d{5}", re.ASCII)


class ValidationError(Exception):
    def __init__(self, errors: dict[str, str]):
        super().__init__(", ".join(sorted(errors)))
        self.errors = errors          # field name -> message; keys from: filename, content_type,
                                      # size_bytes, matter_id, first_bytes


@dataclass(frozen=True)
class CleanUpload:
    stored_name: str      # "<32 hex chars>.<ext>", generated, never derived from the filename
    display_name: str     # the filename after NFC normalisation
    extension: str        # "pdf" or "docx", lowercase
    content_type: str
    size_bytes: int
    matter_id: str


def _check_filename(name):
    """Return (display_name, extension, error). On error the first two are None."""
    if not isinstance(name, str):
        return None, None, "must be a string"
    name = unicodedata.normalize("NFC", name)
    if not 1 <= len(name) <= 120:
        return None, None, "must be 1 to 120 characters"
    for ch in name:
        if unicodedata.category(ch) == "Cc":
            return None, None, "must not contain control characters"
        if ch in _BIDI_CONTROLS:
            return None, None, "must not contain bidirectional control characters"
    if "/" in name or "\\" in name:
        return None, None, "must not contain path separators"
    if ".." in name:
        return None, None, "must not contain '..'"
    if name.startswith("."):
        return None, None, "must not start with a dot"
    base, dot, ext = name.rpartition(".")
    if not dot:
        return None, None, "must have an extension"
    ext = ext.lower()
    if ext not in _CONTENT_TYPES:
        return None, None, "extension must be pdf or docx"
    if not base.strip():
        return None, None, "needs a name before the extension"
    return name, ext, None


def validate_upload(meta: dict) -> CleanUpload:
    """Check every field of `meta` and raise one ValidationError listing all failing fields."""
    errors: dict[str, str] = {}

    display_name, ext, problem = _check_filename(meta.get("filename"))
    if problem:
        errors["filename"] = problem

    content_type = meta.get("content_type")
    if not isinstance(content_type, str):
        errors["content_type"] = "must be a string"
    elif ext is not None and content_type != _CONTENT_TYPES[ext]:
        errors["content_type"] = f"must be exactly {_CONTENT_TYPES[ext]} for a .{ext} file"

    first_bytes = meta.get("first_bytes")
    if not isinstance(first_bytes, bytes):
        errors["first_bytes"] = "must be bytes"
    elif ext is not None and not first_bytes.startswith(_MAGIC[ext]):
        errors["first_bytes"] = f"does not look like a .{ext} file"

    size = meta.get("size_bytes")
    # type(...) is int rejects bool (True is an int) and floats like 10.0
    if type(size) is not int:
        errors["size_bytes"] = "must be an integer"
    elif not 1 <= size <= MAX_BYTES:
        errors["size_bytes"] = f"must be between 1 and {MAX_BYTES}"

    matter_id = meta.get("matter_id")
    if not isinstance(matter_id, str) or not _MATTER_RE.fullmatch(matter_id):
        errors["matter_id"] = "must look like MAT-2026-00042 (ASCII digits only)"

    if errors:
        raise ValidationError(errors)

    return CleanUpload(
        stored_name=f"{secrets.token_hex(16)}.{ext}",
        display_name=display_name,
        extension=ext,
        content_type=_CONTENT_TYPES[ext],
        size_bytes=size,
        matter_id=matter_id,
    )
