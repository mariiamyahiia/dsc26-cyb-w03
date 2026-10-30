import re

import pytest

from bayyina_guard.validation import MAX_BYTES, ValidationError, validate_upload

PDF = "application/pdf"
DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def meta(**kw):
    m = {
        "filename": "lease.pdf",
        "content_type": PDF,
        "size_bytes": 1000,
        "matter_id": "MAT-2026-00042",
        "first_bytes": b"%PDF-1.7",
    }
    m.update(kw)
    return m


def errors(**kw):
    with pytest.raises(ValidationError) as exc:
        validate_upload(meta(**kw))
    return exc.value.errors


def test_valid_pdf_and_docx():
    assert validate_upload(meta()).extension == "pdf"
    ok = validate_upload(meta(filename="memo.docx", content_type=DOCX, first_bytes=b"PK\x03\x04xx"))
    assert ok.extension == "docx" and ok.content_type == DOCX


@pytest.mark.parametrize("name", [
    "..\\x.pdf", "/abs.pdf", "a/b.pdf", ".hidden.pdf", "x..pdf", "x.pdf/",
    "x.pdf.exe", "x.", "pdf", " .pdf", "",
    "a\u202eb.pdf", "\u0639\u0642\u062f\u202b.pdf", "a\u2066b.pdf", "a\u061cb.pdf",
    "a\x00b.pdf", "a\nb.pdf", "x" * 117 + ".pdf", 5,
])
def test_bad_filenames(name):
    assert "filename" in errors(filename=name)


@pytest.mark.parametrize("name", [
    "LEASE.PDF", "x.exe.pdf",
    "\u0639\u0642\u062f \u0625\u064a\u062c\u0627\u0631.pdf",
    "x" * 116 + ".pdf",
])
def test_good_filenames(name):
    assert validate_upload(meta(filename=name)).extension == "pdf"


def test_type_and_bytes_must_agree_with_extension():
    e = errors(filename="a.docx", content_type=PDF, first_bytes=b"%PDF-1")
    assert "content_type" in e and "first_bytes" in e
    e = errors(filename="a.docx", content_type=DOCX, first_bytes=b"%PDF-1")
    assert "first_bytes" in e and "content_type" not in e


def test_invalid_filename_still_checks_other_types_only():
    e = errors(filename="bad.exe", content_type=5, first_bytes="text")
    assert set(e) == {"filename", "content_type", "first_bytes"}


@pytest.mark.parametrize("size", [True, 10.0, 0, "10", MAX_BYTES + 1, None, -5])
def test_bad_sizes(size):
    assert "size_bytes" in errors(size_bytes=size)


@pytest.mark.parametrize("size", [1, MAX_BYTES])
def test_good_sizes(size):
    assert validate_upload(meta(size_bytes=size)).size_bytes == size


@pytest.mark.parametrize("mid", [
    "MAT-\u0662\u0660\u0662\u0666-\u0660\u0660\u0660\u0664\u0662",
    "MAT-2026-00042\n", " MAT-2026-00042", "mat-2026-00042",
    "MAT-2026-0004", "MAT-202-00042", "MAT-2026-000421", None, 5,
])
def test_bad_matter_ids(mid):
    assert "matter_id" in errors(matter_id=mid)


def test_all_errors_reported_together():
    e = errors(filename=5, content_type=5, size_bytes=0, matter_id="x", first_bytes="x")
    assert set(e) == {"filename", "content_type", "size_bytes", "matter_id", "first_bytes"}


def test_display_name_is_nfc_and_stored_names_are_unique():
    clean = validate_upload(meta(filename="cafe\u0301.pdf"))
    assert clean.display_name == "caf\u00e9.pdf"
    names = {validate_upload(meta()).stored_name for _ in range(50)}
    assert len(names) == 50
    assert all(re.fullmatch(r"[0-9a-f]{32}\.pdf", n) for n in names)