from itertools import product

from bayyina_guard.policy import Document, User, authorize, visible_documents

DOC = Document(id="d1", client_id="CL-A", matter_id="MAT-2026-00001")
RESTRICTED = Document(id="d2", client_id="CL-A", matter_id="MAT-2026-00001", confidentiality="restricted")
HELD = Document(id="d3", client_id="CL-A", matter_id="MAT-2026-00001", legal_hold=True)
M = frozenset({"MAT-2026-00001"})


def u(role, **kw):
    return User(id="u1", role=role, **kw)


def why(user, action, doc):
    d = authorize(user, action, doc)
    return d.allowed, d.reason


def test_deny_by_default():
    assert why(None, "read", DOC) == (False, "unauthenticated")
    assert why(User(id="", role="partner"), "read", DOC) == (False, "unauthenticated")
    assert why(u("partner"), "nuke", DOC) == (False, "unknown_action")
    assert why(u("intern"), "read", DOC) == (False, "unknown_role")
    assert why(u("auditor"), "read", DOC) == (False, "role_not_permitted")


def test_ok_cases():
    assert why(u("partner"), "delete", DOC) == (True, "ok")
    assert why(u("associate", matters=M), "comment", DOC) == (True, "ok")
    assert why(u("client", client_id="CL-A"), "read", DOC) == (True, "ok")


def test_legal_hold_beats_everything_for_delete():
    assert why(u("partner", mfa=True), "delete", HELD) == (False, "legal_hold")
    assert why(u("client", client_id="other"), "delete", HELD) == (False, "legal_hold")
    assert why(u("partner"), "read", HELD) == (True, "ok")


def test_precedence_of_reasons():
    assert why(u("client", client_id="other"), "delete", DOC) == (False, "role_not_permitted")
    assert why(u("client", client_id="other"), "read", RESTRICTED) == (False, "tenant_mismatch")
    assert why(u("client", client_id=None), "read", DOC) == (False, "tenant_mismatch")
    assert why(u("associate", matters=frozenset()), "read", RESTRICTED) == (False, "not_assigned")


def test_restricted_and_mfa():
    assert why(u("paralegal", matters=M), "comment", DOC) == (False, "role_not_permitted")
    assert why(u("paralegal", matters=M, mfa=True), "read", RESTRICTED) == (False, "restricted")
    assert why(u("client", client_id="CL-A", mfa=True), "read", RESTRICTED) == (False, "restricted")
    assert why(u("associate", matters=M), "read", RESTRICTED) == (False, "mfa_required")
    assert why(u("associate", matters=M, mfa=True), "read", RESTRICTED) == (True, "ok")
    assert why(u("partner"), "share_external", DOC) == (False, "mfa_required")
    assert why(u("partner", mfa=True), "share_external", DOC) == (True, "ok")


def test_unknown_confidentiality_counts_as_not_normal():
    secret = Document(id="d9", client_id="CL-A", matter_id="MAT-2026-00001", confidentiality="secret")
    assert why(u("partner"), "read", secret) == (False, "mfa_required")


def test_client_is_only_allowed_on_exact_normal_match():
    for cid, action, conf, mfa, hold in product(
        [None, "CL-A", "cl-a", "CL-A ", ""],
        ["read", "comment", "upload_version", "delete", "share_external", "bogus"],
        ["normal", "restricted", "x"],
        [True, False],
        [True, False],
    ):
        doc = Document(id="d", client_id="CL-A", matter_id="m", confidentiality=conf, legal_hold=hold)
        d = authorize(User(id="u", role="client", client_id=cid, mfa=mfa), action, doc)
        if d.allowed:
            assert cid == "CL-A" and conf == "normal" and action in ("read", "comment")


def test_fails_closed_on_broken_input():
    assert authorize(User(id="u", role="associate", matters=None), "read", DOC).allowed is False


def test_visible_documents_uses_the_same_policy_and_keeps_order():
    docs = [DOC, RESTRICTED, HELD, Document(id="d4", client_id="CL-B", matter_id="MAT-2026-00002")]
    for user in (u("partner"), u("associate", matters=M), u("client", client_id="CL-A"), None):
        expected = [d for d in docs if authorize(user, "read", d).allowed]
        assert visible_documents(user, docs) == expected