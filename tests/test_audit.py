"""Week 4 controls: is every decision recorded, and is the record trustworthy?"""

import pytest

from conftest import auth_header, compose, psql


def test_audit_requires_admin(api, token_for):
    for username in ("alice", "arun", "bob"):
        response = api.get("/audit/verify", headers=auth_header(token_for(username)))
        assert response.status_code == 403, f"{username} should not read the audit log"


def test_admin_can_verify_the_chain(api, token_for):
    response = api.get("/audit/verify", headers=auth_header(token_for("priya")))
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True, body
    assert body["tip_hash"]


def test_denied_requests_are_recorded(api, token_for):
    """A refused request is the more interesting record."""
    denied = api.get("/datasets/6/file", headers=auth_header(token_for("alice")))
    assert denied.status_code == 403

    entries = api.get(
        "/audit?limit=200", headers=auth_header(token_for("priya"))
    ).json()
    matching = [
        e
        for e in entries
        if e["actor"] == "alice" and e["action"] == "download" and e["decision"] == "deny"
    ]
    assert matching, "alice's denied download was not written to the audit log"


def test_entries_are_linked_to_their_predecessor(api, token_for):
    entries = api.get(
        "/audit?limit=200", headers=auth_header(token_for("priya"))
    ).json()
    assert len(entries) >= 2
    for previous, current in zip(entries, entries[1:]):
        assert current["prev_hash"] == previous["entry_hash"]


def test_tampering_is_detected(api, token_for):
    """Play the attacker: full database access, no signing key.

    Disable the append-only trigger, rewrite a denial into an approval, then
    recompute the entry's hash so it is internally consistent. That defeated
    the hash chain alone; it does not defeat the signature.
    """
    target = psql("SELECT id FROM audit_log WHERE decision='deny' ORDER BY id LIMIT 1")
    if not target:
        pytest.skip("no denied entry in the audit log yet")

    psql("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_change")
    try:
        psql(f"UPDATE audit_log SET decision='allow' WHERE id={target}")

        # The attacker also recomputes the hash, as in Week 4's second attack.
        compose(
            "exec", "-T", "api", "python", "-c",
            "from app.db import SessionLocal; from app import audit; "
            "s=SessionLocal(); r=audit.verify_chain(s); "
            "e=s.get(audit.AuditEntry, r['first_bad_id']); "
            "f={k: getattr(e,k) for k in audit.HASHED_FIELDS}; "
            "e.entry_hash=audit.compute_hash(f, e.prev_hash); s.commit()",
        )

        result = api.get("/audit/verify", headers=auth_header(token_for("priya"))).json()
        assert result["ok"] is False
        assert result["first_bad_id"] == int(target)
        assert "signature" in result["reason"]
    finally:
        # Restore. Putting the contents back restores the original hash, which
        # the untouched signature already covers.
        psql(f"UPDATE audit_log SET decision='deny' WHERE id={target}")
        compose(
            "exec", "-T", "api", "python", "-c",
            "from app.db import SessionLocal; from app import audit; "
            "s=SessionLocal(); r=audit.verify_chain(s); "
            "e=s.get(audit.AuditEntry, r['first_bad_id']); "
            "f={k: getattr(e,k) for k in audit.HASHED_FIELDS}; "
            "e.entry_hash=audit.compute_hash(f, e.prev_hash); s.commit()",
        )
        psql("ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_change")

    after = api.get("/audit/verify", headers=auth_header(token_for("priya"))).json()
    assert after["ok"] is True, "the log was left broken by the tamper test"
