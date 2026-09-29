"""Hash-chained, append-only, signed audit log.

Every dataset request is recorded here, including denied ones. Each entry
stores the hash of the entry before it, so editing any historical row breaks
every link that follows it. Each entry is then SIGNED with a key that lives
outside the database, so an attacker who can rewrite rows and recompute
hashes still cannot produce a log that verifies.
"""

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from sqlalchemy import BigInteger, Integer, String, select, text
from sqlalchemy.orm import Mapped, Session, mapped_column

from app.db import Base

# The chain has to start somewhere. Entry 1 points at 64 zeros.
GENESIS_HASH = "0" * 64

# Every field that goes into the hash, in one place. If a column is not in
# this tuple it can be edited without breaking the chain, so adding a column
# later means adding it here too.
HASHED_FIELDS = (
    "ts",
    "actor",
    "actor_sub",
    "institution",
    "roles",
    "action",
    "dataset_id",
    "decision",
    "reason",
    "client_ip",
    "request_id",
)

# Any constant. Every appender takes the same lock, so appends serialise.
APPEND_LOCK_KEY = 4242

# The private key signs; it exists only in the application's environment and
# never touches the database. The public key verifies, and can be published
# so an outside auditor can check the log without being able to forge it.
_SIGNING_KEY = Ed25519PrivateKey.from_private_bytes(
    base64.b64decode(os.environ["AUDIT_SIGNING_KEY"])
)
_PUBLIC_KEY = Ed25519PublicKey.from_public_bytes(
    base64.b64decode(os.environ["AUDIT_PUBLIC_KEY"])
)


class AuditEntry(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    # Stored as text, exactly as it was hashed, so it round-trips byte for byte
    ts: Mapped[str] = mapped_column(String(32))
    actor: Mapped[str] = mapped_column(String(255))
    actor_sub: Mapped[str] = mapped_column(String(64))
    institution: Mapped[str] = mapped_column(String(50))
    roles: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(50))
    dataset_id: Mapped[int | None] = mapped_column(Integer)
    decision: Mapped[str] = mapped_column(String(10))
    reason: Mapped[str] = mapped_column(String(200))
    client_ip: Mapped[str] = mapped_column(String(64))
    request_id: Mapped[str] = mapped_column(String(36))
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str] = mapped_column(String(128))


def canonical_payload(fields: dict[str, Any], prev_hash: str) -> bytes:
    """Produce exactly the same bytes for the same entry, every time."""
    payload = {key: fields[key] for key in HASHED_FIELDS}
    # prev_hash goes INSIDE the JSON, so the input cannot be read two ways.
    payload["prev_hash"] = prev_hash
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def compute_hash(fields: dict[str, Any], prev_hash: str) -> str:
    return hashlib.sha256(canonical_payload(fields, prev_hash)).hexdigest()


def sign_hash(entry_hash: str) -> str:
    """Sign the entry hash, which already covers every field and the link."""
    return base64.b64encode(_SIGNING_KEY.sign(entry_hash.encode("ascii"))).decode()


def signature_is_valid(entry_hash: str, signature: str) -> bool:
    try:
        _PUBLIC_KEY.verify(base64.b64decode(signature), entry_hash.encode("ascii"))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def record(
    session: Session,
    *,
    actor: str,
    actor_sub: str,
    institution: str,
    roles: list[str],
    action: str,
    decision: str,
    dataset_id: int | None = None,
    reason: str = "",
    client_ip: str = "",
    request_id: str = "",
) -> AuditEntry:
    """Append one entry, linked to the current tip of the chain, and sign it."""
    # Serialise appends. Without this, two simultaneous requests can read the
    # same prev_hash and write two entries claiming the same predecessor,
    # forking the chain and making verification fail on honest data.
    session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": APPEND_LOCK_KEY})

    tip = session.execute(
        select(AuditEntry.entry_hash).order_by(AuditEntry.id.desc()).limit(1)
    ).scalar()
    prev_hash = tip or GENESIS_HASH

    fields: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "actor": actor,
        "actor_sub": actor_sub,
        "institution": institution,
        "roles": ",".join(sorted(roles)),
        "action": action,
        "dataset_id": dataset_id,
        "decision": decision,
        "reason": reason,
        "client_ip": client_ip,
        "request_id": request_id,
    }

    entry_hash = compute_hash(fields, prev_hash)
    entry = AuditEntry(
        **fields,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
        signature=sign_hash(entry_hash),
    )
    session.add(entry)
    session.commit()
    return entry


def verify_chain(session: Session) -> dict[str, Any]:
    """Walk the chain from the start. Returns the first entry that fails."""
    prev_hash = GENESIS_HASH
    checked = 0

    def failure(entry_id: int, reason: str) -> dict[str, Any]:
        return {
            "ok": False,
            "entries_checked": checked,
            "first_bad_id": entry_id,
            "reason": reason,
            "tip_hash": None,
        }

    for entry in session.scalars(select(AuditEntry).order_by(AuditEntry.id)):
        checked += 1

        if entry.prev_hash != prev_hash:
            return failure(entry.id, "prev_hash does not point at the previous entry")

        fields = {key: getattr(entry, key) for key in HASHED_FIELDS}
        if entry.entry_hash != compute_hash(fields, prev_hash):
            return failure(entry.id, "entry contents do not match its stored hash")

        # The check an attacker with database access cannot defeat: the signing
        # key is not in the database, so they cannot re-sign what they rewrote.
        if not signature_is_valid(entry.entry_hash, entry.signature):
            return failure(entry.id, "signature is missing or invalid")

        prev_hash = entry.entry_hash

    return {
        "ok": True,
        "entries_checked": checked,
        "first_bad_id": None,
        "reason": None,
        # Publish this somewhere outside the database to detect truncation.
        "tip_hash": prev_hash if checked else GENESIS_HASH,
    }


# Database-level append-only enforcement. This stops ordinary mistakes and
# casual tampering. It does NOT stop someone who can disable the trigger,
# which is exactly the attacker the hash chain and signatures are for.
_APPEND_ONLY_STATEMENTS = (
    """
    CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger AS $$
    BEGIN
        RAISE EXCEPTION 'audit_log is append-only: % is not permitted', TG_OP;
    END;
    $$ LANGUAGE plpgsql
    """,
    "DROP TRIGGER IF EXISTS audit_log_no_change ON audit_log",
    """
    CREATE TRIGGER audit_log_no_change
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable()
    """,
)


def ensure_append_only(engine) -> None:
    with engine.begin() as conn:
        for statement in _APPEND_ONLY_STATEMENTS:
            conn.execute(text(statement))