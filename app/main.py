import hashlib
import re
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi import Path as PathParam
from fastapi.responses import FileResponse
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app import audit, policy
from app.auth import CurrentUser, CurrentUserDep
from app.db import Base, Dataset, engine, get_session
from app.ratelimit import rate_limit_middleware
from app.schemas import DatasetOut, Institution, Sensitivity

UPLOAD_DIR = Path("/data/uploads")
MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB
CHUNK_SIZE = 1024 * 1024  # read 1 MB at a time
MAX_DB_INT = 2_147_483_647  # largest value a PostgreSQL INTEGER can hold

DatasetId = Annotated[int, PathParam(ge=1, le=MAX_DB_INT)]


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Runs once at startup: create tables that don't exist yet
    Base.metadata.create_all(engine)
    audit.ensure_append_only(engine)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(title="Secure Research Data Bank", version="0.7.0", lifespan=lifespan)

# Added last, so it runs FIRST: reject a flood before doing any work on it.
app.middleware("http")(rate_limit_middleware)


@app.middleware("http")
async def add_request_id(request: Request, call_next):
    """Tag every request so a log entry can be tied back to one HTTP call."""
    request.state.request_id = uuid.uuid4().hex
    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    return response


def client_ip(request: Request) -> str:
    # request.client is the direct peer. X-Forwarded-For is NOT used here:
    # any client can send that header, so trusting it without a known proxy
    # in front lets an attacker forge the source address in the audit log.
    return request.client.host if request.client else ""


def log_decision(
    session: Session,
    request: Request,
    user: CurrentUser,
    action: str,
    decision: str,
    dataset_id: int | None = None,
    reason: str = "",
) -> None:
    audit.record(
        session,
        actor=user.username,
        actor_sub=user.subject,
        institution=user.institution,
        roles=user.roles,
        action=action,
        decision=decision,
        dataset_id=dataset_id,
        reason=reason,
        client_ip=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )


def enforce(
    session: Session,
    request: Request,
    user: CurrentUser,
    action: str,
    dataset: Dataset | None = None,
    hide_when_denied: bool = False,
) -> None:
    """Ask OPA, record the answer, then act on it.

    The log is written for allow AND deny. A refused request is often the more
    interesting record: it is the evidence that someone tried.
    """
    allowed = policy.is_allowed(user, action, dataset)
    log_decision(
        session,
        request,
        user,
        action,
        "allow" if allowed else "deny",
        dataset_id=dataset.id if dataset is not None else None,
        reason="" if allowed else "denied by policy",
    )
    if allowed:
        return
    if hide_when_denied:
        # 404 rather than 403, so a denial does not confirm the dataset exists
        raise HTTPException(status_code=404, detail="Dataset not found")
    raise HTTPException(status_code=403, detail="Not permitted by policy")


def get_dataset_or_404(dataset_id: int, session: Session) -> Dataset:
    dataset = session.get(Dataset, dataset_id)
    if dataset is None:
        raise HTTPException(status_code=404, detail="Dataset not found")
    return dataset


def safe_download_name(original: str) -> str:
    # Keep only letters, digits, dot, dash and underscore for the download header
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", original).strip("._")
    return cleaned[:100] or "dataset"


@app.get("/health")
def health():
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return {"status": "ok", "database": "reachable"}


@app.post("/datasets", response_model=DatasetOut, status_code=201)
def upload_dataset(
    request: Request,
    file: Annotated[UploadFile, File()],
    name: Annotated[str, Form(min_length=1, max_length=200)],
    sensitivity: Annotated[Sensitivity, Form()],
    user: CurrentUserDep,
    description: Annotated[str | None, Form(max_length=2000)] = None,
    shared_with: Annotated[list[Institution] | None, Form()] = None,
    session: Session = Depends(get_session),
):
    enforce(session, request, user, "upload")

    # Never use the uploader's filename on disk: generate our own
    stored_filename = uuid.uuid4().hex
    dest = UPLOAD_DIR / stored_filename

    hasher = hashlib.sha256()
    size = 0
    try:
        with dest.open("xb") as out:
            while chunk := file.file.read(CHUNK_SIZE):
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="File larger than 50 MB")
                hasher.update(chunk)
                out.write(chunk)

        if size == 0:
            raise HTTPException(status_code=400, detail="Uploaded file is empty")

        # Remove duplicates, and don't "share" a dataset with its own owner
        shared = sorted({i.value for i in (shared_with or [])} - {user.institution})

        dataset = Dataset(
            name=name,
            description=description,
            owner_institution=user.institution,
            sensitivity=sensitivity.value,
            shared_with=shared,
            original_filename=Path(file.filename or "unnamed").name[:255],
            stored_filename=stored_filename,
            content_type=(file.content_type or "application/octet-stream")[:100],
            size_bytes=size,
            sha256=hasher.hexdigest(),
        )
        session.add(dataset)
        session.commit()
        session.refresh(dataset)
    except Exception:
        # Upload failed or DB write failed: don't leave an orphan file behind
        dest.unlink(missing_ok=True)
        raise

    log_decision(session, request, user, "upload_complete", "allow", dataset_id=dataset.id)
    return dataset


@app.get("/datasets", response_model=list[DatasetOut])
def list_datasets(
    request: Request,
    user: CurrentUserDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    session: Session = Depends(get_session),
):
    stmt = select(Dataset).order_by(Dataset.id).limit(limit).offset(offset)
    datasets = session.scalars(stmt).all()
    # Filter by policy: a dataset the caller may not see must not appear here
    # either, or the listing becomes a way around the per-dataset check.
    visible = [d for d in datasets if policy.is_allowed(user, "read_metadata", d)]
    log_decision(
        session,
        request,
        user,
        "list",
        "allow",
        reason=f"{len(visible)} of {len(datasets)} visible",
    )
    return visible


@app.get("/datasets/{dataset_id}", response_model=DatasetOut)
def get_dataset(
    dataset_id: DatasetId,
    request: Request,
    user: CurrentUserDep,
    session: Session = Depends(get_session),
):
    dataset = get_dataset_or_404(dataset_id, session)
    enforce(session, request, user, "read_metadata", dataset, hide_when_denied=True)
    return dataset


@app.get("/datasets/{dataset_id}/file")
def download_dataset(
    dataset_id: DatasetId,
    request: Request,
    user: CurrentUserDep,
    session: Session = Depends(get_session),
):
    dataset = get_dataset_or_404(dataset_id, session)

    # 404 if they may not even know it exists; 403 if they may see it but
    # are not permitted the file itself.
    enforce(session, request, user, "read_metadata", dataset, hide_when_denied=True)
    enforce(session, request, user, "download", dataset)

    # The path comes from OUR database value, never from the request
    path = UPLOAD_DIR / dataset.stored_filename
    if not path.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename=safe_download_name(dataset.original_filename),
        headers={"X-Content-Type-Options": "nosniff"},
    )


@app.get("/audit")
def list_audit(
    request: Request,
    user: CurrentUserDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    session: Session = Depends(get_session),
):
    enforce(session, request, user, "read_audit")
    stmt = (
        select(audit.AuditEntry)
        .order_by(audit.AuditEntry.id)
        .limit(limit)
        .offset(offset)
    )
    return [
        {
            "id": e.id,
            "ts": e.ts,
            "actor": e.actor,
            "institution": e.institution,
            "roles": e.roles,
            "action": e.action,
            "dataset_id": e.dataset_id,
            "decision": e.decision,
            "reason": e.reason,
            "client_ip": e.client_ip,
            "request_id": e.request_id,
            "prev_hash": e.prev_hash,
            "entry_hash": e.entry_hash,
        }
        for e in session.scalars(stmt)
    ]


@app.get("/audit/verify")
def verify_audit(
    request: Request,
    user: CurrentUserDep,
    session: Session = Depends(get_session),
):
    enforce(session, request, user, "read_audit")
    return audit.verify_chain(session)