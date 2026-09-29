import hashlib
import re
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi import Path as PathParam
from fastapi.responses import FileResponse
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.auth import CurrentUserDep
from app import policy
from app.db import Base, Dataset, engine, get_session
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
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(title="Secure Research Data Bank", version="0.5.0", lifespan=lifespan)


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
    file: Annotated[UploadFile, File()],
    name: Annotated[str, Form(min_length=1, max_length=200)],
    user: CurrentUserDep,
    sensitivity: Annotated[Sensitivity, Form()],
    description: Annotated[str | None, Form(max_length=2000)] = None,
    shared_with: Annotated[list[Institution] | None, Form()] = None,
    session: Session = Depends(get_session),
):
    policy.require(user, "upload")

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

    return dataset


@app.get("/datasets", response_model=list[DatasetOut])
def list_datasets(
    user: CurrentUserDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    session: Session = Depends(get_session),
):
    stmt = select(Dataset).order_by(Dataset.id).limit(limit).offset(offset)
    datasets = session.scalars(stmt).all()
    # Filter by policy: a dataset the caller may not see must not appear here
    # either, or the listing becomes a way around the per-dataset check.
    return [d for d in datasets if policy.is_allowed(user, "read_metadata", d)]


@app.get("/datasets/{dataset_id}", response_model=DatasetOut)
def get_dataset(
    dataset_id: DatasetId,
    user: CurrentUserDep,
    session: Session = Depends(get_session),
):
    dataset = get_dataset_or_404(dataset_id, session)
    policy.require_visible(user, dataset)
    return dataset


@app.get("/datasets/{dataset_id}/file")
def download_dataset(
    dataset_id: DatasetId,
    user: CurrentUserDep,
    session: Session = Depends(get_session),
):
    dataset = get_dataset_or_404(dataset_id, session)

    # 404 if they may not even know it exists; 403 if they may see it but
    # are not permitted the file itself.
    policy.require_visible(user, dataset)
    policy.require(user, "download", dataset)

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