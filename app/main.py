import hashlib
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import Base, Dataset, engine, get_session
from app.schemas import DatasetOut, Institution, Sensitivity

UPLOAD_DIR = Path("/data/uploads")
MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB
CHUNK_SIZE = 1024 * 1024  # read 1 MB at a time


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Runs once at startup: create tables that don't exist yet
    Base.metadata.create_all(engine)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(title="Secure Research Data Bank", version="0.2.0", lifespan=lifespan)


@app.get("/health")
def health():
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return {"status": "ok", "database": "reachable"}


@app.post("/datasets", response_model=DatasetOut, status_code=201)
def upload_dataset(
    file: Annotated[UploadFile, File()],
    name: Annotated[str, Form(min_length=1, max_length=200)],
    owner_institution: Annotated[Institution, Form()],
    sensitivity: Annotated[Sensitivity, Form()],
    description: Annotated[str | None, Form(max_length=2000)] = None,
    shared_with: Annotated[list[Institution] | None, Form()] = None,
    session: Session = Depends(get_session),
):
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
        shared = sorted({i.value for i in (shared_with or [])} - {owner_institution.value})

        dataset = Dataset(
            name=name,
            description=description,
            owner_institution=owner_institution.value,
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