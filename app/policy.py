"""Ask Open Policy Agent whether a request is allowed.

The application knows WHO is asking and WHAT they are asking for. It does not
know the rules. Those live in policies/databank.rego and are evaluated here.
"""

import os
from typing import Any

import httpx
from fastapi import HTTPException, status

from app.auth import CurrentUser
from app.db import Dataset

OPA_URL = os.environ["OPA_URL"]
OPA_TIMEOUT_SECONDS = 2.0

# One connection pool for the process, rather than a new connection per request
_client = httpx.Client(timeout=OPA_TIMEOUT_SECONDS)


def _user_input(user: CurrentUser) -> dict[str, Any]:
    # Only what the policy needs. Never the raw token.
    return {
        "username": user.username,
        "institution": user.institution,
        "roles": user.roles,
    }


def _dataset_input(dataset: Dataset | None) -> dict[str, Any]:
    if dataset is None:
        return {}
    return {
        "id": dataset.id,
        "owner_institution": dataset.owner_institution,
        "sensitivity": dataset.sensitivity,
        "shared_with": list(dataset.shared_with or []),
    }


def is_allowed(user: CurrentUser, action: str, dataset: Dataset | None = None) -> bool:
    """Return OPA's decision. Any failure denies rather than guesses."""
    payload = {
        "input": {
            "user": _user_input(user),
            "action": action,
            "dataset": _dataset_input(dataset),
        }
    }

    try:
        response = _client.post(OPA_URL, json=payload)
        response.raise_for_status()
        body = response.json()
    except Exception:
        # OPA unreachable, slow, or returning nonsense. We cannot make an
        # access decision, so we refuse to serve the request at all.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authorization service unavailable",
        )

    # A missing "result" means the rule did not evaluate. Treat as deny.
    return body.get("result") is True


def require(user: CurrentUser, action: str, dataset: Dataset | None = None) -> None:
    """Allow the request to continue, or raise 403."""
    if not is_allowed(user, action, dataset):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not permitted by policy",
        )


def require_visible(user: CurrentUser, dataset: Dataset) -> None:
    """Raise 404 if the user may not even know this dataset exists.

    Returning 403 here would confirm the dataset is real, letting an attacker
    map the catalogue by walking IDs and reading the status codes.
    """
    if not is_allowed(user, "read_metadata", dataset):
        raise HTTPException(status_code=404, detail="Dataset not found")
