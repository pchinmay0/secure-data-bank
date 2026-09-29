"""Shared fixtures for the attack suite.

These are integration tests: they run against the live Docker Compose stack
and use real tokens from Keycloak. Start the stack first.
"""

import base64
import json
import os
import pathlib
import subprocess

import httpx
import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
API_URL = os.environ.get("API_URL", "http://localhost:8000")
KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
REALM = "databank"
CLIENT_ID = "databank-api"

TOKEN_ENDPOINT = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"


def env_value(key: str) -> str:
    """Read one key from .env. Tests never hold credentials of their own."""
    for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip()
    raise RuntimeError(f"{key} is not set in .env")


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def decode_payload(token: str) -> dict:
    """A JWT is signed, not encrypted: the payload needs no key to read."""
    part = token.split(".")[1]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


def forge_alg_none(token: str) -> str:
    """Keep a real payload, claim alg:none, drop the signature."""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).rstrip(b"=")
    payload = token.split(".")[1]
    return f"{header.decode()}.{payload}."


def compose(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )


def psql(sql: str) -> str:
    """Run SQL as the database owner: the attacker's position in Week 4."""
    user = env_value("POSTGRES_USER")
    db = env_value("POSTGRES_DB")
    result = compose("exec", "-T", "db", "psql", "-U", user, "-d", db, "-tAc", sql)
    if result.returncode != 0:
        raise RuntimeError(f"psql failed: {result.stderr.strip()}")
    return result.stdout.strip()


@pytest.fixture(scope="session")
def client_secret() -> str:
    return env_value("DATABANK_CLIENT_SECRET")


@pytest.fixture(scope="session")
def dev_password() -> str:
    return env_value("DEV_USER_PASSWORD")


@pytest.fixture
def token_for(client_secret, dev_password):
    """Fetch a fresh token. Not cached: they expire in five minutes."""

    def _token(username: str, client_id: str = CLIENT_ID) -> str:
        data = {
            "client_id": client_id,
            "grant_type": "password",
            "username": username,
            "password": dev_password,
        }
        if client_id == CLIENT_ID:
            data["client_secret"] = client_secret
        response = httpx.post(TOKEN_ENDPOINT, data=data, timeout=15)
        response.raise_for_status()
        return response.json()["access_token"]

    return _token


@pytest.fixture(scope="session")
def api():
    with httpx.Client(base_url=API_URL, timeout=30) as client:
        # Fail fast with a useful message if the stack is not running
        try:
            client.get("/health")
        except httpx.ConnectError as exc:
            pytest.exit(f"API not reachable at {API_URL}. Run docker compose up -d. ({exc})")
        yield client
