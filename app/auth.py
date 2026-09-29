"""JWT verification for tokens issued by Keycloak.

The API never sees a password. It only proves, cryptographically, that a
token was issued by the identity provider we trust and is meant for us.
"""

import os
from typing import Annotated, Any

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient
from pydantic import BaseModel

# Where tokens must SAY they came from (the "iss" claim, as seen by clients)
OIDC_ISSUER = os.environ["OIDC_ISSUER"]
# Where WE fetch the public keys from (reachable from inside the container)
OIDC_JWKS_URL = os.environ["OIDC_JWKS_URL"]
# Who tokens must be addressed to (the "aud" claim)
OIDC_AUDIENCE = os.environ["OIDC_AUDIENCE"]

# Pin the algorithm. Never accept whatever the token's header asks for.
ALLOWED_ALGORITHMS = ["RS256"]

# Tolerance for small clock differences between Keycloak and this container
LEEWAY_SECONDS = 10

# Fetches and caches Keycloak's public keys, picking the right one by "kid"
_jwks_client = PyJWKClient(OIDC_JWKS_URL, cache_keys=True, lifespan=300)

# auto_error=False so we can raise our own 401 with a WWW-Authenticate header
_bearer_scheme = HTTPBearer(auto_error=False)


class CurrentUser(BaseModel):
    """The verified identity behind a request. Built only from signed claims."""

    username: str
    subject: str
    institution: str
    roles: list[str]


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def decode_token(token: str) -> dict[str, Any]:
    """Run every validation check, or raise 401. No partial trust."""
    try:
        signing_key = _jwks_client.get_signing_key_from_jwt(token)
    except Exception:
        # Unknown "kid", unreadable header, or JWKS unreachable
        raise _unauthorized("Token signing key could not be resolved")

    try:
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=ALLOWED_ALGORITHMS,
            issuer=OIDC_ISSUER,
            audience=OIDC_AUDIENCE,
            leeway=LEEWAY_SECONDS,
            options={
                "require": ["exp", "iat", "iss", "aud", "sub"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )
    except jwt.ExpiredSignatureError:
        raise _unauthorized("Token has expired")
    except jwt.ImmatureSignatureError:
        raise _unauthorized("Token is not valid yet")
    except jwt.InvalidAudienceError:
        raise _unauthorized("Token is not intended for this API")
    except jwt.InvalidIssuerError:
        raise _unauthorized("Token issuer is not trusted")
    except jwt.MissingRequiredClaimError:
        raise _unauthorized("Token is missing a required claim")
    except jwt.InvalidTokenError:
        # Catch-all: bad signature, alg:none, malformed token
        raise _unauthorized("Token is invalid")


def get_current_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)
    ],
) -> CurrentUser:
    """FastAPI dependency: turns an Authorization header into a verified user."""
    if credentials is None or not credentials.credentials:
        raise _unauthorized("Missing bearer token")

    claims = decode_token(credentials.credentials)

    institution = claims.get("institution")
    if not isinstance(institution, str) or not institution:
        raise _unauthorized("Token has no usable institution claim")

    username = claims.get("preferred_username")
    if not isinstance(username, str) or not username:
        raise _unauthorized("Token has no usable preferred_username claim")

    realm_access = claims.get("realm_access") or {}
    raw_roles = realm_access.get("roles") if isinstance(realm_access, dict) else None
    roles = [r for r in (raw_roles or []) if isinstance(r, str)]

    return CurrentUser(
        username=username,
        subject=claims["sub"],
        institution=institution,
        roles=roles,
    )


CurrentUserDep = Annotated[CurrentUser, Depends(get_current_user)]
