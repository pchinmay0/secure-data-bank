"""Week 2 controls: does the API believe only what Keycloak signed?"""

from conftest import auth_header, decode_payload, forge_alg_none


def test_health_is_public(api):
    # Monitoring should not need credentials.
    assert api.get("/health").status_code == 200


def test_no_token_is_rejected(api):
    response = api.get("/datasets")
    assert response.status_code == 401
    # Tell a well-behaved client how to authenticate.
    assert "bearer" in response.headers.get("www-authenticate", "").lower()


def test_valid_token_is_accepted(api, token_for):
    response = api.get("/datasets", headers=auth_header(token_for("alice")))
    assert response.status_code == 200


def test_garbage_token_is_rejected(api):
    response = api.get("/datasets", headers=auth_header("not-a-token"))
    assert response.status_code == 401


def test_tampered_token_is_rejected(api, token_for):
    # One extra character breaks the signature.
    response = api.get("/datasets", headers=auth_header(token_for("alice") + "x"))
    assert response.status_code == 401


def test_alg_none_forgery_is_rejected(api, token_for):
    """The payload is byte-identical to a valid token. Only the header changes.

    A library that trusted the token's own "alg" field would accept this.
    """
    forged = forge_alg_none(token_for("alice"))
    assert decode_payload(forged)["preferred_username"] == "alice"
    assert api.get("/datasets", headers=auth_header(forged)).status_code == 401


def test_token_for_another_client_is_rejected(api, token_for):
    """A genuine, correctly signed token that is not addressed to this API.

    admin-cli is a built-in Keycloak client. Its tokens carry no audience at
    all, which is why the API requires the claim to be present, not merely to
    match when it happens to be there.
    """
    other = token_for("alice", client_id="admin-cli")
    assert decode_payload(other).get("aud") is None
    assert api.get("/datasets", headers=auth_header(other)).status_code == 401


def test_institution_comes_from_the_token_not_the_request(api, token_for):
    """Week 1's vulnerability: the uploader used to declare the owner."""
    files = {"file": ("probe.csv", b"a,b\n1,2\n", "text/csv")}
    data = {
        "name": "ownership probe",
        "sensitivity": "internal",
        # bob is LabB. He asks to own this as UniversityA.
        "owner_institution": "UniversityA",
    }
    response = api.post(
        "/datasets",
        headers=auth_header(token_for("bob")),
        files=files,
        data=data,
    )
    assert response.status_code == 201
    assert response.json()["owner_institution"] == "LabB"
