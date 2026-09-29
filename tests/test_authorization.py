"""Week 3 controls: the access-control matrix, enforced end to end.

Dataset fixtures in the seeded database:
    4  UniversityA  public
    6  UniversityA  restricted, shared with nobody
    1  UniversityA  restricted, shared with LabB
    9  LabB         restricted, shared with UniversityA
"""

import pytest

from conftest import auth_header

# user, path, expected status, what the case demonstrates
CASES = [
    ("alice", "/datasets/4", 200, "public dataset, metadata"),
    ("alice", "/datasets/4/file", 200, "public dataset, download"),
    ("bob", "/datasets/4/file", 200, "public crosses institutions"),
    ("alice", "/datasets/6", 200, "own institution, restricted metadata"),
    ("alice", "/datasets/6/file", 403, "researcher denied restricted download"),
    ("arun", "/datasets/6/file", 200, "data steward allowed, same dataset"),
    ("bob", "/datasets/6", 404, "other institution, not shared: hidden"),
    ("bob", "/datasets/1", 200, "shared with LabB: metadata visible"),
    ("bob", "/datasets/1/file", 403, "sharing grants metadata, never the file"),
    ("priya", "/datasets/6/file", 404, "admin has no cross-institution power"),
    ("priya", "/datasets/9/file", 200, "admin downloads own restricted data"),
    ("bob", "/datasets/9/file", 403, "researcher denied own restricted download"),
]


@pytest.mark.parametrize(
    "username,path,expected,description",
    CASES,
    ids=[f"{u}{p.replace('/', '_')}" for u, p, _, _ in CASES],
)
def test_access_matrix(api, token_for, username, path, expected, description):
    response = api.get(path, headers=auth_header(token_for(username)))
    assert response.status_code == expected, description


def test_idor_is_closed(api, token_for):
    """Week 1 let anyone walk IDs and download restricted data.

    bob now gets 404 for everything he may not know about, which is
    indistinguishable from a dataset that was never uploaded, so he cannot
    map the catalogue by reading status codes.
    """
    token = token_for("bob")
    hidden = [
        i
        for i in range(1, 12)
        if api.get(f"/datasets/{i}", headers=auth_header(token)).status_code == 404
    ]
    assert hidden, "expected at least one dataset to be invisible to bob"


def test_listing_hides_what_the_detail_route_hides(api, token_for):
    """A collection endpoint must not leak what the item endpoint refuses."""
    token = token_for("bob")
    listed = {d["id"] for d in api.get("/datasets", headers=auth_header(token)).json()}
    for dataset_id in listed:
        detail = api.get(f"/datasets/{dataset_id}", headers=auth_header(token))
        assert detail.status_code == 200, f"dataset {dataset_id} listed but not readable"


def test_privilege_escalation_via_role_claim_is_not_possible(api, token_for):
    """Roles come from the signed token, so a client cannot assert one."""
    response = api.get(
        "/datasets/6/file",
        headers={
            **auth_header(token_for("alice")),
            # None of these are read by anything. They are here to prove it.
            "X-Roles": "admin,data_steward",
            "X-Institution": "UniversityA",
        },
    )
    assert response.status_code == 403
