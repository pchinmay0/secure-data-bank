"""Rate limiting. Runs last, because tripping the limit affects later calls."""

from conftest import auth_header

# Must match DOWNLOAD_LIMIT_PER_MINUTE in app/ratelimit.py
DOWNLOAD_LIMIT = 20


def test_download_flood_is_throttled(api, token_for):
    """Dataset 4 is public, so every one of these would otherwise succeed."""
    token = token_for("alice")
    statuses = [
        api.get("/datasets/4/file", headers=auth_header(token)).status_code
        for _ in range(DOWNLOAD_LIMIT + 5)
    ]

    assert 429 in statuses, "the limiter never engaged"
    # Everything up to the limit should have been served.
    assert statuses[0] == 200
    # Once throttled, it stays throttled inside the window.
    assert statuses[-1] == 429


def test_throttled_response_says_when_to_retry(api, token_for):
    token = token_for("alice")
    response = None
    for _ in range(DOWNLOAD_LIMIT + 5):
        response = api.get("/datasets/4/file", headers=auth_header(token))
        if response.status_code == 429:
            break
    assert response.status_code == 429
    # A well-behaved client needs to know how long to wait.
    assert int(response.headers["retry-after"]) > 0


def test_health_is_never_throttled(api):
    # Monitoring must keep working while the API is under load.
    assert all(api.get("/health").status_code == 200 for _ in range(30))
