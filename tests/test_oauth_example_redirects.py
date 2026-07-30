import importlib.util
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest


def load_oauth_example():
    module_path = (
        Path(__file__).resolve().parents[1]
        / "examples"
        / "example-oauth-server-clients"
        / "oauth_sse_server.py"
    )
    spec = importlib.util.spec_from_file_location(
        "oauth_sse_server_example", module_path
    )
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


oauth_server = load_oauth_example()


@pytest.mark.asyncio
async def test_oauth_authorize_rejects_unregistered_redirect_uri():
    with pytest.raises(oauth_server.HTTPException) as exc_info:
        await oauth_server.oauth_authorize(
            response_type="code",
            client_id=oauth_server.EXPECTED_CLIENT_ID,
            redirect_uri="https://attacker.example/callback",
            state="state-123",
            scope="tools.read",
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "invalid_redirect_uri"


@pytest.mark.asyncio
async def test_oauth_authorize_allows_expected_redirect_uri():
    response = await oauth_server.oauth_authorize(
        response_type="code",
        client_id=oauth_server.EXPECTED_CLIENT_ID,
        redirect_uri=oauth_server.EXPECTED_REDIRECT_URI,
        state="state 123",
        scope="tools.read",
    )

    assert response.status_code == 302
    location = response.headers["location"]
    parsed = urlparse(location)
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == (
        oauth_server.EXPECTED_REDIRECT_URI
    )
    query = parse_qs(parsed.query)
    assert query["state"] == ["state 123"]
    assert query["code"]
