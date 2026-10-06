"""Tests for DEPENDENCY_TRACK_AUTH_MODE=user_token (per-user Dependency Track sessions)."""

import time
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs

import httpx
import pytest
import respx
from jose import jwt

from dependency_track_mcp.client import DEFAULT_SESSION_TTL_SECONDS, DependencyTrackClient
from dependency_track_mcp.config import Settings
from dependency_track_mcp.exceptions import AuthenticationError, AuthorizationError

BASE = "https://test.example.com/api/v1"


def _access_token(sub: str = "user-1", exp_in: int = 600) -> str:
    return jwt.encode({"sub": sub, "exp": int(time.time()) + exp_in}, "secret", algorithm="HS256")


def _request_with_token(token: str | None):
    headers = {"authorization": f"Bearer {token}"} if token else {}
    return SimpleNamespace(headers=headers)


@pytest.fixture
def user_settings():
    return Settings(
        url="https://test.example.com",
        oauth_issuer="https://auth.example.com",
        auth_mode="user_token",
    )


@pytest.fixture
def client(user_settings):
    return DependencyTrackClient(user_settings)


def _as_user(token: str | None):
    return patch(
        "dependency_track_mcp.client.get_http_request",
        return_value=_request_with_token(token),
    )


class TestUserTokenSettings:
    def test_api_key_not_required_in_user_token_mode(self, user_settings):
        assert user_settings.api_key is None

    def test_api_key_required_in_api_key_mode(self, monkeypatch):
        monkeypatch.delenv("DEPENDENCY_TRACK_API_KEY", raising=False)
        with pytest.raises(ValueError, match="DEPENDENCY_TRACK_API_KEY is required"):
            Settings(
                url="https://test.example.com",
                oauth_issuer="https://auth.example.com",
                _env_file=None,
            )

    def test_auth_mode_from_env(self, monkeypatch):
        monkeypatch.setenv("DEPENDENCY_TRACK_URL", "https://test.example.com")
        monkeypatch.setenv("MCP_OAUTH_ISSUER", "https://auth.example.com")
        monkeypatch.setenv("DEPENDENCY_TRACK_AUTH_MODE", "user_token")
        monkeypatch.delenv("DEPENDENCY_TRACK_API_KEY", raising=False)
        assert Settings(_env_file=None).auth_mode == "user_token"


class TestUserTokenClient:
    @pytest.mark.asyncio
    async def test_exchanges_access_token_and_uses_session(self, client):
        token = _access_token()
        with respx.mock(base_url=BASE) as mock, _as_user(token):
            login = mock.post("/user/oidc/login").respond(200, text="dt-session-1")
            projects = mock.get("/project").respond(200, json=[{"name": "p"}])

            assert await client.get("/project") == [{"name": "p"}]

        login_request = login.calls.last.request
        assert login_request.headers["content-type"] == "application/x-www-form-urlencoded"
        assert parse_qs(login_request.content.decode()) == {"accessToken": [token]}
        api_request = projects.calls.last.request
        assert api_request.headers["authorization"] == "Bearer dt-session-1"
        assert "x-api-key" not in api_request.headers

    @pytest.mark.asyncio
    async def test_session_is_cached_per_access_token(self, client):
        token_a, token_b = _access_token("a"), _access_token("b")
        with respx.mock(base_url=BASE) as mock:
            login = mock.post("/user/oidc/login")
            login.side_effect = [
                httpx.Response(200, text="session-a"),
                httpx.Response(200, text="session-b"),
            ]
            projects = mock.get("/project").respond(200, json=[])

            with _as_user(token_a):
                await client.get("/project")
                await client.get("/project")
            with _as_user(token_b):
                await client.get("/project")

        assert login.call_count == 2
        sent = [c.request.headers["authorization"] for c in projects.calls]
        assert sent == ["Bearer session-a", "Bearer session-a", "Bearer session-b"]

    @pytest.mark.asyncio
    async def test_expired_cache_entry_triggers_new_login(self, client):
        token = _access_token()
        with respx.mock(base_url=BASE) as mock, _as_user(token):
            login = mock.post("/user/oidc/login").respond(200, text="session")
            mock.get("/project").respond(200, json=[])

            await client.get("/project")
            key = next(iter(client._sessions))
            client._sessions[key] = ("session", time.time() - 1)
            await client.get("/project")

        assert login.call_count == 2

    @pytest.mark.asyncio
    async def test_rejected_session_logs_in_again_once(self, client):
        token = _access_token()
        with respx.mock(base_url=BASE) as mock, _as_user(token):
            login = mock.post("/user/oidc/login")
            login.side_effect = [
                httpx.Response(200, text="stale"),
                httpx.Response(200, text="fresh"),
            ]
            projects = mock.get("/project")
            projects.side_effect = [httpx.Response(401), httpx.Response(200, json=[])]

            assert await client.get("/project") == []

        assert login.call_count == 2
        sent = [c.request.headers["authorization"] for c in projects.calls]
        assert sent == ["Bearer stale", "Bearer fresh"]

    @pytest.mark.asyncio
    async def test_persistent_401_raises(self, client):
        with respx.mock(base_url=BASE) as mock, _as_user(_access_token()):
            mock.post("/user/oidc/login").respond(200, text="session")
            mock.get("/project").respond(401)

            with pytest.raises(AuthenticationError, match="session was rejected"):
                await client.get("/project")

    @pytest.mark.asyncio
    async def test_login_rejected(self, client):
        with respx.mock(base_url=BASE) as mock, _as_user(_access_token()):
            mock.post("/user/oidc/login").respond(401)

            with pytest.raises(AuthenticationError, match="rejected the user's access token"):
                await client.get("/project")

    @pytest.mark.asyncio
    async def test_forbidden_mentions_user_permissions(self, client):
        with respx.mock(base_url=BASE) as mock, _as_user(_access_token()):
            mock.post("/user/oidc/login").respond(200, text="session")
            mock.get("/project").respond(403, json={"message": "nope"})

            with pytest.raises(AuthorizationError, match="user may lack"):
                await client.get("/project")

    @pytest.mark.asyncio
    async def test_missing_bearer_token(self, client):
        with _as_user(None), pytest.raises(AuthenticationError, match="No bearer token"):
            await client.get("/project")

    @pytest.mark.asyncio
    async def test_outside_http_request(self, client):
        with patch(
            "dependency_track_mcp.client.get_http_request",
            side_effect=RuntimeError("No active HTTP request found."),
        ):
            with pytest.raises(AuthenticationError, match="requires an authenticated HTTP"):
                await client.get("/project")

    @pytest.mark.asyncio
    async def test_non_jwt_access_token_uses_default_ttl(self, client):
        with respx.mock(base_url=BASE) as mock, _as_user("opaque-token"):
            mock.post("/user/oidc/login").respond(200, text="session")
            mock.get("/project").respond(200, json=[])

            before = time.time()
            await client.get("/project")

        ((_, expiry),) = client._sessions.values()
        assert (
            before + DEFAULT_SESSION_TTL_SECONDS
            <= expiry
            <= time.time() + DEFAULT_SESSION_TTL_SECONDS
        )

    @pytest.mark.asyncio
    async def test_close_clears_sessions(self, client):
        with respx.mock(base_url=BASE) as mock, _as_user(_access_token()):
            mock.post("/user/oidc/login").respond(200, text="session")
            mock.get("/project").respond(200, json=[])
            await client.get("/project")

        assert client._sessions
        await client.close()
        assert not client._sessions


class TestApiKeyModeUnchanged:
    @pytest.mark.asyncio
    async def test_api_key_header_and_no_login(self, settings):
        client = DependencyTrackClient(settings)
        with respx.mock(base_url=BASE, assert_all_called=False) as mock:
            login = mock.post("/user/oidc/login")
            projects = mock.get("/project").respond(200, json=[])
            await client.get("/project")

        assert not login.called
        request = projects.calls.last.request
        assert request.headers["x-api-key"] == "test-api-key"
        assert "authorization" not in request.headers
