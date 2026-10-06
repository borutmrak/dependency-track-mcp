"""Async HTTP client for Dependency Track API.

Security Features:
- HTTPS/TLS with certificate verification (verify_ssl setting)
- API key transmitted via secure X-Api-Key header (DEPENDENCY_TRACK_AUTH_MODE=api_key)
- Per-user Dependency Track sessions (DEPENDENCY_TRACK_AUTH_MODE=user_token): the caller's
  OAuth access token is exchanged for a Dependency Track session token, so Dependency Track
  enforces that user's permissions and portfolio access control
- Exponential backoff for rate limiting
- Sanitized error messages (no credential leakage)
- Input/output validation via Pydantic models
"""

import asyncio
import hashlib
import time
from typing import Any

import httpx
from fastmcp.server.dependencies import get_http_request
from jose import jwt
from jose.exceptions import JWTError

from dependency_track_mcp.config import Settings, get_settings
from dependency_track_mcp.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    ConnectionError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
)

# Relative to Settings.api_base_url (/api/v1)
OIDC_LOGIN_ENDPOINT = "/user/oidc/login"

# How long to reuse a Dependency Track session when the access token has no readable `exp`
DEFAULT_SESSION_TTL_SECONDS = 300


def _current_access_token() -> str:
    """Return the bearer token of the MCP request currently being served.

    The token has already been validated by the server's JWT middleware.
    """
    try:
        request = get_http_request()
    except RuntimeError as e:
        raise AuthenticationError(
            "DEPENDENCY_TRACK_AUTH_MODE=user_token requires an authenticated HTTP request."
        ) from e

    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        raise AuthenticationError("No bearer token found on the MCP request.")
    return token


def _token_expiry(access_token: str, now: float) -> float:
    """Expiry of the access token (unverified `exp` claim), or a short default."""
    try:
        exp = jwt.get_unverified_claims(access_token).get("exp")
    except JWTError:
        exp = None
    if isinstance(exp, int | float) and exp > now:
        return float(exp)
    return now + DEFAULT_SESSION_TTL_SECONDS


class DependencyTrackClient:
    """Async HTTP client for Dependency Track API with retry support."""

    _instance: "DependencyTrackClient | None" = None
    _client: httpx.AsyncClient | None = None

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self._client = None
        # sha256(access token) -> (Dependency Track session token, expiry timestamp)
        self._sessions: dict[str, tuple[str, float]] = {}

    @classmethod
    def get_instance(cls, settings: Settings | None = None) -> "DependencyTrackClient":
        """Get or create singleton client instance."""
        if cls._instance is None:
            cls._instance = cls(settings)
        return cls._instance

    @classmethod
    async def close_instance(cls) -> None:
        """Close the singleton client instance."""
        if cls._instance is not None:
            await cls._instance.close()
            cls._instance = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client.

        Security: Client is configured with:
        - HTTPS base URL
        - X-Api-Key header for authentication in api_key mode (not exposed in logs)
        - TLS certificate verification (configurable via verify_ssl)
        - Request timeouts to prevent hanging
        """
        if self._client is None or self._client.is_closed:
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            if self.settings.auth_mode == "api_key":
                headers["X-Api-Key"] = self.settings.api_key
            self._client = httpx.AsyncClient(
                base_url=self.settings.api_base_url,
                headers=headers,
                timeout=httpx.Timeout(self.settings.timeout),
                verify=self.settings.verify_ssl,
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
        self._sessions.clear()

    async def _auth_headers(self, force_login: bool = False) -> dict[str, str]:
        """Per-request authentication headers.

        In api_key mode the X-Api-Key header is already set on the HTTP client.
        In user_token mode the caller's access token is exchanged for a Dependency Track
        session token, which is cached until the access token expires.
        """
        if self.settings.auth_mode != "user_token":
            return {}

        access_token = _current_access_token()
        key = hashlib.sha256(access_token.encode()).hexdigest()
        now = time.time()

        cached = self._sessions.get(key)
        if cached is not None and cached[1] > now and not force_login:
            return {"Authorization": f"Bearer {cached[0]}"}

        session_token = await self._login(access_token)
        self._sessions = {k: v for k, v in self._sessions.items() if v[1] > now}
        self._sessions[key] = (session_token, _token_expiry(access_token, now))
        return {"Authorization": f"Bearer {session_token}"}

    async def _login(self, access_token: str) -> str:
        """Exchange an OAuth access token for a Dependency Track session token.

        Dependency Track validates the access token against the identity provider's
        userinfo endpoint, provisions or updates the user, and returns a session token.
        """
        client = await self._get_client()
        try:
            response = await client.post(
                OIDC_LOGIN_ENDPOINT,
                data={"accessToken": access_token},
                # The client's default JSON content type would otherwise win
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "text/plain",
                },
            )
        except httpx.ConnectError as e:
            raise ConnectionError(
                f"Failed to connect to Dependency Track at {self.settings.url}: {e}"
            ) from e
        except httpx.TimeoutException as e:
            raise ConnectionError(f"Request timed out: {e}") from e

        if response.status_code == 401:
            raise AuthenticationError(
                "Dependency Track rejected the user's access token. Check that OIDC is "
                "enabled in Dependency Track with the same identity provider as MCP_OAUTH_ISSUER."
            )
        if not response.is_success:
            self._handle_error_response(response)
        return response.text.strip()

    def _handle_error_response(self, response: httpx.Response) -> None:
        """Convert HTTP error responses to appropriate exceptions.

        Security: Error messages are sanitized to prevent information disclosure.
        API keys and authentication headers are never included in error output.
        """
        status = response.status_code
        try:
            detail = response.json()
        except Exception:
            detail = {"message": response.text}
        
        # Dependency-Track endpoints occasionally return non-dict JSON bodies
        # on error (e.g. a list of validation messages, a bare string). Coerce
        # to a dict so .get() below never raises AttributeError.
        if not isinstance(detail, dict):
            detail = {"message": str(detail)}
        
        message = detail.get("message", f"HTTP {status} error")

        if status == 400:
            raise ValidationError(message, details=detail)
        elif status == 401:
            if self.settings.auth_mode == "user_token":
                hint = "The user's Dependency Track session was rejected."
            else:
                hint = "Check your DEPENDENCY_TRACK_API_KEY."
            raise AuthenticationError(f"Authentication failed. {hint}", details=detail)
        elif status == 403:
            raise AuthorizationError(
                f"Permission denied: {message}. "
                + (
                    "The user may lack required permissions."
                    if self.settings.auth_mode == "user_token"
                    else "The API key may lack required permissions."
                ),
                details=detail,
            )
        elif status == 404:
            raise NotFoundError(message, details=detail)
        elif status == 409:
            raise ConflictError(message, details=detail)
        elif status == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitError(
                "Rate limit exceeded. Please try again later.",
                retry_after=int(retry_after) if retry_after else None,
            )
        elif status >= 500:
            raise ServerError(f"Server error: {message}", details=detail)
        else:
            # Handle any other error status
            raise ValidationError(f"HTTP {status}: {message}", details=detail)

    async def _request_with_retry(
        self,
        method: str,
        endpoint: str,
        **kwargs,
    ) -> httpx.Response:
        """Make a request with retry logic for transient failures."""
        client = await self._get_client()
        retries = 0
        last_exception = None
        reauthenticated = False
        auth_headers = await self._auth_headers()

        while retries <= self.settings.max_retries:
            try:
                if auth_headers:
                    kwargs["headers"] = {**kwargs.get("headers", {}), **auth_headers}
                response = await client.request(method, endpoint, **kwargs)

                # Success
                if response.is_success:
                    return response

                # Retryable errors (429, 5xx)
                if response.status_code == 429:
                    retry_after = response.headers.get("Retry-After", "1")
                    wait_time = int(retry_after)
                    if retries < self.settings.max_retries:
                        await asyncio.sleep(wait_time)
                        retries += 1
                        continue
                    self._handle_error_response(response)
                elif response.status_code >= 500:
                    wait_time = 2**retries  # Exponential backoff
                    if retries < self.settings.max_retries:
                        await asyncio.sleep(wait_time)
                        retries += 1
                        continue
                    self._handle_error_response(response)
                elif (
                    response.status_code == 401
                    and self.settings.auth_mode == "user_token"
                    and not reauthenticated
                ):
                    # Cached Dependency Track session expired or was revoked: log in again once
                    auth_headers = await self._auth_headers(force_login=True)
                    reauthenticated = True
                    continue
                elif 400 <= response.status_code < 500:
                    # All 4xx errors are non-retryable
                    self._handle_error_response(response)
                else:
                    # Handle any other error status
                    self._handle_error_response(response)

            except httpx.ConnectError as e:
                last_exception = ConnectionError(
                    f"Failed to connect to Dependency Track at {self.settings.url}: {e}"
                )
                if retries < self.settings.max_retries:
                    await asyncio.sleep(2**retries)
                    retries += 1
                    continue
                break

            except httpx.TimeoutException as e:
                last_exception = ConnectionError(f"Request timed out: {e}")
                if retries < self.settings.max_retries:
                    await asyncio.sleep(2**retries)
                    retries += 1
                    continue
                break

        raise last_exception or ServerError("Max retries exceeded")

    async def get(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any]:
        """Make a GET request."""
        response = await self._request_with_retry("GET", endpoint, params=params)
        return response.json()

    async def get_with_headers(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any] | list[Any], dict[str, str]]:
        """Make a GET request and return both body and headers."""
        response = await self._request_with_retry("GET", endpoint, params=params)
        return response.json(), dict(response.headers)

    async def post(
        self,
        endpoint: str,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any] | None:
        """Make a POST request."""
        response = await self._request_with_retry("POST", endpoint, json=data, params=params)
        if response.status_code == 204:
            return None
        return response.json()

    async def put(
        self,
        endpoint: str,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any] | None:
        """Make a PUT request."""
        response = await self._request_with_retry("PUT", endpoint, json=data, params=params)
        if response.status_code == 204:
            return None
        return response.json()

    async def patch(
        self,
        endpoint: str,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any] | None:
        """Make a PATCH request."""
        response = await self._request_with_retry("PATCH", endpoint, json=data)
        if response.status_code == 204:
            return None
        return response.json()

    async def delete(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | list | None = None,
    ) -> None:
        """Make a DELETE request."""
        kwargs = {"params": params}
        if data is not None:
            kwargs["json"] = data
        await self._request_with_retry("DELETE", endpoint, **kwargs)


# Convenience function for getting the client
def get_client() -> DependencyTrackClient:
    """Get the Dependency Track client instance."""
    return DependencyTrackClient.get_instance()
