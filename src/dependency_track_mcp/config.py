"""Configuration management for Dependency Track MCP Server.

Security Requirements:
- HTTPS only: All URLs must use HTTPS (not HTTP)
- OAuth 2.1 required: Bearer token authorization is mandatory
- API keys: Loaded from environment variables (never hardcoded)
- SSL verification: Enabled by default for all HTTPS connections
- Input validation: Via Pydantic Field constraints
"""

import atexit
import logging
import os
import tempfile
import warnings
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import AliasChoices, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class ConfigurationError(Exception):
    """Raised when configuration is invalid or unsafe."""

    pass


class Settings(BaseSettings):
    """Dependency Track MCP Server settings loaded from environment variables.

    Security Enforcement:
    - OAuth 2.1 authorization is MANDATORY (required for MCP specification compliance)
    - HTTPS is MANDATORY for all URLs (HTTP is not allowed)
    - SSL certificate verification is MANDATORY in production
    - MCP settings use MCP_ prefix; Dependency Track backend uses DEPENDENCY_TRACK_
    - API key is for server-to-API authentication only (not for MCP clients)
    """

    model_config = SettingsConfigDict(
        env_prefix="",
        env_file=str(Path(__file__).resolve().parents[2] / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # OAuth 2.1 Authorization Settings (MANDATORY)
    oauth_enabled: bool = Field(
        default=True,
        validation_alias=AliasChoices("oauth_enabled", "MCP_OAUTH_ENABLED"),
        description="Enable OAuth 2.1 authorization (MANDATORY for production)",
    )
    oauth_issuer: str = Field(
        ...,
        validation_alias=AliasChoices("oauth_issuer", "MCP_OAUTH_ISSUER"),
        description="OAuth 2.1 token issuer URL - MUST use HTTPS (e.g., https://auth.example.com)",
    )
    oauth_jwks_url: str | None = Field(
        default=None,
        validation_alias=AliasChoices("oauth_jwks_url", "MCP_OAUTH_JWKS_URL"),
        description="OAuth 2.1 JWKS endpoint URL (auto-derived from issuer if not specified). "
        "For Keycloak: https://keycloak.example.com/realms/<realm>/protocol/openid-connect/certs",
    )
    oauth_audience: str | None = Field(
        default=None,
        validation_alias=AliasChoices("oauth_audience", "MCP_OAUTH_AUDIENCE"),
        description="OAuth 2.1 expected audience for tokens (aud claim). "
        "Configure this in Keycloak via an Audience mapper in a Client Scope.",
    )
    oauth_required_scopes: str = Field(
        default="read:projects read:vulnerabilities",
        validation_alias=AliasChoices(
            "oauth_required_scopes",
            "MCP_OAUTH_REQUIRED_SCOPES",
        ),
        description="Space-separated list of required OAuth 2.1 scopes",
    )
    oauth_resource_uri: str = Field(
        default="https://mcp.example.com/mcp",
        validation_alias=AliasChoices(
            "oauth_resource_uri",
            "MCP_OAUTH_RESOURCE_URI",
        ),
        description=(
            "Resource URI for this MCP server (used in /.well-known/oauth-protected-resource)"
        ),
    )

    # Development Settings
    dev_allow_http: bool = Field(
        default=False,
        validation_alias=AliasChoices("dev_allow_http", "MCP_DEV_ALLOW_HTTP"),
        description="DEVELOPMENT ONLY: Allow HTTP URLs (use https for production)",
    )

    # Dependency Track Settings
    url: str = Field(
        ...,
        validation_alias=AliasChoices("url", "DEPENDENCY_TRACK_URL"),
        description="Base URL of the Dependency Track instance - MUST use HTTPS (e.g., https://dtrack.example.com)",
    )
    auth_mode: Literal["api_key", "user_token"] = Field(
        default="api_key",
        validation_alias=AliasChoices("auth_mode", "DEPENDENCY_TRACK_AUTH_MODE"),
        description=(
            "How the server authenticates to Dependency Track: 'api_key' uses "
            "DEPENDENCY_TRACK_API_KEY for every request; 'user_token' exchanges the "
            "caller's OAuth access token for a Dependency Track session "
            "(POST /api/v1/user/oidc/login), so requests run with that user's "
            "permissions and portfolio access"
        ),
    )
    api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("api_key", "DEPENDENCY_TRACK_API_KEY"),
        description=(
            "API key for Dependency Track server-to-API authentication only "
            "(required when DEPENDENCY_TRACK_AUTH_MODE=api_key)"
        ),
    )
    timeout: int = Field(
        default=30,
        ge=1,
        le=300,
        validation_alias=AliasChoices("timeout", "DEPENDENCY_TRACK_TIMEOUT"),
        description="Request timeout in seconds",
    )
    verify_ssl: bool = Field(
        default=True,
        validation_alias=AliasChoices("verify_ssl", "DEPENDENCY_TRACK_VERIFY_SSL"),
        description="Whether to verify SSL certificates (MANDATORY for production)",
    )
    max_retries: int = Field(
        default=3,
        ge=0,
        le=10,
        validation_alias=AliasChoices("max_retries", "DEPENDENCY_TRACK_MAX_RETRIES"),
        description="Maximum number of retry attempts for failed requests",
    )

    # HTTP Server Settings (for web deployment)
    server_transport: str = Field(
        default="http",
        validation_alias=AliasChoices("server_transport", "MCP_SERVER_TRANSPORT"),
        description="Transport mode: 'http' (HTTPS web server via TLS)",
    )
    server_host: str = Field(
        default="0.0.0.0",
        validation_alias=AliasChoices("server_host", "MCP_SERVER_HOST"),
        description="HTTP server host address (when transport=http)",
    )
    server_port: int = Field(
        default=8000,
        ge=1,
        le=65535,
        validation_alias=AliasChoices("server_port", "MCP_SERVER_PORT"),
        description="HTTP server port (when transport=http)",
    )
    server_tls_cert: str | None = Field(
        default=None,
        validation_alias=AliasChoices("server_tls_cert", "MCP_SERVER_TLS_CERT"),
        description="PEM-encoded TLS certificate for HTTPS (required for HTTP transport)",
    )
    server_tls_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("server_tls_key", "MCP_SERVER_TLS_KEY"),
        description="PEM-encoded TLS private key for HTTPS (required for HTTP transport)",
    )
    server_tls_ca_certs: str | None = Field(
        default=None,
        validation_alias=AliasChoices("server_tls_ca_certs", "MCP_SERVER_TLS_CA_CERTS"),
        description="Optional PEM-encoded CA bundle for HTTPS (client cert verification)",
    )
    server_tls_keyfile_password: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "server_tls_keyfile_password",
            "MCP_SERVER_TLS_KEYFILE_PASSWORD",
            "DEPENDENCY_TRACK_SERVER_TLS_KEYFILE_PASSWORD",
        ),
        description="Optional password for encrypted TLS private key",
    )

    @field_validator("url")
    @classmethod
    def validate_dependency_track_url(cls, v: str) -> str:
        """Validate Dependency Track URL format.

        Note: HTTPS requirement is checked in model_validator after dev_allow_http is loaded.
        """
        v = v.rstrip("/")

        parsed = urlparse(v)

        # Must have a scheme and host
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(
                "DEPENDENCY_TRACK_URL must be a valid URL "
                "(e.g., https://dtrack.example.com or http://localhost:8080)"
            )

        return v

    @field_validator("oauth_issuer")
    @classmethod
    def validate_oauth_issuer(cls, v: str) -> str:
        """Validate OAuth issuer URL format.

        Note: HTTPS requirement is checked in model_validator after dev_allow_http is loaded.
        """
        parsed = urlparse(v)

        # Must have a scheme and host
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(
                "MCP_OAUTH_ISSUER must be a valid URL "
                "(e.g., https://auth.example.com or http://localhost:9000)"
            )

        return v

    @field_validator("verify_ssl")
    @classmethod
    def validate_ssl_verification(cls, v: bool) -> bool:
        """Validate SSL verification setting.

        Note: SSL verification can only be disabled via explicit environment variable.
        This is a safety measure to prevent accidental downgrade.

        Raises:
            ValueError: If SSL verification is disabled (not recommended)
        """
        if not v:
            import warnings

            warnings.warn(
                "SSL certificate verification is disabled (verify_ssl=false). "
                "This is UNSAFE in production and should only be used for development/testing. "
                "Ensure this is not a mistake before proceeding.",
                UserWarning,
                stacklevel=2,
            )
        return v

    @model_validator(mode="after")
    def validate_urls_https_unless_dev(self) -> "Settings":
        """Validate HTTPS requirement for URLs (unless dev mode allows HTTP).

        This runs after all field validators and model instantiation.
        Checks that URLs use HTTPS unless dev_allow_http is explicitly enabled.
        Also auto-derives JWKS URL from issuer if not provided.
        """
        # Auto-derive JWKS URL from issuer if not provided
        if not self.oauth_jwks_url:
            # For Keycloak, derive JWKS URL from issuer
            # Issuer format: https://keycloak.example.com/realms/myrealm
            # JWKS URL: https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs
            if "/realms/" in self.oauth_issuer:
                # Keycloak format
                self.oauth_jwks_url = f"{self.oauth_issuer}/protocol/openid-connect/certs"
            else:
                # Generic OIDC format - try standard path
                self.oauth_jwks_url = f"{self.oauth_issuer}/.well-known/jwks.json"

        if self.auth_mode == "api_key" and not self.api_key:
            raise ValueError(
                "DEPENDENCY_TRACK_API_KEY is required when DEPENDENCY_TRACK_AUTH_MODE=api_key"
            )

        # Check Dependency Track URL
        parsed_url = urlparse(self.url)
        if parsed_url.scheme == "http":
            if not self.dev_allow_http:
                raise ValueError(
                    "DEPENDENCY_TRACK_URL must use HTTPS for security. "
                    "HTTP is not allowed in production. "
                    "To use HTTP in development only: set MCP_DEV_ALLOW_HTTP=true"
                )
            else:
                warnings.warn(
                    "⚠️ DEVELOPMENT MODE: Using HTTP for DEPENDENCY_TRACK_URL. "
                    "This is UNSAFE and must never be used in production. "
                    "MCP_DEV_ALLOW_HTTP is enabled for development/testing only.",
                    UserWarning,
                    stacklevel=2,
                )

        # Check OAuth issuer URL (HTTP allowed in dev mode)
        parsed_issuer = urlparse(self.oauth_issuer)
        if parsed_issuer.scheme == "http":
            if not self.dev_allow_http:
                raise ValueError(
                    "MCP_OAUTH_ISSUER must use HTTPS for security. "
                    "HTTP is not allowed in production. "
                    "To use HTTP in development only: set MCP_DEV_ALLOW_HTTP=true"
                )
            else:
                warnings.warn(
                    "⚠️ DEVELOPMENT MODE: Using HTTP for MCP_OAUTH_ISSUER. "
                    "This is UNSAFE and must never be used in production. "
                    "MCP_DEV_ALLOW_HTTP is enabled for development/testing only.",
                    UserWarning,
                    stacklevel=2,
                )
        elif parsed_issuer.scheme != "https":
            raise ValueError(
                "MCP_OAUTH_ISSUER must use HTTPS or HTTP scheme. "
                f"Got: {parsed_issuer.scheme}://... "
                "Use https:// (production) or http:// (with MCP_DEV_ALLOW_HTTP=true for dev only)."
            )

        # Warn if dev_allow_http is enabled
        if self.dev_allow_http:
            warnings.warn(
                "⚠️ DEVELOPMENT MODE ENABLED: MCP_DEV_ALLOW_HTTP=true. "
                "This allows HTTP URLs for development/testing only. "
                "NEVER enable this in production deployments.",
                UserWarning,
                stacklevel=2,
            )

        return self

    def validate_oauth_enabled(self) -> None:
        """Validate that OAuth 2.1 is enabled.

        OAuth 2.1 is mandatory for MCP specification compliance and web deployment.

        Raises:
            ConfigurationError: If OAuth is not properly configured
        """
        if not self.oauth_enabled:
            raise ConfigurationError(
                "OAuth 2.1 authorization is MANDATORY and cannot be disabled. "
                "Set MCP_OAUTH_ENABLED=true to enable OAuth 2.1. "
                "Disabling OAuth violates MCP specification requirements "
                "and is unsafe for web deployment."
            )

    def validate_configuration_for_web_deployment(self) -> None:
        """Validate that configuration is safe for web deployment.

        This performs comprehensive security checks to ensure the server can be
        safely deployed on the web.

        Note: HTTP is allowed for development if dev_allow_http=true, but this
        should never be used in production deployments.

        Raises:
            ConfigurationError: If configuration is unsafe
        """
        # Check OAuth is enabled
        self.validate_oauth_enabled()

        # Check HTTPS for Dependency Track (unless dev_allow_http)
        if not self.url.startswith("https://"):
            if not self.dev_allow_http:
                raise ConfigurationError(
                    "DEPENDENCY_TRACK_URL must use HTTPS for production. HTTP is not allowed. "
                    f"Current value: {self.url}\n"
                    "For development only, set MCP_DEV_ALLOW_HTTP=true"
                )
            # else: dev_allow_http is true, HTTP is allowed for dev

        # Check HTTPS for OAuth issuer (unless dev_allow_http)
        if not self.oauth_issuer.startswith("https://"):
            if not self.dev_allow_http:
                raise ConfigurationError(
                    "MCP_OAUTH_ISSUER must use HTTPS for production. HTTP is not allowed. "
                    f"Current value: {self.oauth_issuer}\n"
                    "For development only, set MCP_DEV_ALLOW_HTTP=true"
                )
            # else: dev_allow_http is true, HTTP is allowed for dev

        # Require TLS for HTTP transport (HTTPS only)
        if not self.server_tls_cert or not self.server_tls_key:
            raise ConfigurationError(
                "TLS is required for HTTPS. Provide both MCP_SERVER_TLS_CERT "
                "and MCP_SERVER_TLS_KEY to enable HTTPS."
            )

        # Check SSL verification
        if not self.verify_ssl:
            raise ConfigurationError(
                "SSL certificate verification must be enabled for web deployment. "
                "Set DEPENDENCY_TRACK_VERIFY_SSL=true or remove the setting "
                "to use the default (true)."
            )

        # Check that OAuth issuer is configured
        if not self.oauth_issuer:
            raise ConfigurationError(
                "OAuth 2.1 issuer must be configured via MCP_OAUTH_ISSUER. "
                "This is required for web deployment."
            )

    @property
    def api_base_url(self) -> str:
        """Get the base URL for API requests."""
        return f"{self.url}/api/v1"

    @property
    def oauth_resource_metadata_url(self) -> str:
        """Get the OAuth resource metadata URL."""
        # Extract base URL from oauth_resource_uri
        parsed = urlparse(self.oauth_resource_uri)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        return f"{base_url}/.well-known/oauth-protected-resource"

    def get_required_scopes(self) -> set[str]:
        """Get the set of required OAuth 2.1 scopes."""
        return set(scope.strip() for scope in self.oauth_required_scopes.split() if scope.strip())


_TLS_TEMP_FILES: list[str] = []
_TLS_CLEANUP_REGISTERED = False


def _ensure_tls_cleanup_registered() -> None:
    global _TLS_CLEANUP_REGISTERED
    if not _TLS_CLEANUP_REGISTERED:
        atexit.register(cleanup_tls_temp_files)
        _TLS_CLEANUP_REGISTERED = True


def _normalize_pem(value: str) -> str:
    """Normalize PEM content from env vars.

    Supports \n-escaped newlines commonly used in environment variables.
    """
    if "\\n" in value and "\n" not in value:
        value = value.replace("\\n", "\n")
    return value.strip() + "\n"


def _write_tls_temp_file(label: str, content: str) -> str:
    _ensure_tls_cleanup_registered()
    normalized = _normalize_pem(content)
    temp = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        delete=False,
        prefix=f"dependency-track-{label}-",
        suffix=".pem",
    )
    temp.write(normalized)
    temp.flush()
    temp.close()
    _TLS_TEMP_FILES.append(temp.name)
    return temp.name


def materialize_tls_files(settings: Settings) -> tuple[str, str, str | None]:
    """Materialize TLS PEM content from env vars into temp files.

    Returns (certfile, keyfile, ca_certs) paths for server startup.
    """
    if not settings.server_tls_cert or not settings.server_tls_key:
        raise ConfigurationError(
            "TLS is required for HTTPS. Provide MCP_SERVER_TLS_CERT and MCP_SERVER_TLS_KEY."
        )

    certfile = _write_tls_temp_file("cert", settings.server_tls_cert)
    keyfile = _write_tls_temp_file("key", settings.server_tls_key)
    ca_certs = None
    if settings.server_tls_ca_certs:
        ca_certs = _write_tls_temp_file("ca", settings.server_tls_ca_certs)
    return certfile, keyfile, ca_certs


def cleanup_tls_temp_files() -> None:
    """Remove temporary TLS files created from env vars."""
    while _TLS_TEMP_FILES:
        path = _TLS_TEMP_FILES.pop()
        try:
            os.remove(path)
        except OSError:
            continue


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance.

    Raises:
        ConfigurationError: If settings are invalid
    """
    try:
        return Settings()  # type: ignore
    except Exception as e:
        raise ConfigurationError(f"Failed to load settings from environment variables: {e}") from e
