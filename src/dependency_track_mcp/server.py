"""Dependency Track MCP Server - Main entry point.

This is a local MCP server designed to run via stdio transport.

Security Model:
- Uses stdio transport (limits access to spawning MCP client only)
- OAuth 2.1 bearer token authorization (MANDATORY)
- HTTPS only (HTTP not allowed for web deployment)
- SSL certificate verification enabled (mandatory)
- No HTTP endpoints exposed
- No token passthrough (uses server's configured API key for backend)
- Implements fine-grained scopes for permission control

See SECURITY.md for detailed security documentation.
"""

import asyncio
import logging
import sys

from fastmcp import FastMCP

from dependency_track_mcp.client import DependencyTrackClient
from dependency_track_mcp.config import (
    ConfigurationError,
    cleanup_tls_temp_files,
    get_settings,
    materialize_tls_files,
)
from dependency_track_mcp.oauth import (
    JWTValidator,
    OAuth2AuthorizationMiddleware,
)
from dependency_track_mcp.scopes import Scopes  # noqa: F401 - exported for tools
from dependency_track_mcp.tools import register_all_tools

logger = logging.getLogger(__name__)

# Create the FastMCP server with metadata
mcp = FastMCP(
    name="dependency-track",
    instructions="""
    Dependency Track MCP Server - Software Composition Analysis

    **SECURITY NOTICE**: This server requires OAuth 2.1 bearer token authentication
    as per the MCP specification. All requests must include a valid Authorization
    header: Authorization: Bearer <oauth2_token>

    This server provides tools to interact with OWASP Dependency Track for:
    - Managing projects and their components
    - Viewing and triaging security vulnerabilities
    - Uploading and exporting SBOMs (Software Bill of Materials)
    - Monitoring security metrics and policy compliance
    - Searching across the vulnerability database

    OAuth 2.1 Authorization:
    - MCP_OAUTH_ISSUER: OAuth 2.1 token issuer URL (required)
    - MCP_OAUTH_AUDIENCE: Expected token audience (optional)
    - MCP_OAUTH_REQUIRED_SCOPES: Required scopes (default: read:projects read:vulnerabilities)

    Dependency Track Backend:
    - DEPENDENCY_TRACK_URL: Base URL of your Dependency Track instance (HTTPS required)
    - DEPENDENCY_TRACK_API_KEY: API key for server-to-API authentication (not for MCP clients)
    - DEPENDENCY_TRACK_AUTH_MODE: api_key (default) or user_token (per-user sessions)

    Scopes:
    - read:projects - List and view projects
    - write:projects - Create, update, and delete projects
    - read:components - List and view components
    - read:vulnerabilities - View vulnerabilities and findings
    - write:analysis - Record analysis decisions (triage)
    - read:metrics - View security metrics
    - read:policies - View policy violations
    - upload:bom - Upload SBOM files
    - search - Search functionality

    See https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
    for OAuth 2.1 specification details.
    """,
)

# OAuth 2.1 components - initialized after validation
_oauth_validator: JWTValidator | None = None
_oauth_middleware: OAuth2AuthorizationMiddleware | None = None


def _initialize_oauth_validator() -> JWTValidator | None:
    """Initialize OAuth 2.1 JWT validator with settings.

    Returns:
        Configured JWTValidator instance, or None if settings unavailable
    """
    try:
        settings = get_settings()
    except Exception:
        # Settings not configured yet
        return None

    validator = JWTValidator(expected_issuer=settings.oauth_issuer)
    return validator


def _initialize_oauth_components() -> None:
    """Initialize OAuth 2.1 validator and middleware after validation."""
    global _oauth_validator, _oauth_middleware

    validator = _initialize_oauth_validator()
    if validator:
        settings = get_settings()
        _oauth_middleware = OAuth2AuthorizationMiddleware(
            validator=validator,
            required_scopes=settings.get_required_scopes(),
        )
    _oauth_validator = validator


# Register all tools with the server
register_all_tools(mcp)


async def cleanup():
    """Cleanup resources on shutdown."""
    await DependencyTrackClient.close_instance()
    cleanup_tls_temp_files()


def validate_security_configuration(settings) -> None:
    """Validate that security configuration is safe for production/web deployment.

    This function performs comprehensive security checks before starting the server.
    The server will not start if security requirements are not met.

    Args:
        settings: Server configuration settings

    Raises:
        ConfigurationError: If security configuration is invalid
        SystemExit: If validation fails
    """
    try:
        # Validate OAuth 2.1 is enabled
        settings.validate_oauth_enabled()

        # Validate all URLs use HTTPS
        settings.validate_configuration_for_web_deployment()

        logger.info("✓ Security configuration validated successfully")
        logger.info("✓ OAuth 2.1 issuer configured")
        logger.info("✓ Required scopes configured")
        logger.info(f"✓ HTTPS enabled: {settings.url.startswith('https://')}")
        logger.info(f"✓ SSL verification: {settings.verify_ssl}")

    except ConfigurationError as e:
        logger.error("=" * 80)
        logger.error("SECURITY CONFIGURATION ERROR - SERVER CANNOT START")
        logger.error("=" * 80)
        logger.error(str(e))
        logger.error("=" * 80)
        logger.error("\nTo fix this issue:")
        logger.error("1. Set MCP_OAUTH_ISSUER to your OAuth 2.1 provider URL")
        logger.error("2. Ensure all URLs use HTTPS (not HTTP)")
        logger.error("3. Set DEPENDENCY_TRACK_VERIFY_SSL=true for production")
        logger.error("4. Set MCP_OAUTH_ENABLED=true")
        logger.error("\nSee .env.example and SECURITY.md for detailed configuration instructions.")
        logger.error("=" * 80)
        sys.exit(1)


def main():
    """Main entry point for the MCP server."""
    # Load configuration
    try:
        settings = get_settings()
    except Exception as e:
        logger.error("=" * 80)
        logger.error("CONFIGURATION ERROR - SERVER CANNOT START")
        logger.error("=" * 80)
        logger.error(f"Failed to load configuration: {e}")
        logger.error("\nRequired environment variables:")
        logger.error("  - MCP_OAUTH_ISSUER (OAuth 2.1 provider, must use HTTPS)")
        logger.error("  - DEPENDENCY_TRACK_URL (Dependency Track instance, must use HTTPS)")
        logger.error(
            "  - DEPENDENCY_TRACK_API_KEY (API key for backend, unless "
            "DEPENDENCY_TRACK_AUTH_MODE=user_token)"
        )
        logger.error("\nOptional environment variables:")
        logger.error("  - MCP_OAUTH_AUDIENCE")
        logger.error("  - MCP_OAUTH_REQUIRED_SCOPES")
        logger.error("  - DEPENDENCY_TRACK_VERIFY_SSL (default: true)")
        logger.error("  - DEPENDENCY_TRACK_TIMEOUT (default: 30)")
        logger.error("  - DEPENDENCY_TRACK_MAX_RETRIES (default: 3)")
        logger.error("  - MCP_SERVER_TRANSPORT (default: http)")
        logger.error("  - MCP_SERVER_HOST (default: 0.0.0.0)")
        logger.error("  - MCP_SERVER_PORT (default: 8000)")
        logger.error("  - MCP_SERVER_TLS_CERT (required for HTTPS)")
        logger.error("  - MCP_SERVER_TLS_KEY (required for HTTPS)")
        logger.error("\nSee .env.example for detailed configuration examples.")
        logger.error("=" * 80)
        sys.exit(1)

    # Validate security configuration
    validate_security_configuration(settings)

    # Initialize OAuth components after validation
    _initialize_oauth_components()

    # Start server
    try:
        logger.info(f"Starting HTTPS server on {settings.server_host}:{settings.server_port}")
        certfile, keyfile, ca_certs = materialize_tls_files(settings)
        mcp.run(
            transport="http",
            host=settings.server_host,
            port=settings.server_port,
            ssl_certfile=certfile,
            ssl_keyfile=keyfile,
            ssl_ca_certs=ca_certs,
            ssl_keyfile_password=settings.server_tls_keyfile_password,
        )
    finally:
        # Ensure cleanup runs
        asyncio.run(cleanup())


if __name__ == "__main__":
    main()
