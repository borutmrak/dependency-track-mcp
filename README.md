# Dependency Track MCP Server

[![Tests](https://img.shields.io/badge/tests-909%20passing-brightgreen)](https://github.com/secprog/dependency-track-mcp)
[![Code Coverage](https://img.shields.io/badge/code%20coverage-100%25-brightgreen)](https://github.com/secprog/dependency-track-mcp)
[![API Coverage](https://img.shields.io/badge/API%20coverage-100%25-brightgreen)](https://github.com/secprog/dependency-track-mcp)
[![Code Quality](https://img.shields.io/badge/ruff-passing-brightgreen)](https://github.com/secprog/dependency-track-mcp)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://github.com/secprog/dependency-track-mcp)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

An MCP (Model Context Protocol) server for [OWASP Dependency Track](https://dependencytrack.org/) - enabling AI assistants to interact with your Software Composition Analysis platform.

**✨ Complete API Coverage**: 100% of Dependency Track API v4.13.6 endpoints implemented with 909 passing tests and 100% code coverage.

## Features

### 🎯 Core SCA Capabilities
- **Project Management** (28 tools): Full lifecycle, hierarchies, cloning, batch operations, tags
- **Component Analysis** (24 tools): Dependencies, CPE/PURL/SWID, internal identification, licensing
- **Vulnerability Management** (22 tools): CRUD operations, assignments, affected project queries
- **Finding Analysis** (12 tools): Triage decisions, analysis states, comments, suppression
- **Security Metrics** (16 tools): Portfolio/project metrics, historical data, trends
- **Policy Compliance** (18 tools): Policy management, conditions, violations, enforcement
- **SBOM Operations** (8 tools): Upload/export CycloneDX/SPDX, validation, token-based upload
- **Search** (6 tools): Advanced search across projects, components, vulnerabilities, services

### 📚 Reference Data & Metadata
- **Licenses** (10 tools): License and license group management with SPDX support
- **Tags** (9 tools): Project/policy tagging, collection projects
- **CWE** (2 tools): Common Weakness Enumeration reference data
- **Repositories** (8 tools): Repository type management, metadata resolution
- **Services** (8 tools): Service component tracking and management
- **VEX** (3 tools): Vulnerability Exploitability eXchange documents

### 🔧 Administration & Configuration
- **Teams** (8 tools): Team management, API key generation
- **Users** (11 tools): LDAP and managed users, team membership
- **Permissions** (4 tools): Fine-grained permission management
- **ACL** (7 tools): Project-team access control mappings
- **Notifications** (17 tools): Publishers, rules, alerts, testing (Slack, email, webhooks, etc.)
- **LDAP** (3 tools): LDAP integration and team synchronization
- **OIDC** (6 tools): OpenID Connect group management and mappings
- **Properties** (11 tools): Custom project/component properties, system configuration

### 🛠️ System & Integrations
- **Version** (1 tool): Application version and build information
- **Badges** (3 tools): SVG badge generation for vulnerabilities
- **Calculator** (1 tool): CVSS v2/v3 score calculation
- **Integrations** (4 tools): Third-party integration management
- **Events** (1 tool): System event monitoring

## Installation

```bash
pip install dependency-track-mcp
```

Or install from source:

```bash
git clone https://github.com/secprog/dependency-track-mcp.git
cd dependency-track-mcp
pip install -e .
```

## Configuration

### Security Warning ⚠️ - OAuth 2.1 Required

**This MCP server requires OAuth 2.1 bearer token authentication** as specified in the [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).

All requests must include a valid OAuth 2.1 bearer token:
```
Authorization: Bearer <your_oauth2_token>
```

Follow these security best practices:

- **Configure OAuth 2.1 issuer** - Set `MCP_OAUTH_ISSUER` to your OAuth provider
- **Never commit API keys** - Use environment variables or an environment file based on [.env.example](.env.example) (already ignored by [.gitignore](.gitignore))
- **Use HTTPS only** - Always connect to Dependency Track over HTTPS with valid certificates
- **Minimal scopes** - Request only the scopes your use case needs
- **Rotate credentials** - Change API keys and tokens periodically
- **Secure client configs** - Restrict file permissions on MCP client configuration files

📖 See [KEYCLOAK_SETUP.md](KEYCLOAK_SETUP.md) and [.env.example](.env.example) for OAuth 2.1 setup and configuration examples.

### Environment Variables

Set the following environment variables:

```bash
# OAuth 2.1 Authorization (REQUIRED)
export MCP_OAUTH_ISSUER=https://auth.example.com
export MCP_OAUTH_JWKS_URL=https://auth.example.com/.well-known/jwks.json  # Optional (auto-derived if omitted)
export MCP_OAUTH_AUDIENCE=dependency-track-mcp  # Optional
export MCP_OAUTH_REQUIRED_SCOPES="read:projects read:vulnerabilities"  # Optional
export MCP_OAUTH_RESOURCE_URI=https://your-mcp-host.example.com/mcp  # Optional

# Dependency Track Backend (for server-to-API auth only)
export DEPENDENCY_TRACK_URL=https://dependency-track.example.com
export DEPENDENCY_TRACK_API_KEY=your-dtrack-api-key  # Required when DEPENDENCY_TRACK_AUTH_MODE=api_key
export DEPENDENCY_TRACK_AUTH_MODE=api_key  # Optional: api_key (default) or user_token

# Optional
export DEPENDENCY_TRACK_TIMEOUT=30
export DEPENDENCY_TRACK_VERIFY_SSL=true
export DEPENDENCY_TRACK_MAX_RETRIES=3

# Server Settings (HTTPS by default)
export MCP_SERVER_HOST=0.0.0.0
export MCP_SERVER_PORT=9000
export MCP_SERVER_TLS_CERT="-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
export MCP_SERVER_TLS_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
export MCP_SERVER_TLS_CA_CERTS="-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"  # Optional
export MCP_SERVER_TLS_KEYFILE_PASSWORD=your_password  # Optional
```

Or create an environment file based on [.env.example](.env.example).

### OAuth 2.1 Setup

1. **Configure your OAuth provider** to support OpenID Connect with JWT tokens
2. **Publish JWKS endpoint** for token signature verification
3. **Set token claims** to include `sub`, `iat`, `exp`, and `scope` or `scopes`
4. **Use HTTPS** for all OAuth endpoints
5. **Set appropriate token lifetime** (e.g., 1 hour)

### Getting a Dependency Track API Key

The API key is used for **server-to-API authentication only** and is not exposed to MCP clients.

1. Log in to Dependency Track as an administrator
2. Navigate to Administration > Access Management > Teams
3. Select or create a team
4. Generate a new API key for the team
5. Copy the key (it won't be shown again)
6. Store it in `DEPENDENCY_TRACK_API_KEY` environment variable

### Per-User Permissions (`DEPENDENCY_TRACK_AUTH_MODE=user_token`)

With an API key, every MCP user acts with the permissions of the key's team. To have Dependency Track
enforce each user's own permissions and portfolio access control instead, set
`DEPENDENCY_TRACK_AUTH_MODE=user_token` (no API key needed). For every MCP request the server exchanges
the caller's OAuth access token for a Dependency Track session via `POST /api/v1/user/oidc/login`, and
calls the API with that session (`Authorization: Bearer`). Sessions are cached until the access token
expires.

Requirements:

1. OIDC is enabled in Dependency Track, using the same identity provider as `MCP_OAUTH_ISSUER`.
2. The access token can be used at the identity provider's userinfo endpoint (the `openid` scope), and
   userinfo returns Dependency Track's username claim (`DT_OIDC_USERNAME_CLAIM` /
   `ALPINE_OIDC_USERNAME_CLAIM`) and, with team synchronization, its teams claim.
3. The `sub` claim must be the same as in tokens of Dependency Track's own OIDC client, otherwise
   Dependency Track refuses the login of an existing user ("subject identifier has changed").
4. With user provisioning disabled in Dependency Track, users must have logged in to the UI once.

Dependency Track validates the access token by calling userinfo with it, so it accepts any valid access
token from that provider; the MCP server only forwards tokens it has already validated.

## Usage

### Running the Server

```bash
# Using the installed entry point
dependency-track-mcp

# Or run directly
python -m dependency_track_mcp.main
```

This starts a FastAPI server with OAuth 2.1 JWT authentication and mounts the MCP endpoint at `/mcp`. If TLS certs are provided, it serves HTTPS. HTTP is only allowed when `MCP_DEV_ALLOW_HTTP=true`.

### HTTP Endpoints

- `/mcp` - MCP protocol endpoint (protected by OAuth 2.1 Bearer tokens)
- `/.well-known/oauth-protected-resource` - OAuth resource metadata (RFC 8707)
- `/health` - Health check

### Configuration for Production

Required environment variables (or an environment file based on [.env.example](.env.example)):

```bash
# OAuth 2.1 (required)
MCP_OAUTH_ISSUER=https://keycloak.example.com/realms/mcp
MCP_OAUTH_AUDIENCE=mcp-api

# TLS certificates (required for HTTPS)
MCP_SERVER_TLS_CERT="-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
MCP_SERVER_TLS_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"

# Dependency Track backend
DEPENDENCY_TRACK_URL=https://dtrack.example.com
DEPENDENCY_TRACK_API_KEY=your-api-key
```

### Local Development

For local development with HTTP (never use in production):

```bash
# Enable HTTP for local testing
MCP_DEV_ALLOW_HTTP=true
MCP_OAUTH_ISSUER=http://localhost:8083/realms/mcp
DEPENDENCY_TRACK_URL=http://localhost:8081
```

See [KEYCLOAK_SETUP.md](KEYCLOAK_SETUP.md) for setting up local Keycloak.

### Quick Start Script

If you prefer a simple launcher with environment-file validation, use [start_services.py](start_services.py).

### Client Configuration (HTTP transport)

Point your MCP client at the HTTP endpoint and include a Bearer token:

- MCP endpoint: `https://<host>:<port>/mcp` (use `http://` only when `MCP_DEV_ALLOW_HTTP=true`)
- Authorization header: `Authorization: Bearer <oauth2_token>`

**Security Notes**:
- The Dependency Track API key is stored server-side only (not exposed to clients)
- OAuth tokens are transmitted at runtime (not stored in config)
- TLS certificates can be provided as PEM content (use `\n` for newlines)
- Restrict file permissions on any client config that includes secrets

## MCP Scopes

The server implements **fine-grained OAuth 2.1 scopes** for precise access control:

### Core SCA Operations

| Scope | Description |
|-------|-------------|
| `read:projects` | List and view projects |
| `write:projects` | Create, update, and delete projects |
| `read:components` | List and view components |
| `write:components` | Create/update components |
| `read:vulnerabilities` | View vulnerabilities and findings |
| `write:vulnerabilities` | Create, update, delete vulnerabilities |
| `write:analysis` | Record analysis decisions (triage) |
| `read:metrics` | View security metrics |
| `read:policies` | View policy violations |
| `write:policies` | Create/update policies |
| `upload:bom` | Upload SBOM files |
| `upload:vex` | Upload VEX documents |
| `search` | Search functionality |

### Reference Data

| Scope | Description |
|-------|-------------|
| `read:licenses` | List and view licenses |
| `write:licenses` | Create/update license groups |
| `read:tags` | List and view tags |
| `write:tags` | Create/update tags |
| `read:services` | List and view services |
| `write:services` | Create/update services |
| `read:repositories` | List and view repositories |
| `write:repositories` | Create/update repositories |
| `read:cwe` | View CWE reference data |

### Administration (Fine-Grained)

| Scope | Description |
|-------|-------------|
| `read:teams` | List and view teams |
| `write:teams` | Create, update, delete teams |
| `manage:api-keys` | Generate, regenerate, delete API keys |
| `read:users` | List and view users |
| `write:users` | Create, update, delete users |
| `manage:user-teams` | Add/remove users from teams |
| `read:permissions` | List permissions |
| `write:permissions` | Grant/revoke permissions |
| `read:acl` | View access control mappings |
| `write:acl` | Manage access control mappings |
| `read:notifications` | List notification publishers and rules |
| `write:notification-publishers` | Create/update/delete notification publishers |
| `write:notification-rules` | Create/update/delete notification rules |
| `test:notifications` | Send test notifications |
| `read:ldap` | List LDAP groups |
| `write:ldap` | Manage LDAP team mappings |
| `read:oidc` | Check OIDC availability, list groups |
| `write:oidc` | Manage OIDC groups and mappings |
| `read:config` | List/view configuration properties |
| `write:config` | Update configuration properties |

### System & Integrations

| Scope | Description |
|-------|-------------|
| `system:version` | Version and system info |
| `system:badges` | Project badges |
| `system:calculator` | CVSS calculator |
| `system:integrations` | Manage integrations |
| `system:events` | View system events |

**Token Scope Claims**: Your OAuth tokens should include scopes in one of these formats:

```
"scope": "read:projects read:vulnerabilities write:analysis"
"scopes": "read:projects read:vulnerabilities write:analysis"
```

## Available Tools

**Complete API Coverage**: All 160+ endpoints from Dependency Track API v4.13.6 are implemented and tested.

Tool groups are registered in [src/dependency_track_mcp/tools](src/dependency_track_mcp/tools):

### Core SCA Tools
- **Projects** (28 tools): Full project lifecycle, hierarchies, cloning, batch operations
- **Components** (24 tools): Component management, dependencies, CPE, PURL, SWID
- **Vulnerabilities** (22 tools): Vulnerability CRUD, assignments, affected projects
- **Findings** (12 tools): Finding analysis, triage, comments, suppression
- **Metrics** (16 tools): Portfolio and project metrics with historical data
- **Policies** (18 tools): Policy management, conditions, violations, enforcement
- **BOM** (8 tools): Upload/export SBOMs (CycloneDX/SPDX), token-based upload
- **Search** (6 tools): Advanced search across projects, components, vulnerabilities

### Reference Data Tools
- **Licenses** (10 tools): License and license group management
- **Tags** (9 tools): Tag management, project/policy associations
- **CWE** (2 tools): Common Weakness Enumeration reference
- **Repositories** (8 tools): Repository type management and metadata
- **Services** (8 tools): Service component tracking
- **VEX** (3 tools): Vulnerability Exploitability eXchange documents

### Properties Tools
- **Project Properties** (4 tools): Custom project metadata
- **Component Properties** (4 tools): Custom component metadata
- **Config Properties** (3 tools): System configuration management

### Administration Tools
- **Teams** (8 tools): Team management and API key operations
- **Users** (11 tools): User management, LDAP/managed users, team membership
- **Permissions** (4 tools): Permission management and assignments
- **ACL** (7 tools): Project-team access control mappings
- **Notifications** (17 tools): Publishers, rules, alerts, and testing
- **LDAP** (3 tools): LDAP integration and team mappings
- **OIDC** (6 tools): OpenID Connect group management

### System & Integration Tools
- **Version** (1 tool): Application version and build info
- **Badges** (3 tools): SVG badge generation for projects
- **Calculator** (1 tool): CVSS score calculation
- **Integrations** (4 tools): Third-party integration management
- **Events** (1 tool): System event monitoring

## Quality & Testing

### Test Coverage

- **909 tests** - 100% passing
- **100% code coverage** - All 3,313 lines of code fully tested
- **100% API coverage** - All Dependency Track API v4.13.6 endpoints
- **Unit tests** - Client, config, OAuth, models, scopes, all tools
- **Integration tests** - End-to-end tool validation
- **Mock-based** - Fast execution with respx HTTP mocking

### Code Quality

- **Ruff** - All linting rules pass (E, F, I, N, W, UP)
- **Type hints** - Full type annotation coverage
- **Pydantic** - Validated models for all API types
- **Async-first** - All I/O operations use async/await
- **Error handling** - Comprehensive exception hierarchy

### Security Standards

- **OAuth 2.1** - Full JWT validation with JWKS
- **HTTPS/TLS** - Certificate verification enabled by default
- **Scope validation** - Fine-grained permission checks
- **Input validation** - Pydantic models for all inputs
- **No secrets in logs** - Sensitive data properly masked

## Development

### Setup

```bash
git clone https://github.com/secprog/dependency-track-mcp.git
cd dependency-track-mcp
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests (909 tests)
pytest

# Run with coverage report (100% coverage)
pytest --cov=src/dependency_track_mcp --cov-report=html

# Run specific test categories
pytest -m unit              # Unit tests only
pytest -m integration       # Integration tests only

# Run specific test file
pytest tests/test_client.py

# Run with verbose output
pytest -v

# Run tests matching a pattern
pytest -k "test_oauth"
```

### Code Formatting

```bash
ruff check .
ruff format .
```

## Security

This MCP server implements OAuth 2.1 bearer token authorization as required by the [MCP Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).

**Key Security Features**:
- 🔐 **OAuth 2.1 Bearer Tokens** - Required per MCP specification
- ✅ **JWT Validation** - Structure, expiration, issuer, and scope validation
- 🔒 **HTTPS/TLS** - Certificate verification enabled by default
- 🔑 **Secure API Key Management** - Backend keys via environment variables only
- 🛡️ **Input Validation** - Pydantic models for all inputs/outputs
- 🚫 **No Token Passthrough** - OAuth tokens not sent to backend
- 📊 **Scope-Based Authorization** - Fine-grained permission control
- ⚡ **Retry/Backoff** - Resilient HTTP client with retries

**OAuth 2.1 Requirements**:
- All requests must include valid Bearer token in Authorization header
- Tokens must be valid JWTs with required claims (`sub`, `iat`, `exp`, `scope`/`scopes`)
- Server validates token expiration, issuer, and required scopes
- MCP client is responsible for obtaining tokens from OAuth provider
- Token signature verification is performed using JWKS (auto-derived from issuer)

To validate your configuration locally, run [verify_security.py](verify_security.py).

## License

MIT License - see [LICENSE](LICENSE) for details.

## Related Projects

- [OWASP Dependency Track](https://dependencytrack.org/)
- [FastMCP](https://github.com/jlowin/fastmcp)
- [Model Context Protocol](https://modelcontextprotocol.io/)
