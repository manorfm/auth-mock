# Auth Mock

[![Go Version](https://img.shields.io/badge/Go-1.23-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-0.1.0-blue.svg)](https://github.com/manorfm/auth-mock/releases)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](https://github.com/manorfm/auth-mock/actions)
[![Coverage](https://img.shields.io/badge/Coverage-80%25-brightgreen.svg)](https://github.com/manorfm/auth-mock/actions)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://hub.docker.com/r/manorfm/auth-mock)

A mock authentication service for local testing and integration. It keeps **users, roles, OAuth clients, and verification state in memory** (no database). It issues JWTs with RSA keys in memory, supports **channels** (`client_app` vs `management_panel`), **user types** (`client`, `management`, `standalone`), and OAuth2/OpenID Connect flows used by dependent services.

## Key Features

### JWT Implementation
- In-memory RSA key pair generation and management
- Automatic key rotation with configurable intervals
- JWKS endpoint for public key distribution
- Support for custom claims and dynamic token fields
- Token blacklisting and revocation
- Configurable token durations (access and refresh)
- Secure key ID generation using SHA-256
- Thread-safe key operations with mutex protection

### Authentication & Authorization
- **RBAC** with fixed system roles `root`, `admin`, `user` plus **custom roles** (in-memory catalog; admin-managed)
- **Registration by channel**: public `client` and `management` signup; **standalone** users only via admin API
- **Login** requires `channel` in the JSON body; JWTs carry `roles`, `user_type`, and `channels`
- **Refresh token** returned as an **HTTP-only cookie** (`refresh_token` on path `/api`); access token in JSON for login and MFA completion
- OAuth2/OpenID Connect protocol support
- MFA with TOTP, backup codes, and MFA ticket flow when TOTP is enabled
- Email verification and password reset (optional SMTP)
- **Stricter rate limiting** on management signup, login/MFA, and admin routes (in addition to the global limiter)
- Account records created with each new user

### Security Features
- In-memory RSA key pairs (2048-bit by default)
- Secure key rotation mechanism
- Rate limiting to prevent abuse
- Input validation and sanitization
- Secure password hashing
- Token blacklisting
- Header-based API versioning
- Comprehensive error handling

### Configuration Options
- JWT token durations (access and refresh)
- RSA key size (default: 2048 bits)
- JWKS cache duration
- **`REFRESH_COOKIE_SECURE`**: set to `true` in HTTPS deployments so the refresh cookie is marked `Secure`
- SMTP settings for email delivery
- Default user configuration (optional bootstrap user on startup)
- Custom claims fields
- TOTP settings (issuer, algorithm, digits, period)
- Backup codes configuration
- Structured logging with **Zap** (including audit-style fields on sensitive admin actions)

## Architecture

The project follows a hexagonal architecture with the following layers:

- `domain`: Core business entities, interfaces, and domain-specific errors
- `application`: Use cases and business logic
- `infrastructure`: JWT, email, and other external service implementations
- `interfaces/http`: HTTP handlers, middlewares, and OpenAPI/Swagger documentation

### JWT Strategy

The service implements an in-memory JWT strategy that:

- Generates and manages RSA key pairs in memory
- Provides automatic key rotation
- Implements thread-safe operations
- Supports custom claims and dynamic fields
- Handles token verification with proper error handling
- Exposes JWKS endpoint for public key distribution

Key features of the JWT implementation:
- Automatic key rotation with configurable intervals
- Thread-safe operations using mutex protection
- Secure key ID generation using SHA-256
- Support for custom claims and dynamic fields
- Comprehensive error handling for token operations

### Error handling

- Domain errors map to JSON `code`, `message`, and optional `details` (validation)
- Wire codes are the **`U00xx`** values below; `internal/domain/errors.go` is the source of truth if the code and README diverge

## Getting Started

### Prerequisites

- Go 1.23 or later
- Make (optional)
- Docker (optional)

### Environment Variables

Create a `.env` file in the root directory with the following variables:

```env
# JWT Configuration
JWT_ACCESS_TOKEN_DURATION=15m
JWT_REFRESH_TOKEN_DURATION=168h  # 7 days
RSA_KEY_SIZE=2048
JWKS_CACHE_DURATION=1h

# Server Configuration
PORT=8080
SERVER_URL=http://localhost:8080

# Email verification gate (if true, login requires verified email)
EMAIL_ENABLED=false

# Refresh cookie (set true behind HTTPS)
REFRESH_COOKIE_SECURE=false

# Default User Configuration
DEFAULT_USER_EMAIL=admin@example.com
DEFAULT_USER_PASSWORD=admin123
DEFAULT_USER_ROLES=admin,user  # Comma-separated list of roles

# SMTP Configuration
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_FROM=noreply@example.com
SMTP_AUTH_VALIDATION=true
SMTP_USE_TLS=true
SMTP_SKIP_VERIFY=false

# TOTP Configuration
TOTP_ISSUER=User Manager Service
TOTP_ALGORITHM=SHA1
TOTP_DIGITS=6
TOTP_PERIOD=30
TOTP_BACKUP_CODES_COUNT=10

# Custom Claims (optional)
CUSTOM_CLAIMS_FIELDS={"custom_field":"value"}
```

### Running the Application

```bash
# Install dependencies
make deps

# Start the application
make run

# Run tests
make test

# Run linter
make lint

# Generate Swagger documentation (requires swag)
make swagger
```

### Docker Support

```bash
# Build Docker image
docker build -t auth-mock .

# Run with Docker
docker run -p 8080:8080 --env-file .env auth-mock
```

## API Documentation

The API documentation is available through Swagger UI. Once the application is running, you can access it at:

```
http://localhost:8080/swagger/index.html
```

### Authentication flow

Detailed design and rollout notes for refresh invalidation live in `docs/refresh-token-invalidation/`. Breaking changes (including OAuth2 refresh rotation) are listed in `CHANGELOG.md`. This mock keeps **JWT revocation (blacklist) and persistence in-process only** — no Redis or other external store for tokens.

1. **Register** with the endpoint that matches the product:
   - `POST /api/auth/register/client` — consumer app; user type `client`, channel `client_app`, role `user`
   - `POST /api/auth/register/management` — management panel; user type `management`, channel `management_panel`, role `user`
2. If `EMAIL_ENABLED=true`, complete **`POST /api/auth/verify-email`** before login; registration responses use `status: "email_verify"` until verified.
3. **Login** with `POST /api/auth/login` using `email` + `password`; `channel` is optional (`client_app` or `management_panel`) and defaults to `management_panel` when omitted. The JSON response contains **`access_token` only**; the **`refresh_token`** is set in a cookie (see env `REFRESH_COOKIE_SECURE`).
4. **Refresh** with `POST /api/auth/refresh` (cookie or `refresh_token` in JSON body). The presented refresh token is invalidated on success (rotation), and a new refresh cookie is returned.
5. **Logout** with `POST /api/auth/logout` (cookie or `refresh_token` in JSON body). The current refresh token is invalidated server-side and the refresh cookie is cleared.
6. If TOTP is enabled, login returns an **MFA ticket** JSON (unchanged shape); then call **`POST /api/auth/verify-mfa`** — on success you get the same cookie + JSON access token pattern as login.
7. **OAuth2 token endpoint** (`POST /api/oauth2/token` with `grant_type=refresh_token`): uses the same **refresh rotation** as `/api/auth/refresh`. Reusing the same refresh string after a successful exchange returns **`U0026` (Token blacklisted)**.
8. Call protected routes with:
   ```
   Authorization: Bearer <access_token>
   ```
   Protected routes in this mock expect the **`management_panel`** channel in the JWT (OIDC, TOTP, accounts, user profile, OAuth2 client CRUD).

When a user’s **password is changed** (including password reset), the server increments **`session_version`**. Previously issued access and refresh JWTs carry claim **`sv`**; if it is lower than the current version, validation fails with **`U0069` (Session revoked)** until the user signs in again.

### Available endpoints

#### Public
- `POST /api/auth/register/client` — public signup (client app)
- `POST /api/auth/register/management` — public signup (management; stricter rate limit)
- `POST /api/auth/login` — email + password (+ optional `channel`, default `management_panel`) (stricter rate limit)
- `POST /api/auth/refresh` — rotate refresh token (cookie or body `refresh_token`)
- `POST /api/auth/logout` — invalidate current refresh token and clear cookie
- `POST /api/auth/verify-mfa` — exchange MFA ticket for tokens (stricter rate limit)
- `POST /api/auth/verify-email` — verify email code
- `POST /api/auth/request-password-reset` — request reset code
- `POST /api/auth/reset-password` — reset password
- `GET /.well-known/openid-configuration` — OpenID Provider metadata
- `GET /.well-known/jwks.json` — JWKS

#### Protected (Bearer token + JWT must allow `management_panel`)
- `GET /api/users/{id}`, `PUT /api/users/{id}`
- `GET /api/oauth2/authorize`, `POST /api/oauth2/token`, `GET /api/oauth2/userinfo`
- `POST /api/oauth2/clients`, `GET /api/oauth2/clients/{id}`, `PUT /api/oauth2/clients/{id}`, `DELETE /api/oauth2/clients/{id}`
- `POST /api/totp/enable`, `POST /api/totp/verify`, `POST /api/totp/verify-backup`, `POST /api/totp/disable`
- `GET /api/accounts`, `GET /api/accounts/me`, `PUT /api/accounts`, `DELETE /api/accounts`

#### Admin (`root` or `admin` role; stricter rate limit)
- `GET /api/users` — list users
- `GET /api/oauth2/clients` — list OAuth2 clients (read-only listing here; client CRUD lives under protected routes above)
- `POST /api/admin/users/standalone` — create **standalone** user (no `admin`/`root` in payload)
- `POST /api/admin/users/{id}/roles`, `DELETE /api/admin/users/{id}/roles/{role}`, `GET /api/admin/users/{id}/roles` — roles for **standalone** users only
- `GET /api/admin/roles`, `POST /api/admin/roles`, `PUT /api/admin/roles/{name}`, `DELETE /api/admin/roles/{name}` — custom role catalog (system roles cannot be renamed/deleted)

#### Health
- `GET /health`, `GET /health/ready`, `GET /health/live`


### Error responses

Responses use JSON with `code` and `message` (and optional `details` for validation). HTTP status is chosen per handler (e.g. `400` for bad input or business rules, `401`/`403` for authentication/authorization).

All domain error codes emitted by this service are listed below. **`U0061`–`U0068`** are identity/RBAC policy errors (same situations often described elsewhere as “auth policy”); the Go symbols are `ErrAuth*` in `errors.go`. **`U0006` and `U0017` are not defined** in the current codebase.

#### Business / validation (`U0001`–`U0068`)

| Code | Typical `message` |
|------|-------------------|
| `U0001` | Invalid credentials |
| `U0002` | Invalid client |
| `U0003` | Invalid authorization code |
| `U0004` | Authorization code expired |
| `U0005` | Invalid PKCE |
| `U0007` | `{resource} not found` (e.g. User, Client, Account) |
| `U0008` | `{resource} is invalid` |
| `U0009` | `{resource} already exists` (e.g. User, Client) |
| `U0010` | Invalid scope |
| `U0011` | Invalid field |
| `U0012` | Path parameter not found |
| `U0013` | Invalid request body |
| `U0014` | Unauthorized |
| `U0018` | Forbidden |
| `U0019` | Invalid token |
| `U0020` | Varies (invalid duration / validation text from `ErrInvalidDuration`) |
| `U0021` | Token expired **or** Token issued in the future |
| `U0022` | Token not yet valid |
| `U0023` | Token has no roles |
| `U0024` | Token subject is required |
| `U0025` | Invalid claims |
| `U0026` | Token blacklisted |
| `U0069` | Session revoked (e.g. password changed; JWT `sv` stale) |
| `U0029` | Invalid signing method |
| `U0030` | Invalid signature |
| `U0031` | Invalid redirect URI |
| `U0032` | Invalid code challenge method |
| `U0033` | Invalid code challenge |
| `U0034` | Email not verified |
| `U0035` | Invalid verification code |
| `U0036` | Verification code expired |
| `U0037` | Invalid password change code |
| `U0038` | Password change code expired |
| `U0040` | missing necessary SMTP configuration |
| `U0041` | invalid email address |
| `U0042` | Token signature is invalid |
| `U0043` | Token malformed |
| `U0044` | Token has no roles |
| `U0045` | TOTP is not enabled for this user |
| `U0046` | TOTP is already enabled for this user |
| `U0047` | Invalid TOTP code |
| `U0051` | Invalid TOTP backup code |
| `U0052` | All TOTP backup codes have been used |
| `U0053` | TOTP verification required |
| `U0054` | Invalid MFA ticket |
| `U0055` | MFA ticket expired |
| `U0056` | MFA ticket already used |
| `U0057` | Invalid user ID |
| `U0061` | Invalid credentials (login / channel policy; `ErrAuthInvalidCredentials`) |
| `U0062` | Channel not allowed for this user (`ErrAuthForbiddenChannel`) |
| `U0063` | Role not found (`ErrAuthRoleNotFound`) |
| `U0064` | Role cannot be changed or removed (`ErrAuthRoleProtected`) |
| `U0065` | Role already assigned (`ErrAuthRoleAlreadyAssigned`) |
| `U0066` | Cannot remove required base role (`ErrAuthRoleRequiredMinimum`) |
| `U0067` | Administrator privileges required (`ErrAuthAdminRequired`) |
| `U0068` | Operation allowed only for standalone users (`ErrAuthUserNotStandalone`) |

#### Infrastructure (`U0015`, `U0016`, `U0027`, `U0028`, `U0039`, `U0048`–`U0050`, `U0058`–`U0060`)

| Code | Typical `message` |
|------|-------------------|
| `U0015` | Internal server error |
| `U0016` | Failed to generate token |
| `U0027` | Failed to generate token |
| `U0028` | Invalid key configuration |
| `U0039` | Failed to send email |
| `U0048` | Failed to generate TOTP secret |
| `U0049` | Failed to generate TOTP QR code |
| `U0050` | Failed to generate TOTP backup codes |
| `U0058` | Failed to create account |
| `U0059` | Failed to update account |
| `U0060` | Failed to delete account |

## Project Structure

```
.
├── cmd/
│   └── main.go                 # HTTP server entrypoint
├── internal/
│   ├── domain/                 # Entities, auth contracts, errors
│   ├── application/            # Auth, account, OAuth, OIDC, TOTP services
│   ├── infrastructure/       # JWT, email, config, in-memory repositories
│   └── interfaces/http/      # Chi router, handlers, middlewares
├── docs/                       # Swagger JSON (generated)
├── test/integration/         # Integration tests
└── bin/                        # Built binary (`make build`)
```


## Development

### Testing

```bash
# Run all tests
make test

# Run tests with coverage
go test -cover ./...

# Run specific test
go test -run TestName ./...
```

### Code Quality

```bash
# Run linter
make lint

# Run all checks (lint + test)
make check
```

## License

MIT 