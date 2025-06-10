# Auth Mock

[![Go Version](https://img.shields.io/badge/Go-1.23-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-0.1.0-blue.svg)](https://github.com/manorfm/auth-mock/releases)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](https://github.com/manorfm/auth-mock/actions)
[![Coverage](https://img.shields.io/badge/Coverage-80%25-brightgreen.svg)](https://github.com/manorfm/auth-mock/actions)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://hub.docker.com/r/manorfm/auth-mock)

A mock authentication service designed for testing and development purposes. This service provides a complete authentication system that can be used with testcontainers to validate JWT token validation, public key retrieval, and other authentication flows.

## Features

- In-memory user storage for testing
- JWT-based authentication with key rotation
- Role-based access control (RBAC)
- OAuth2/OpenID Connect support
- Token blacklisting
- Rate limiting
- Refresh token mechanism
- JWKS endpoint for public key distribution
- Email verification system
- Password reset functionality
- OpenTelemetry integration for observability
- Swagger/OpenAPI documentation
- Header-based API versioning
- Comprehensive error handling
- Configurable JWT strategies
- Multi-factor authentication (MFA) with TOTP
- Backup codes for MFA recovery
- MFA ticket-based verification flow
- Default user configuration for testing

## Architecture

The project follows a hexagonal architecture with the following layers:

- `domain`: Core business entities, interfaces, and domain-specific errors
- `application`: Use cases and business logic
- `infrastructure`: JWT, and other external service implementations
- `interfaces/http`: HTTP handlers, middlewares, and OpenAPI/Swagger documentation

### API Versioning

The service uses header-based versioning through the `Accept` header:

```http
Accept: application/vnd.ipede.v1+json
```

This approach:
- Keeps URLs clean and stable
- Allows for multiple API versions to coexist
- Provides better separation of concerns
- Follows REST best practices

### Error Handling

The service implements a comprehensive error handling system with:

- Domain-specific error types (`BusinessError` and `InfraError`)
- Standardized error codes (U0001-U0044)
- Detailed error messages and codes
- Proper error wrapping and context
- HTTP status code mapping

Example error response:
```json
{
  "code": "U0001",
  "message": "Invalid credentials"
}
```

### JWT Strategy

The service implements a composite JWT strategy that:

- Provides automatic fallback mechanisms
- Implements key rotation
- Handles token verification with proper error handling
- Supports JWKS for public key distribution

## Getting Started

### Prerequisites

- Go 1.23 or later
- PostgreSQL
- Make
- Docker (optional)

### Environment Variables

Create a `.env` file in the root directory with the following variables:

```env
# JWT Configuration
JWT_ACCESS_DURATION=15m
JWT_REFRESH_DURATION=168h  # 7 days
RSA_KEY_SIZE=2048
JWKS_CACHE_DURATION=1h

# Server Configuration
SERVER_PORT=8080
SERVER_HOST=localhost
SERVER_URL=http://localhost:8080

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
```

### Default User Configuration

The service automatically creates a default user for testing purposes. This is particularly useful when using testcontainers to validate authentication flows. The default user will be created with the following characteristics:

1. Email and password from environment variables:
   - `DEFAULT_USER_EMAIL` (defaults to empty string)
   - `DEFAULT_USER_PASSWORD` (defaults to empty string)

2. Roles from environment variable:
   - `DEFAULT_USER_ROLES` (defaults to "admin" if not specified)
   - Multiple roles can be specified as a comma-separated list (e.g., "admin,user,manager")

3. The default user will be created with:
   - Email verification already completed
   - All specified roles assigned
   - A unique ULID as the user ID

Example usage with testcontainers:
```go
func TestAuthentication(t *testing.T) {
    // Start the auth-mock service with testcontainers
    container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
        ContainerRequest: testcontainers.ContainerRequest{
            Image: "manorfm/auth-mock:latest",
            Env: map[string]string{
                "DEFAULT_USER_EMAIL": "test@example.com",
                "DEFAULT_USER_PASSWORD": "test123",
                "DEFAULT_USER_ROLES": "admin,user",
            },
            ExposedPorts: []string{"8080/tcp"},
        },
        Started: true,
    })
    // ... rest of your test
}
```

### Running the Application

```bash
# Install dependencies
make deps

# Run migrations
make migrate-up

# Start the application
make run

# Run tests
make test

# Run linter
make lint

# Generate Swagger documentation
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

### Authentication

The API uses JWT (JSON Web Tokens) for authentication with the following features:

- Access and refresh token pairs
- Token blacklisting for revocation
- JWKS endpoint for public key distribution
- Rate limiting to prevent abuse

To access protected endpoints:

1. Register a new user using the `/api/users/register` endpoint
2. Login using the `/api/auth/login` endpoint to get your access token
3. Include the token in the `Authorization` header of subsequent requests:
   ```
   Authorization: Bearer <your-access-token>
   ```

### OAuth2/OpenID Connect

The service implements OAuth2 and OpenID Connect protocols with the following endpoints:

- `/oauth2/authorize` - Authorization endpoint
- `/oauth2/token` - Token endpoint
- `/oauth2/userinfo` - UserInfo endpoint
- `/.well-known/openid-configuration` - OpenID Provider Configuration
- `/.well-known/jwks.json` - JSON Web Key Set

### Available Endpoints

#### Public Endpoints
- `POST /api/users/register` - Register a new user
- `POST /api/auth/login` - Login and get access token
- `POST /api/auth/verify-email` - Verify email address
- `POST /api/auth/request-password-reset` - Request password reset
- `POST /api/auth/reset-password` - Reset password
- `POST /api/auth/verify-mfa` - Verify MFA code
- `POST /api/oauth2/token` - OAuth2 token endpoint
- `GET /.well-known/openid-configuration` - OpenID Provider Configuration
- `GET /.well-known/jwks.json` - JSON Web Key Set

#### Protected Endpoints (Requires Authentication)
- `GET /api/users/{id}` - Get user by ID
- `PUT /api/users/{id}` - Update user by ID
- `GET /api/oauth2/authorize` - OAuth2 authorization endpoint
- `POST /api/oauth2/token` - OAuth2 token endpoint
- `GET /api/oauth2/userinfo` - Get user information
- `POST /api/totp/enable` - Enable TOTP for user
- `POST /api/totp/verify` - Verify TOTP code
- `POST /api/totp/verify-backup` - Verify TOTP backup code
- `POST /api/totp/disable` - Disable TOTP for user

#### Admin Endpoints (Requires Admin Role)
- `GET /api/users` - List all users
- `GET /api/oauth2/clients` - List OAuth2 clients
- `POST /api/oauth2/clients` - Create OAuth2 client
- `GET /api/oauth2/clients/{id}` - Get OAuth2 client
- `PUT /api/oauth2/clients/{id}` - Update OAuth2 client
- `DELETE /api/oauth2/clients/{id}` - Delete OAuth2 client

### Error Responses

The API uses standard HTTP status codes and returns error details in the following format:

```json
{
  "code": "ERROR_CODE",
  "message": "Error message"
}
```

Common error codes:
- `U0001` - Invalid credentials
- `U0002` - Invalid client
- `U0003` - Invalid authorization code
- `U0004` - Authorization code expired
- `U0005` - Invalid PKCE
- `U0006` - Invalid user ID
- `U0007` - Resource not found
- `U0008` - Invalid resource
- `U0009` - Resource already exists
- `U0010` - Invalid scope
- `U0011` - Invalid field
- `U0012` - Path parameter not found
- `U0013` - Invalid request body
- `U0014` - Unauthorized
- `U0015` - Internal server error
- `U0016` - Failed to generate token
- `U0018` - Forbidden
- `U0019` - Invalid token
- `U0020` - Invalid duration
- `U0021` - Token expired
- `U0022` - Token not yet valid
- `U0023` - Token has no roles
- `U0024` - Token subject required
- `U0025` - Invalid claims
- `U0026` - Token blacklisted
- `U0027` - Token generation failed
- `U0028` - Invalid key configuration
- `U0029` - Invalid signing method
- `U0030` - Invalid signature
- `U0031` - Invalid redirect URI
- `U0032` - Invalid code challenge method
- `U0033` - Invalid code challenge
- `U0034` - Email not verified
- `U0035` - Invalid verification code
- `U0036` - Verification code expired
- `U0037` - Invalid password change code
- `U0038` - Password change code expired
- `U0039` - Email send failed
- `U0040` - Missing SMTP configuration
- `U0041` - Invalid email
- `U0042` - Token signature invalid
- `U0043` - Token malformed
- `U0044` - Token has no roles
- `U0045` - TOTP not enabled
- `U0046` - TOTP already enabled
- `U0047` - Invalid TOTP code
- `U0048` - TOTP secret generation failed
- `U0049` - TOTP QR generation failed
- `U0050` - TOTP backup codes generation failed
- `U0051` - Invalid TOTP backup code
- `U0052` - TOTP backup codes exhausted
- `U0053` - TOTP verification required
- `U0054` - Invalid MFA ticket
- `U0055` - MFA ticket expired
- `U0056` - MFA ticket already used
- `U0057` - Invalid user ID

## Project Structure

```
.
├── cmd/                    # Application entry points
│   ├── main.go            # Main application
│   └── migrate/           # Migration tool
├── internal/              # Private application code
│   ├── domain/           # Domain entities and interfaces
│   ├── application/      # Use cases and business logic
│   ├── infrastructure/   # External services implementation
│   │   ├── jwt/         # JWT service implementation
│   │   ├── postgres/    # PostgreSQL implementation
│   │   ├── email/       # Email service implementation
│   └── interfaces/       # HTTP handlers and middlewares
├── docs/                # Documentation and Swagger files
└── bin/                 # Compiled binaries
```

## Development

```bash
# Run all pending migrations
make migrate-up

# Rollback the last migration
make migrate-down

# Reset migrations (rollback all and run up)
make migrate-reset

# Force migration to specific version
make migrate-force VERSION=<version>
```

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

## Observability

The service includes OpenTelemetry integration for:

- Distributed tracing
- Metrics collection
- Structured logging
- Performance monitoring

## Security Features

- Rate limiting
- Input validation
- Secure password hashing
- Email verification
- Token blacklisting
- Role-based access control
- Header-based API versioning
- Comprehensive error handling
- Configurable JWT strategies
- Multi-factor authentication with TOTP
- Backup codes for MFA recovery
- MFA ticket-based verification flow
- Secure TOTP secret storage
- TOTP backup codes management

## License

MIT 