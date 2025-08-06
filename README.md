# Auth Mock

[![Go Version](https://img.shields.io/badge/Go-1.23-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-0.1.0-blue.svg)](https://github.com/manorfm/auth-mock/releases)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](https://github.com/manorfm/auth-mock/actions)
[![Coverage](https://img.shields.io/badge/Coverage-80%25-brightgreen.svg)](https://github.com/manorfm/auth-mock/actions)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://hub.docker.com/r/manorfm/auth-mock)

A comprehensive mock authentication service designed for testing and development purposes. This service provides a complete authentication system with in-memory JWT key management, role-based access control, and OAuth2/OpenID Connect support.

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
- Role-based access control (RBAC)
- OAuth2/OpenID Connect protocol support
- Multi-factor authentication (MFA) with TOTP
- Backup codes for MFA recovery
- MFA ticket-based verification flow
- Email verification system
- Password reset functionality
- Rate limiting with configurable thresholds
- Account management system with automatic account creation

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
- SMTP settings for email delivery
- Default user configuration
- Custom claims fields
- TOTP settings (issuer, algorithm, digits, period)
- Backup codes configuration

### Observability
- OpenTelemetry integration
- Structured logging with Zap
- Distributed tracing
- Metrics collection
- Performance monitoring

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

### Error Handling

The service implements a comprehensive error handling system with:

- Domain-specific error types (`BusinessError` and `InfraError`)
- Standardized error codes (U0001-U0057)
- Detailed error messages and codes
- Proper error wrapping and context
- HTTP status code mapping

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
JWT_ACCESS_TOKEN_DURATION=15m
JWT_REFRESH_TOKEN_DURATION=168h  # 7 days
RSA_KEY_SIZE=2048
JWKS_CACHE_DURATION=1h

# Server Configuration
PORT=8080
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

# Custom Claims (optional)
CUSTOM_CLAIMS_FIELDS={"custom_field":"value"}
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

### Authentication Flow

1. Register a new user using the `/api/register` endpoint
2. Login using the `/api/auth/login` endpoint to get your access token
3. Include the token in the `Authorization` header of subsequent requests:
   ```
   Authorization: Bearer <your-access-token>
   ```

### Available Endpoints

#### Public Endpoints
- `POST /api/register` - Register a new user
- `POST /api/auth/login` - Login and get access token
- `POST /api/auth/verify-email` - Verify email address
- `POST /api/auth/request-password-reset` - Request password reset
- `POST /api/auth/reset-password` - Reset password
- `POST /api/auth/verify-mfa` - Verify MFA code
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
- `GET /api/accounts` - Get current user's account
- `GET /api/accounts/me` - Get current user's account with user data and MFA status
- `PUT /api/accounts` - Update current user's account status
- `DELETE /api/accounts` - Delete current user's account

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
- `U0058` - Failed to create account
- `U0059` - Failed to update account
- `U0060` - Failed to delete account

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