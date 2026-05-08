# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Removed

- **Redis-backed revocation**: `RedisTokenRevocationStore`, env vars `TOKEN_REVOCATION_REDIS_*`, and the `redis` service from `docker-compose.yml`. Revocation stays **memory-only** by design for this mock.

### Changed

- **Go 1.25** (`go.mod`, README prerequisites); Docker build image **`golang:1.25-alpine`**, runtime **`alpine:3.21`**. Direct dependencies updated where compatible (e.g. **chi v5.2.5**, **jwt/v5 v5.3.1**, **validator/v10**, **zap**, **golang.org/x/crypto** and related `x/*`, **testify**, **swag**).
- **OAuth2 / OIDC** (`POST {API_BASE_PATH}/oauth2/token`, `grant_type=refresh_token`): refresh tokens are now **rotated** — the refresh JWT presented in the request is blacklisted after a successful exchange, matching `POST {API_BASE_PATH}/auth/refresh`. **Clients that reused the same refresh string for multiple exchanges will break**; each successful response returns a new refresh token that must be stored and used on the next refresh.
- **Token endpoint errors**: when a refresh token was already consumed or revoked, the handler returns **`U0026` Token blacklisted** (HTTP `400`) instead of an internal error.

### Added

- **`POST {API_BASE_PATH}/auth/logout`**: invalidates the current refresh JWT (cookie or JSON body `refresh_token`) via server-side blacklist and clears the refresh cookie (`204 No Content` on success).
- **Session invalidation on password change**: `users.session_version` increments on password update; JWTs include claim **`sv`**. When `sv` is behind the stored version, `ValidateToken` returns **`U0069` Session revoked** (access and refresh).

### Notes

- JWT **jti blacklist** for refresh rotation and logout is **in-memory** inside the process only (no optional Redis / external revocation backend in this repository).
