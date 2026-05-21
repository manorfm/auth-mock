package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/interfaces/http/errors"
	"go.uber.org/zap"
)

type AuthMiddleware struct {
	jwt    domain.JWTService
	logger *zap.Logger
}

func NewAuthMiddleware(jwt domain.JWTService, logger *zap.Logger) *AuthMiddleware {
	return &AuthMiddleware{jwt: jwt, logger: logger}
}

func (m *AuthMiddleware) Authenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := m.extractToken(r)
		if token == "" {
			errors.RespondWithError(w, domain.ErrUnauthorized)
			return
		}

		claims, err := m.jwt.ValidateToken(token)
		if err != nil {
			m.logger.Error("Failed to validate token", zap.Error(err))
			errors.RespondWithError(w, err.(domain.Error))
			return
		}

		m.logger.Debug("Token validated successfully",
			zap.String("subject", claims.Subject),
			zap.Strings("roles", claims.Roles))

		ctx := context.WithValue(r.Context(), domain.ContextKeySubject, claims.Subject)
		ctx = context.WithValue(ctx, domain.ContextKeyRoles, claims.Roles)
		ctx = context.WithValue(ctx, domain.ContextKeyChannels, claims.Channels)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *AuthMiddleware) RequireRole(role string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			roles, ok := domain.GetRoles(r.Context())
			if !ok {
				errors.RespondWithError(w, domain.ErrAuthAdminRequired)
				return
			}

			for _, userRole := range roles {
				if userRole == role {
					next.ServeHTTP(w, r)
					return
				}
			}

			errors.RespondWithError(w, domain.ErrAuthAdminRequired)
		})
	}
}

func (m *AuthMiddleware) RequireAnyRole(roles ...string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userRoles, ok := domain.GetRoles(r.Context())
			if !ok {
				errors.RespondWithError(w, domain.ErrAuthAdminRequired)
				return
			}
			for _, role := range roles {
				for _, userRole := range userRoles {
					if role == userRole || userRole == domain.RoleAdmin || userRole == domain.RoleRoot || strings.HasPrefix(userRole, "platform.") {
						next.ServeHTTP(w, r)
						return
					}
				}
			}
			errors.RespondWithError(w, domain.ErrAuthAdminRequired)
		})
	}
}

func (m *AuthMiddleware) RequireChannel(channel string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			channels, ok := domain.GetChannels(r.Context())
			if !ok {
				errors.RespondWithError(w, domain.ErrAuthForbiddenChannel)
				return
			}
			for _, allowed := range channels {
				if allowed == channel {
					next.ServeHTTP(w, r)
					return
				}
			}
			errors.RespondWithError(w, domain.ErrAuthForbiddenChannel)
		})
	}
}

func (m *AuthMiddleware) extractToken(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	if len(strings.Split(bearToken, " ")) == 2 {
		return strings.Split(bearToken, " ")[1]
	}
	return ""
}
