package domain

import (
	"context"
)

type UserInfo struct {
	Sub           string   `json:"sub"`
	Name          string   `json:"name"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	AMR           []string `json:"amr"`
}

// OIDCService defines the interface for OpenID Connect operations
type OIDCService interface {
	// GetUserInfo retrieves user information for the given user ID
	GetUserInfo(ctx context.Context, userID string) (*UserInfo, error)

	// GetOpenIDConfiguration retrieves the OpenID Connect configuration
	GetOpenIDConfiguration(ctx context.Context) (map[string]interface{}, error)

	// ExchangeCode exchanges an authorization code for tokens
	ExchangeCode(ctx context.Context, code string, codeVerifier string) (*TokenPair, error)

	// RefreshToken refreshes an access token using a refresh token
	RefreshToken(ctx context.Context, refreshToken string) (*TokenPair, error)

	// Authorize handles the authorization request and returns an authorization code
	Authorize(ctx context.Context, clientID, redirectURI, state, scope string) (string, error)
}
