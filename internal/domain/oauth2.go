package domain

import (
	"context"
	"time"
)

// OAuth2Client represents a registered OAuth2 client
type OAuth2Client struct {
	ID           string    `json:"id"`
	Secret       string    `json:"secret"`
	RedirectURIs []string  `json:"redirect_uris"`
	GrantTypes   []string  `json:"grant_types"`
	Scopes       []string  `json:"scopes"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// AuthorizationCode represents an OAuth2 authorization code
type AuthorizationCode struct {
	Code                string    `json:"code"`
	ClientID            string    `json:"client_id"`
	UserID              string    `json:"user_id"`
	Scopes              []string  `json:"scopes"`
	ExpiresAt           time.Time `json:"expires_at"`
	CreatedAt           time.Time `json:"created_at"`
	CodeVerifier        string    `json:"code_verifier"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
}

// OAuth2Service defines the interface for OAuth2 operations
type OAuth2Service interface {
	// ValidateClient validates if a client exists and if the redirect URI is allowed
	ValidateClient(ctx context.Context, clientID, redirectURI string) (*OAuth2Client, error)

	// GenerateAuthorizationCode generates a new authorization code for the client and user
	GenerateAuthorizationCode(ctx context.Context, clientID, userID string, scopes []string, codeChallenge, codeChallengeMethod string) (string, error)

	// ValidateAuthorizationCode validates an authorization code and returns the associated data
	ValidateAuthorizationCode(ctx context.Context, code string) (*OAuth2Client, string, []string, error)
}

// OAuth2Repository defines the interface for OAuth2 data access
type OAuth2Repository interface {
	// CreateClient creates a new OAuth2 client
	CreateClient(ctx context.Context, client *OAuth2Client) error

	// FindClientByID finds an OAuth2 client by ID
	FindClientByID(ctx context.Context, id string) (*OAuth2Client, error)

	// UpdateClient updates an OAuth2 client
	UpdateClient(ctx context.Context, client *OAuth2Client) error

	// DeleteClient deletes an OAuth2 client
	DeleteClient(ctx context.Context, id string) error

	// ListClients lists all OAuth2 clients
	ListClients(ctx context.Context) ([]*OAuth2Client, error)

	// CreateAuthorizationCode creates a new authorization code
	CreateAuthorizationCode(ctx context.Context, code *AuthorizationCode) error

	// GetAuthorizationCode gets an authorization code by code
	GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error)

	// DeleteAuthorizationCode deletes an authorization code
	DeleteAuthorizationCode(ctx context.Context, code string) error
}
