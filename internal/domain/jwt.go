package domain

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/manorfm/auth-mock/internal/infrastructure/config"
	"github.com/oklog/ulid/v2"
)

// JWT defines the interface for JWT operations
type JWT struct {
	privateKey   *rsa.PrivateKey
	publicKey    *rsa.PublicKey
	config       *config.Config
	keyID        string
	lastRotation time.Time
	blacklist    map[string]time.Time // Token ID -> Expiration time
	mu           sync.RWMutex
}

// RefreshTokenRequest represents the request to refresh an access token
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// TokenPair represents a pair of access and refresh tokens
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type Claims struct {
	*jwt.RegisteredClaims
	Roles []string `json:"roles"`
}

// Valid implements the jwt.Claims interface
func (c *Claims) Valid() error {
	// Validate standard claims
	if c.ExpiresAt != nil && c.ExpiresAt.Before(time.Now()) {
		return ErrTokenExpired
	}

	if c.IssuedAt != nil && c.IssuedAt.After(time.Now()) {
		return ErrTokenIssuedInFuture
	}

	if c.NotBefore != nil && c.NotBefore.After(time.Now()) {
		return ErrTokenNotYetValid
	}

	if len(c.Roles) == 0 {
		return ErrTokenNoRoles
	}

	if c.Subject == "" {
		return ErrTokenSubjectRequired
	}

	return nil
}

// LoginResponse represents the response for a login request
type LoginResponse struct {
	User  *User      `json:"user"`
	Token *TokenPair `json:"token"`
}

// GetPrivateKey returns the private key
func (j *JWT) GetPrivateKey() *rsa.PrivateKey {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.privateKey
}

// GetPublicKey returns the public key
func (j *JWT) GetPublicKey() *rsa.PublicKey {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.publicKey
}

// GetKeyID returns the current key ID
func (j *JWT) GetKeyID() string {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.keyID
}

// GetLastRotation returns the last key rotation time
func (j *JWT) GetLastRotation() time.Time {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.lastRotation
}

// RotateKey generates a new key pair and updates the key ID
func (j *JWT) RotateKey() error {
	j.mu.Lock()
	defer j.mu.Unlock()

	privateKey, err := rsa.GenerateKey(rand.Reader, j.config.RSAKeySize)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	j.privateKey = privateKey
	j.publicKey = &privateKey.PublicKey
	j.keyID = generateKeyID(privateKey)
	j.lastRotation = time.Now()

	return nil
}

// BlacklistToken adds a token to the blacklist
func (j *JWT) BlacklistToken(tokenID string, expiresAt time.Time) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.blacklist[tokenID] = expiresAt
}

// IsTokenBlacklisted checks if a token is blacklisted
func (j *JWT) IsTokenBlacklisted(tokenID string) bool {
	j.mu.RLock()
	defer j.mu.RUnlock()

	if exp, ok := j.blacklist[tokenID]; ok {
		if time.Now().Before(exp) {
			return true
		}
		// Clean up expired blacklist entries
		delete(j.blacklist, tokenID)
	}
	return false
}

// CleanupBlacklist removes expired tokens from the blacklist
func (j *JWT) CleanupBlacklist() {
	j.mu.Lock()
	defer j.mu.Unlock()

	now := time.Now()
	for tokenID, exp := range j.blacklist {
		if now.After(exp) {
			delete(j.blacklist, tokenID)
		}
	}
}

// generateKeyID generates a unique key ID from the private key
func generateKeyID(key *rsa.PrivateKey) string {
	// Use the public key components to generate a unique ID
	modulus := key.N.Bytes()
	exponent := []byte{byte(key.E)}

	// Combine modulus and exponent
	data := append(modulus, exponent...)

	// Generate SHA-256 hash
	hash := sha256.Sum256(data)

	// Encode as base64url without padding
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// This allows for easier mocking in tests
// Only the methods needed by the middleware are included
// JWTService defines the interface for JWT operations
type JWTService interface {
	ValidateToken(token string) (*Claims, error)
	GetJWKS(ctx context.Context) (map[string]interface{}, error)
	GenerateTokenPair(userID ulid.ULID, roles []string) (*TokenPair, error)
	GetPublicKey() *rsa.PublicKey
	RotateKeys() error
	BlacklistToken(tokenID string, expiresAt time.Time) error
	IsTokenBlacklisted(tokenID string) bool
}

// JWTStrategy defines the interface for JWT operations
type JWTStrategy interface {
	// Sign signs a JWT token with the strategy's private key
	Sign(claims *Claims) (string, error)
	// Verify verifies a JWT token
	Verify(tokenString string) (*Claims, error)
	// GetPublicKey returns the public key for token validation
	GetPublicKey() *rsa.PublicKey
	// GetKeyID returns the current key ID
	GetKeyID() string
	// RotateKey rotates the key pair
	RotateKey() error
	// GetLastRotation returns the last key rotation time
	GetLastRotation() time.Time
}
