package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/infrastructure/config"
	"go.uber.org/zap"
)

// localStrategy implements JWTStrategy using a locally generated RSA key pair
type localStrategy struct {
	privateKey   *rsa.PrivateKey
	publicKey    *rsa.PublicKey
	config       *config.Config
	logger       *zap.Logger
	keyID        string
	lastRotation time.Time
	mu           sync.RWMutex
}

// NewLocalStrategy creates a new local strategy for JWT signing
func NewLocalStrategy(config *config.Config, logger *zap.Logger) (domain.JWTStrategy, error) {
	if config == nil {
		return nil, domain.ErrInvalidKeyConfig
	}

	strategy := &localStrategy{
		config:       config,
		logger:       logger,
		lastRotation: time.Now(),
	}

	// Always generate a new key pair (no loading from files)
	if err := strategy.generateKeyPair(); err != nil {
		return nil, domain.ErrInvalidKeyConfig
	}

	// Generate initial key ID
	strategy.keyID = generateKeyID(strategy.privateKey)

	return strategy, nil
}

// generateKeyPair generates a new RSA key pair
func (l *localStrategy) generateKeyPair() error {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, l.config.RSAKeySize)
	if err != nil {
		l.logger.Error("Failed to generate private key", zap.Error(err))
		return domain.ErrInvalidKeyConfig
	}

	l.privateKey = privateKey
	l.publicKey = &privateKey.PublicKey
	return nil
}

// Sign signs a JWT token using the local private key
func (l *localStrategy) Sign(claims *domain.Claims) (string, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	mapClaims := jwt.MapClaims{
		"sub":   claims.Subject,
		"exp":   claims.ExpiresAt.Unix(),
		"iat":   claims.IssuedAt.Unix(),
		"jti":   claims.ID,
		"roles": claims.Roles,
		"name":  claims.Name,
	}

	// Adiciona os claims extras (dinâmicos)
	for k, v := range claims.Extra {
		mapClaims[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, mapClaims)
	token.Header["kid"] = l.keyID

	return token.SignedString(l.privateKey)
}

// GetPublicKey returns the public key
func (l *localStrategy) GetPublicKey() *rsa.PublicKey {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.publicKey
}

// GetKeyID returns the current key ID
func (l *localStrategy) GetKeyID() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.keyID
}

// RotateKey generates a new key pair
func (l *localStrategy) RotateKey() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Generate new key pair
	if err := l.generateKeyPair(); err != nil {
		return domain.ErrInvalidKeyConfig
	}

	// Update key ID and rotation time
	l.keyID = generateKeyID(l.privateKey)
	l.lastRotation = time.Now()

	return nil
}

// GetLastRotation returns the last key rotation time
func (l *localStrategy) GetLastRotation() time.Time {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.lastRotation
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

// Verify verifies a JWT token using the local private key
func (l *localStrategy) Verify(tokenString string) (*domain.Claims, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.privateKey == nil {
		return nil, domain.ErrInvalidKeyConfig
	}

	// Parse and validate token
	token, err := jwt.ParseWithClaims(tokenString, &domain.Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, domain.ErrInvalidSigningMethod
		}
		return &l.privateKey.PublicKey, nil
	})

	if err != nil {
		l.logger.Error("Failed to parse token", zap.Error(err))
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, domain.ErrTokenExpired
		}
		if errors.Is(err, jwt.ErrTokenMalformed) {
			return nil, domain.ErrTokenMalformed
		}
		if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return nil, domain.ErrTokenSignatureInvalid
		}
		return nil, domain.ErrInvalidToken
	}

	// Check if token is valid
	if !token.Valid {
		l.logger.Error("Invalid token: token validation failed")
		return nil, domain.ErrInvalidToken
	}

	// Get claims
	claims, ok := token.Claims.(*domain.Claims)
	if !ok {
		l.logger.Error("Invalid claims type")
		return nil, domain.ErrInvalidClaims
	}

	return claims, nil
}
