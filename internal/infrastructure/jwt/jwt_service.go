package jwt

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/infrastructure/config"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
)

type jwtService struct {
	strategy   domain.JWTStrategy
	logger     *zap.Logger
	config     *config.Config
	mu         sync.RWMutex
	cache      *jwksCache
	revocation domain.TokenRevocationStore
	sessionSrc domain.SessionVersionSource
}

type jwksCache struct {
	keys     map[string]interface{}
	lastSync time.Time
	mu       sync.RWMutex
}

func newJWKSCache() *jwksCache {
	return &jwksCache{
		keys:     make(map[string]interface{}),
		lastSync: time.Time{},
	}
}

func NewJWTService(strategy domain.JWTStrategy, config *config.Config, logger *zap.Logger, sessionSrc domain.SessionVersionSource) (domain.JWTService, error) {
	revocation := NewMemoryTokenRevocationStore(logger)
	return NewJWTServiceWithRevocationAndSession(strategy, config, logger, revocation, sessionSrc), nil
}

// NewJWTServiceWithRevocation wires a custom revocation backend (tests may inject a mock; production uses memory via NewJWTService).
func NewJWTServiceWithRevocation(strategy domain.JWTStrategy, config *config.Config, logger *zap.Logger, revocation domain.TokenRevocationStore) domain.JWTService {
	return NewJWTServiceWithRevocationAndSession(strategy, config, logger, revocation, nil)
}

// NewJWTServiceWithRevocationAndSession allows tests to supply revocation and optional session-version source.
func NewJWTServiceWithRevocationAndSession(strategy domain.JWTStrategy, config *config.Config, logger *zap.Logger, revocation domain.TokenRevocationStore, sessionSrc domain.SessionVersionSource) domain.JWTService {
	if revocation == nil {
		revocation = NewMemoryTokenRevocationStore(logger)
	}
	return &jwtService{
		strategy:   strategy,
		logger:     logger,
		config:     config,
		cache:      newJWKSCache(),
		revocation: revocation,
		sessionSrc: sessionSrc,
	}
}

// ValidateToken validates a JWT token and returns the claims
func (j *jwtService) ValidateToken(tokenString string) (*domain.Claims, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()

	// Use strategy to verify token
	claims, err := j.strategy.Verify(tokenString)
	if err != nil {
		j.logger.Error("Failed to verify token",
			zap.Error(err),
			zap.String("error_type", fmt.Sprintf("%T", err)))
		return nil, err
	}

	// Validate claims
	if err := claims.Valid(); err != nil {
		j.logger.Error("Invalid claims",
			zap.Error(err),
			zap.String("token_id", claims.ID),
			zap.String("subject", claims.Subject))
		if errors.Is(err, domain.ErrTokenExpired) {
			j.logger.Warn("Token expired",
				zap.Error(err),
				zap.String("token_id", claims.ID))
			return nil, domain.ErrTokenExpired
		}
		return nil, domain.ErrInvalidClaims
	}

	// Additional validation
	if claims.Subject == "" {
		j.logger.Error("Missing subject in token",
			zap.String("token_id", claims.ID))
		return nil, domain.ErrInvalidClaims
	}

	revoked, err := j.revocation.IsRevoked(context.Background(), claims.ID)
	if err != nil {
		j.logger.Error("Failed to check token revocation",
			zap.Error(err),
			zap.String("token_id", claims.ID))
		return nil, domain.ErrInternal
	}
	if revoked {
		j.logger.Warn("Token is blacklisted", zap.String("token_id", claims.ID))
		return nil, domain.ErrTokenBlacklisted
	}

	if j.sessionSrc != nil {
		userID, err := ulid.Parse(claims.Subject)
		if err != nil {
			j.logger.Error("Invalid subject for session version", zap.String("subject", claims.Subject))
			return nil, domain.ErrInvalidClaims
		}
		current, err := j.sessionSrc.GetSessionVersion(context.Background(), userID)
		if err != nil {
			j.logger.Error("Session version lookup failed", zap.Error(err))
			return nil, domain.ErrInternal
		}
		if current < 1 {
			current = 1
		}
		tokSV := claims.SessionVersion
		if tokSV < 1 {
			tokSV = 0
		}
		if tokSV < current {
			j.logger.Warn("Token session version stale",
				zap.String("token_id", claims.ID),
				zap.Int64("token_sv", tokSV),
				zap.Int64("current_sv", current))
			return nil, domain.ErrSessionRevoked
		}
	}

	return claims, nil
}

func (j *jwtService) GetJWKS(ctx context.Context) (map[string]interface{}, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()

	// Check cache first
	j.cache.mu.RLock()
	if !j.cache.lastSync.IsZero() && time.Since(j.cache.lastSync) < j.config.JWKSCacheDuration {
		keys := j.cache.keys
		j.cache.mu.RUnlock()
		return keys, nil
	}
	j.cache.mu.RUnlock()

	// Cache miss or expired, generate new JWKS
	publicKey := j.strategy.GetPublicKey()
	if publicKey == nil {
		j.logger.Error("Failed to get public key")
		return nil, domain.ErrInternal
	}

	jwk, err := convertToJWK(publicKey, j.strategy.GetKeyID())
	if err != nil {
		j.logger.Error("Failed to convert public key to JWK", zap.Error(err))
		return nil, domain.ErrInternal
	}

	keys := map[string]interface{}{
		"keys": []map[string]interface{}{jwk},
	}

	// Update cache
	j.cache.mu.Lock()
	j.cache.keys = keys
	j.cache.lastSync = time.Now()
	j.cache.mu.Unlock()

	return keys, nil
}

// GenerateTokenPair generates a new pair of access and refresh tokens
func (j *jwtService) GenerateTokenPair(ctx context.Context, user *domain.User) (*domain.TokenPair, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()

	if len(user.Roles) == 0 {
		return nil, domain.ErrTokenHasNoRoles
	}

	extraClaims, err := j.config.ParseCustomClaims()
	if err != nil {
		j.logger.Warn("Invalid extra claims format", zap.Error(err))
	}

	sv := user.SessionVersion
	if sv < 1 {
		sv = 1
	}

	// Generate access token
	accessTokenID := ulid.Make().String()
	accessClaims := domain.Claims{
		Roles:          user.Roles,
		Name:           user.Name,
		UserType:       user.UserType,
		Channels:       user.Channels,
		SessionVersion: sv,
		RegisteredClaims: &jwt.RegisteredClaims{
			Subject:   user.ID.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.config.JWTAccessDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        accessTokenID,
		},
		Extra: extraClaims,
	}

	accessToken, err := j.strategy.Sign(&accessClaims)
	if err != nil {
		j.logger.Error("Failed to sign access token",
			zap.Error(err),
			zap.String("token_id", accessTokenID),
			zap.String("user_id", user.ID.String()))
		return nil, domain.ErrTokenGeneration
	}

	// Generate refresh token
	refreshTokenID := ulid.Make().String()
	refreshClaims := domain.Claims{
		Roles:          user.Roles,
		Name:           user.Name,
		UserType:       user.UserType,
		Channels:       user.Channels,
		SessionVersion: sv,
		RegisteredClaims: &jwt.RegisteredClaims{
			Subject:   user.ID.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.config.JWTRefreshDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        refreshTokenID,
		},
	}

	refreshToken, err := j.strategy.Sign(&refreshClaims)
	if err != nil {
		j.logger.Error("Failed to sign refresh token",
			zap.Error(err),
			zap.String("token_id", refreshTokenID),
			zap.String("user_id", user.ID.String()))
		return nil, domain.ErrTokenGeneration
	}

	j.logger.Debug("Generated token pair",
		zap.String("access_token_id", accessTokenID),
		zap.String("refresh_token_id", refreshTokenID),
		zap.String("user_id", user.ID.String()),
		zap.String("key_id", j.strategy.GetKeyID()))

	return &domain.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (j *jwtService) GetPublicKey() *rsa.PublicKey {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.strategy.GetPublicKey()
}

// RotateKeys rotates the JWT keys
func (j *jwtService) RotateKeys() error {

	j.mu.Lock()
	defer j.mu.Unlock()

	if err := j.strategy.RotateKey(); err != nil {
		j.logger.Error("Failed to rotate keys", zap.Error(err))
		return domain.ErrInvalidKeyConfig
	}

	// Clear JWKS cache
	j.cache.mu.Lock()
	j.cache.keys = make(map[string]interface{})
	j.cache.lastSync = time.Time{}
	j.cache.mu.Unlock()

	j.logger.Info("JWT keys rotated successfully",
		zap.String("key_id", j.strategy.GetKeyID()),
		zap.Time("rotation_time", j.strategy.GetLastRotation()))

	return nil
}

// BlacklistToken adds a token to the blacklist
func (j *jwtService) BlacklistToken(tokenID string, expiresAt time.Time) error {
	return j.revocation.Revoke(context.Background(), tokenID, expiresAt)
}

// IsTokenBlacklisted checks if a token is blacklisted
func (j *jwtService) IsTokenBlacklisted(tokenID string) bool {
	revoked, err := j.revocation.IsRevoked(context.Background(), tokenID)
	if err != nil {
		j.logger.Error("Failed to check token revocation", zap.Error(err), zap.String("token_id", tokenID))
		return false
	}
	return revoked
}

// convertToJWK converts an RSA public key to JWK format
func convertToJWK(publicKey *rsa.PublicKey, kid string) (map[string]interface{}, error) {
	// Convert modulus to base64url without padding
	modulusBytes := publicKey.N.Bytes()
	nStr := base64.RawURLEncoding.EncodeToString(modulusBytes)

	// Convert exponent to base64url without padding
	// RSA public exponent is typically 65537 (0x10001)
	eBytes := []byte{0x01, 0x00, 0x01} // 65537 in big-endian
	eStr := base64.RawURLEncoding.EncodeToString(eBytes)

	jwk := map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"kid": kid,
		"alg": "RS256",
		"n":   nStr,
		"e":   eStr,
	}

	return jwk, nil
}

// Close stops the revocation store cleanup goroutine when the store supports it.
func (j *jwtService) Close() {
	if c, ok := j.revocation.(interface{ Close() }); ok {
		c.Close()
	}
}
