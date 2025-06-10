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
	strategy  domain.JWTStrategy
	logger    *zap.Logger
	config    *config.Config
	mu        sync.RWMutex
	cache     *jwksCache
	blacklist map[string]time.Time // tokenID -> expiration
	stopChan  chan struct{}        // Channel to stop cleanup goroutine
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

func NewJWTService(strategy domain.JWTStrategy, config *config.Config, logger *zap.Logger) domain.JWTService {
	service := &jwtService{
		strategy:  strategy,
		logger:    logger,
		config:    config,
		cache:     newJWKSCache(),
		blacklist: make(map[string]time.Time),
		stopChan:  make(chan struct{}),
	}

	// Start cleanup goroutine
	go service.cleanupBlacklist()

	return service
}

// cleanupBlacklist periodically removes expired tokens from the blacklist
func (j *jwtService) cleanupBlacklist() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			j.mu.Lock()
			now := time.Now()
			for tokenID, expiresAt := range j.blacklist {
				if now.After(expiresAt) {
					delete(j.blacklist, tokenID)
					j.logger.Debug("Removed expired token from blacklist", zap.String("token_id", tokenID))
				}
			}
			j.mu.Unlock()
		case <-j.stopChan:
			return
		}
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

	// Check blacklist
	if j.IsTokenBlacklisted(claims.ID) {
		j.logger.Warn("Token is blacklisted", zap.String("token_id", claims.ID))
		return nil, domain.ErrTokenBlacklisted
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
func (j *jwtService) GenerateTokenPair(userID ulid.ULID, roles []string) (*domain.TokenPair, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()

	if len(roles) == 0 {
		return nil, domain.ErrTokenHasNoRoles
	}

	// Generate access token
	accessTokenID := ulid.Make().String()
	accessClaims := domain.Claims{
		Roles: roles,
		RegisteredClaims: &jwt.RegisteredClaims{
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.config.JWTAccessDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        accessTokenID,
		},
	}

	accessToken, err := j.strategy.Sign(&accessClaims)
	if err != nil {
		j.logger.Error("Failed to sign access token",
			zap.Error(err),
			zap.String("token_id", accessTokenID),
			zap.String("user_id", userID.String()))
		return nil, domain.ErrTokenGeneration
	}

	// Generate refresh token
	refreshTokenID := ulid.Make().String()
	refreshClaims := domain.Claims{
		Roles: roles,
		RegisteredClaims: &jwt.RegisteredClaims{
			Subject:   userID.String(),
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
			zap.String("user_id", userID.String()))
		return nil, domain.ErrTokenGeneration
	}

	j.logger.Debug("Generated token pair",
		zap.String("access_token_id", accessTokenID),
		zap.String("refresh_token_id", refreshTokenID),
		zap.String("user_id", userID.String()),
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
	if tokenID == "" {
		return domain.ErrInvalidToken
	}

	j.mu.Lock()
	defer j.mu.Unlock()

	// If token is already expired, don't add to blacklist
	if time.Now().After(expiresAt) {
		j.logger.Debug("Token already expired, not adding to blacklist",
			zap.String("token_id", tokenID),
			zap.Time("expires_at", expiresAt))
		return nil
	}

	j.blacklist[tokenID] = expiresAt
	j.logger.Debug("Added token to blacklist",
		zap.String("token_id", tokenID),
		zap.Time("expires_at", expiresAt))
	return nil
}

// IsTokenBlacklisted checks if a token is blacklisted
func (j *jwtService) IsTokenBlacklisted(tokenID string) bool {
	if tokenID == "" {
		return false
	}

	j.mu.RLock()
	exp, ok := j.blacklist[tokenID]
	j.mu.RUnlock()

	if !ok {
		return false
	}

	if time.Now().After(exp) {
		j.mu.Lock()
		delete(j.blacklist, tokenID)
		j.logger.Debug("Removed expired token from blacklist (during check)", zap.String("token_id", tokenID))
		j.mu.Unlock()
		return false
	}

	return true
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

// Close stops the cleanup goroutine
func (j *jwtService) Close() {
	close(j.stopChan)
}
