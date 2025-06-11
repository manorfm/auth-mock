package jwt

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/infrastructure/config"
)

func getJWTServiceWithDuration(t *testing.T, accessDuration, refreshDuration time.Duration) domain.JWTService {
	logger, err := zap.NewDevelopment()
	require.NoError(t, err)

	cfg := &config.Config{
		JWTAccessDuration:  accessDuration,
		JWTRefreshDuration: refreshDuration,
		RSAKeySize:         2048,
	}

	strategy, err := NewLocalStrategy(cfg, logger)
	require.NoError(t, err)
	service := NewJWTService(strategy, cfg, logger)
	require.NotNil(t, service)

	return service
}

func getJWTService(t *testing.T) domain.JWTService {
	return getJWTServiceWithDuration(t, time.Duration(15*time.Minute), time.Duration(24*time.Hour))
}

func TestJWTService_ValidateToken(t *testing.T) {
	service := getJWTService(t)

	t.Run("valid token", func(t *testing.T) {
		userID := ulid.Make()
		roles := []string{"ADMIN"}
		tokenPair, err := service.GenerateTokenPair(userID, roles)
		require.NoError(t, err)

		claims, err := service.ValidateToken(tokenPair.AccessToken)
		require.NoError(t, err)
		require.NotNil(t, claims)
		require.Equal(t, userID.String(), claims.Subject)
		require.Equal(t, roles, claims.Roles)
	})

	t.Run("expired token", func(t *testing.T) {
		shortService := getJWTServiceWithDuration(t, 1*time.Second, time.Duration(24*time.Hour))
		expiredUserID := ulid.Make()
		expiredRoles := []string{"USER"}
		expiredTokenPair, err := shortService.GenerateTokenPair(expiredUserID, expiredRoles)
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		_, err = shortService.ValidateToken(expiredTokenPair.AccessToken)
		require.Error(t, err)
		require.Contains(t, err.Error(), "expired")
	})

	t.Run("invalid token format", func(t *testing.T) {
		invalidTokens := []string{
			"invalid.token.here",
			"not.even.a.jwt",
			"header.payload.signature",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
		}

		for _, token := range invalidTokens {
			_, err := service.ValidateToken(token)
			require.Error(t, err)
			if !(strings.Contains(err.Error(), "Token malformed") || strings.Contains(err.Error(), "Invalid token")) {
				t.Errorf("unexpected error: %v", err)
			}
		}
	})

	t.Run("blacklisted token", func(t *testing.T) {
		blacklistedUserID := ulid.Make()
		blacklistedRoles := []string{"USER"}
		blacklistedTokenPair, err := service.GenerateTokenPair(blacklistedUserID, blacklistedRoles)
		require.NoError(t, err)

		blacklistedClaims, err := service.ValidateToken(blacklistedTokenPair.AccessToken)
		require.NoError(t, err)

		err = service.BlacklistToken(blacklistedClaims.ID, blacklistedClaims.ExpiresAt.Time)
		require.NoError(t, err)

		_, err = service.ValidateToken(blacklistedTokenPair.AccessToken)
		require.Error(t, err)
		require.Contains(t, err.Error(), domain.ErrTokenBlacklisted.GetMessage())
	})

	t.Run("token with invalid signature", func(t *testing.T) {
		// Create a new service with different keys
		otherService := getJWTService(t)
		userID := ulid.Make()
		roles := []string{"ADMIN"}
		tokenPair, err := otherService.GenerateTokenPair(userID, roles)
		require.NoError(t, err)

		// Try to validate with original service
		_, err = service.ValidateToken(tokenPair.AccessToken)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid")
	})

	t.Run("token with missing required claims", func(t *testing.T) {
		// This would require modifying the token generation to create invalid tokens
		// We'll test this in a separate test that mocks the token generation
	})
}

func TestJWTService_GenerateTokenPair(t *testing.T) {
	service := getJWTService(t)

	t.Run("valid token pair generation", func(t *testing.T) {
		userID := ulid.Make()
		roles := []string{"ADMIN", "USER"}

		tokenPair, err := service.GenerateTokenPair(userID, roles)
		require.NoError(t, err)
		assert.NotEmpty(t, tokenPair.AccessToken)
		assert.NotEmpty(t, tokenPair.RefreshToken)

		// Validate access token
		claims, err := service.ValidateToken(tokenPair.AccessToken)
		require.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Equal(t, userID.String(), claims.Subject)
		assert.Equal(t, roles, claims.Roles)

		// Validate refresh token
		claims, err = service.ValidateToken(tokenPair.RefreshToken)
		require.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Equal(t, userID.String(), claims.Subject)
		assert.Equal(t, roles, claims.Roles)
	})

	t.Run("token pair with empty roles", func(t *testing.T) {
		userID := ulid.Make()
		roles := []string{}

		_, err := service.GenerateTokenPair(userID, roles)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Token has no roles")
	})

	t.Run("token pair with nil roles", func(t *testing.T) {
		userID := ulid.Make()
		var roles []string

		_, err := service.GenerateTokenPair(userID, roles)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Token has no roles")
	})
}

func TestJWTService_GetJWKS(t *testing.T) {
	service := getJWTService(t)

	t.Run("valid JWKS retrieval", func(t *testing.T) {
		ctx := context.Background()
		jwks, err := service.GetJWKS(ctx)
		require.NoError(t, err)
		require.NotNil(t, jwks)

		keys, ok := jwks["keys"].([]map[string]interface{})
		require.True(t, ok, "JWKS should contain a 'keys' array")
		assert.NotEmpty(t, keys, "JWKS should contain at least one key")

		for _, key := range keys {
			assert.Contains(t, key, "kty", "Key should have 'kty' field")
			assert.Contains(t, key, "kid", "Key should have 'kid' field")
			assert.Contains(t, key, "use", "Key should have 'use' field")
			assert.Contains(t, key, "alg", "Key should have 'alg' field")
			assert.Contains(t, key, "n", "Key should have 'n' field")
			assert.Contains(t, key, "e", "Key should have 'e' field")
		}
	})

	t.Run("JWKS after key rotation", func(t *testing.T) {
		// Get initial JWKS
		ctx := context.Background()
		initialJWKS, err := service.GetJWKS(ctx)
		require.NoError(t, err)

		// Rotate keys
		err = service.RotateKeys()
		require.NoError(t, err)

		// Get new JWKS
		newJWKS, err := service.GetJWKS(ctx)
		require.NoError(t, err)

		// Verify JWKS has changed
		assert.NotEqual(t, initialJWKS, newJWKS)
	})
}

func TestJWTService_RotateKeys(t *testing.T) {
	service := getJWTService(t)

	t.Run("successful key rotation", func(t *testing.T) {
		// Generate token with old key
		userID := ulid.Make()
		roles := []string{"ADMIN"}
		tokenPair1, err := service.GenerateTokenPair(userID, roles)
		require.NoError(t, err)

		// Validate token with old key
		validatedClaims, err := service.ValidateToken(tokenPair1.AccessToken)
		require.NoError(t, err)
		assert.NotNil(t, validatedClaims)
		assert.Equal(t, userID.String(), validatedClaims.Subject)
		assert.Contains(t, validatedClaims.Roles, "ADMIN")

		// Rotate keys
		err = service.RotateKeys()
		require.NoError(t, err)

		// Generate new token with new key
		tokenPair2, err := service.GenerateTokenPair(userID, roles)
		require.NoError(t, err)

		// Validate new token
		validatedClaims, err = service.ValidateToken(tokenPair2.AccessToken)
		require.NoError(t, err)
		assert.NotNil(t, validatedClaims)
		assert.Equal(t, userID.String(), validatedClaims.Subject)
		assert.Contains(t, validatedClaims.Roles, "ADMIN")

		// Verify old token is invalid
		_, err = service.ValidateToken(tokenPair1.AccessToken)
		require.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "signature"))
	})

	t.Run("multiple key rotations", func(t *testing.T) {
		// Perform multiple rotations
		for i := 0; i < 3; i++ {
			err := service.RotateKeys()
			require.NoError(t, err)
		}

		// Generate and validate token after multiple rotations
		userID := ulid.Make()
		roles := []string{"ADMIN"}
		tokenPair, err := service.GenerateTokenPair(userID, roles)
		require.NoError(t, err)

		claims, err := service.ValidateToken(tokenPair.AccessToken)
		require.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Equal(t, userID.String(), claims.Subject)
	})
}

func TestJWTService_TokenBlacklist(t *testing.T) {
	service := getJWTService(t)

	t.Run("blacklist and check token", func(t *testing.T) {
		userID := ulid.Make()
		roles := []string{"user"}

		// Generate a token
		tokenPair, err := service.GenerateTokenPair(userID, roles)
		require.NoError(t, err)

		// Get token ID from claims
		claims, err := service.ValidateToken(tokenPair.AccessToken)
		require.NoError(t, err)

		// Blacklist the token
		err = service.BlacklistToken(claims.ID, claims.ExpiresAt.Time)
		require.NoError(t, err)

		// Try to validate the blacklisted token
		claims, err = service.ValidateToken(tokenPair.AccessToken)
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.ErrorIs(t, err, domain.ErrTokenBlacklisted)
	})

	t.Run("blacklist multiple tokens", func(t *testing.T) {
		userID := ulid.Make()
		roles := []string{"user"}

		// Generate multiple tokens
		tokens := make([]string, 3)
		for i := 0; i < 3; i++ {
			tokenPair, err := service.GenerateTokenPair(userID, roles)
			require.NoError(t, err)
			tokens[i] = tokenPair.AccessToken
		}

		// Blacklist all tokens
		for _, token := range tokens {
			claims, err := service.ValidateToken(token)
			require.NoError(t, err)
			err = service.BlacklistToken(claims.ID, claims.ExpiresAt.Time)
			require.NoError(t, err)
		}

		// Verify all tokens are blacklisted
		for _, token := range tokens {
			_, err := service.ValidateToken(token)
			assert.Error(t, err)
			assert.ErrorIs(t, err, domain.ErrTokenBlacklisted)
		}
	})

	t.Run("blacklist expired token", func(t *testing.T) {
		shortService := getJWTServiceWithDuration(t, 1*time.Second, time.Duration(24*time.Hour))
		userID := ulid.Make()
		roles := []string{"user"}

		tokenPair, err := shortService.GenerateTokenPair(userID, roles)
		require.NoError(t, err)

		claims, err := shortService.ValidateToken(tokenPair.AccessToken)
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		// Try to blacklist expired token
		err = shortService.BlacklistToken(claims.ID, claims.ExpiresAt.Time)
		require.NoError(t, err)

		// Verify token is both expired and blacklisted
		_, err = shortService.ValidateToken(tokenPair.AccessToken)
		assert.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "expired") || strings.Contains(err.Error(), "blacklisted"))
	})
}

func TestJWTService_GetPublicKey(t *testing.T) {
	service := getJWTService(t)

	t.Run("get public key", func(t *testing.T) {
		key := service.GetPublicKey()
		require.NotNil(t, key)

		// Verify key can be used to validate tokens
		userID := ulid.Make()
		roles := []string{"ADMIN"}

		tokenPair, err := service.GenerateTokenPair(userID, roles)
		require.NoError(t, err)

		claims, err := service.ValidateToken(tokenPair.AccessToken)
		require.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Equal(t, userID.String(), claims.Subject)
		assert.Contains(t, claims.Roles, "ADMIN")
	})

	t.Run("public key after rotation", func(t *testing.T) {
		// Get initial public key
		initialKey := service.GetPublicKey()
		require.NotNil(t, initialKey)

		// Rotate keys
		err := service.RotateKeys()
		require.NoError(t, err)

		// Get new public key
		newKey := service.GetPublicKey()
		require.NotNil(t, newKey)

		// Verify keys are different
		assert.NotEqual(t, initialKey, newKey)
	})
}
