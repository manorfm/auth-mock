package jwt

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/infrastructure/config"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestLocalStrategy(t *testing.T) {

	logger, err := zap.NewDevelopment()
	require.NoError(t, err)

	config := &config.Config{
		RSAKeySize: 2048,
	}

	t.Run("new strategy", func(t *testing.T) {
		strategy, err := NewLocalStrategy(config, logger)
		require.NoError(t, err)
		assert.NotNil(t, strategy)
		assert.NotNil(t, strategy.GetPublicKey())
		assert.NotEmpty(t, strategy.GetKeyID())
	})

	t.Run("sign and validate token", func(t *testing.T) {
		strategy, err := NewLocalStrategy(config, logger)
		require.NoError(t, err)

		// Create claims
		userID := ulid.Make()
		claims := &domain.Claims{
			Roles: []string{"user"},
			RegisteredClaims: &jwt.RegisteredClaims{
				Subject:   userID.String(),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ID:        ulid.Make().String(),
			},
		}

		// Sign token
		token, err := strategy.Sign(claims)
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		// Validate token
		parsedToken, err := jwt.ParseWithClaims(token, &domain.Claims{}, func(token *jwt.Token) (interface{}, error) {
			return strategy.GetPublicKey(), nil
		})
		require.NoError(t, err)
		assert.True(t, parsedToken.Valid)

		parsedClaims, ok := parsedToken.Claims.(*domain.Claims)
		require.True(t, ok)
		assert.Equal(t, userID.String(), parsedClaims.Subject)
		assert.Equal(t, []string{"user"}, parsedClaims.Roles)
	})

	t.Run("rotate key", func(t *testing.T) {
		strategy, err := NewLocalStrategy(config, logger)
		require.NoError(t, err)

		// Get initial key ID
		initialKeyID := strategy.GetKeyID()

		// Rotate key
		err = strategy.RotateKey()
		require.NoError(t, err)

		// Check key ID changed
		assert.NotEqual(t, initialKeyID, strategy.GetKeyID())
	})
}
