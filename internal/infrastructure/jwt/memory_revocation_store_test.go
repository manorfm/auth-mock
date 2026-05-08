package jwt

import (
	"context"
	"testing"
	"time"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestMemoryTokenRevocationStore_RevokeAndIsRevoked(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	s := NewMemoryTokenRevocationStore(logger)
	t.Cleanup(func() { s.Close() })

	exp := time.Now().Add(1 * time.Hour)
	require.NoError(t, s.Revoke(ctx, "jti-1", exp))

	revoked, err := s.IsRevoked(ctx, "jti-1")
	require.NoError(t, err)
	assert.True(t, revoked)

	revoked, err = s.IsRevoked(ctx, "unknown")
	require.NoError(t, err)
	assert.False(t, revoked)
}

func TestMemoryTokenRevocationStore_RevokeEmptyJTI(t *testing.T) {
	s := NewMemoryTokenRevocationStore(zap.NewNop())
	t.Cleanup(func() { s.Close() })
	err := s.Revoke(context.Background(), "", time.Now().Add(time.Hour))
	assert.ErrorIs(t, err, domain.ErrInvalidToken)
}

func TestMemoryTokenRevocationStore_ExpiredEntryNotRevoked(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryTokenRevocationStore(zap.NewNop())
	t.Cleanup(func() { s.Close() })

	require.NoError(t, s.Revoke(ctx, "jti-old", time.Now().Add(-time.Minute)))

	revoked, err := s.IsRevoked(ctx, "jti-old")
	require.NoError(t, err)
	assert.False(t, revoked)
}
