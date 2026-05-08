package jwt

import (
	"context"
	"sync"
	"time"

	"github.com/manorfm/auth-mock/internal/domain"
	"go.uber.org/zap"
)

// MemoryTokenRevocationStore keeps revoked jti → expiration in memory (single-process).
type MemoryTokenRevocationStore struct {
	mu        sync.RWMutex
	closeOnce sync.Once
	entries   map[string]time.Time
	logger    *zap.Logger
	stopCh    chan struct{}
}

var _ domain.TokenRevocationStore = (*MemoryTokenRevocationStore)(nil)

// NewMemoryTokenRevocationStore starts a periodic cleanup of expired entries.
func NewMemoryTokenRevocationStore(logger *zap.Logger) *MemoryTokenRevocationStore {
	s := &MemoryTokenRevocationStore{
		entries: make(map[string]time.Time),
		logger:  logger,
		stopCh:  make(chan struct{}),
	}
	go s.cleanupLoop()
	return s
}

func (s *MemoryTokenRevocationStore) Revoke(ctx context.Context, jti string, expiresAt time.Time) error {
	_ = ctx
	if jti == "" {
		return domain.ErrInvalidToken
	}
	if time.Now().After(expiresAt) {
		if s.logger != nil {
			s.logger.Debug("Token already expired, not adding revocation",
				zap.String("token_id", jti),
				zap.Time("expires_at", expiresAt))
		}
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[jti] = expiresAt
	if s.logger != nil {
		s.logger.Debug("Revoked token",
			zap.String("token_id", jti),
			zap.Time("expires_at", expiresAt))
	}
	return nil
}

func (s *MemoryTokenRevocationStore) IsRevoked(ctx context.Context, jti string) (bool, error) {
	_ = ctx
	if jti == "" {
		return false, nil
	}
	s.mu.RLock()
	exp, ok := s.entries[jti]
	s.mu.RUnlock()
	if !ok {
		return false, nil
	}
	if time.Now().After(exp) {
		s.mu.Lock()
		delete(s.entries, jti)
		s.mu.Unlock()
		if s.logger != nil {
			s.logger.Debug("Removed expired revocation entry (during check)", zap.String("token_id", jti))
		}
		return false, nil
	}
	return true, nil
}

func (s *MemoryTokenRevocationStore) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for id, exp := range s.entries {
				if now.After(exp) {
					delete(s.entries, id)
					if s.logger != nil {
						s.logger.Debug("Removed expired revocation entry", zap.String("token_id", id))
					}
				}
			}
			s.mu.Unlock()
		case <-s.stopCh:
			return
		}
	}
}

// Close stops the cleanup goroutine.
func (s *MemoryTokenRevocationStore) Close() {
	s.closeOnce.Do(func() {
		close(s.stopCh)
	})
}
