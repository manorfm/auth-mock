package jwt

import (
	"context"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/oklog/ulid/v2"
)

// UserRepositorySessionSource reads SessionVersion from the user repository.
type UserRepositorySessionSource struct {
	repo domain.UserRepository
}

// NewUserRepositorySessionSource adapts UserRepository for JWT session-version checks.
// Pass nil to skip session-version validation (tests only; production should always wire a non-nil repository).
func NewUserRepositorySessionSource(repo domain.UserRepository) domain.SessionVersionSource {
	if repo == nil {
		return nil
	}
	return &UserRepositorySessionSource{repo: repo}
}

func (s *UserRepositorySessionSource) GetSessionVersion(ctx context.Context, userID ulid.ULID) (int64, error) {
	u, err := s.repo.FindByID(ctx, userID)
	if err != nil {
		return 0, err
	}
	if u.SessionVersion < 1 {
		return 1, nil
	}
	return u.SessionVersion, nil
}
