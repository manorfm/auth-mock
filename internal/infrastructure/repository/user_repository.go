package repository

import (
	"context"
	"time"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
)

type UserRepository struct {
	logger *zap.Logger
	users  map[ulid.ULID]*domain.User
}

func NewUserRepository(logger *zap.Logger) *UserRepository {
	return &UserRepository{
		logger: logger,
		users:  make(map[ulid.ULID]*domain.User),
	}
}

func (r *UserRepository) Create(ctx context.Context, user *domain.User) error {
	r.users[user.ID] = user
	return nil
}

func (r *UserRepository) FindByID(ctx context.Context, id ulid.ULID) (*domain.User, error) {
	user, ok := r.users[id]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	return user, nil
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	for _, u := range r.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, domain.ErrUserNotFound
}

func (r *UserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	for _, u := range r.users {
		if u.Email == email {
			return true, nil
		}
	}
	return false, nil
}

func (r *UserRepository) AddRole(ctx context.Context, userID ulid.ULID, role string) error {
	user, ok := r.users[userID]
	if !ok {
		return domain.ErrUserNotFound
	}
	user.Roles = append(user.Roles, role)
	return nil
}

func (r *UserRepository) Delete(ctx context.Context, id ulid.ULID) error {
	delete(r.users, id)
	return nil
}

func (r *UserRepository) List(ctx context.Context, limit, offset int) ([]*domain.User, error) {
	users := make([]*domain.User, 0, len(r.users))
	for _, u := range r.users {
		users = append(users, u)
	}
	return users, nil
}

func (r *UserRepository) Update(ctx context.Context, user *domain.User) error {
	user, ok := r.users[user.ID]
	if !ok {
		return domain.ErrUserNotFound
	}
	user.Name = user.Name
	user.Phone = user.Phone
	user.UpdatedAt = time.Now()
	user.EmailVerified = user.EmailVerified
	user.Roles = user.Roles
	return nil
}

func (r *UserRepository) RemoveRole(ctx context.Context, userID ulid.ULID, role string) error {
	user, ok := r.users[userID]
	if !ok {
		return domain.ErrUserNotFound
	}
	for i, r := range user.Roles {
		if r == role {
			user.Roles = append(user.Roles[:i], user.Roles[i+1:]...)
			break
		}
	}
	return nil
}

func (r *UserRepository) UpdatePassword(ctx context.Context, userID ulid.ULID, hashedPassword string) error {
	user, ok := r.users[userID]
	if !ok {
		return domain.ErrUserNotFound
	}
	user.Password = hashedPassword
	return nil
}
