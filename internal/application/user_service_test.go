package application

import (
	"context"
	"testing"
	"time"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

func TestUserService_GetUser(t *testing.T) {
	logger, _ := zap.NewProduction()
	ctx := context.Background()

	t.Run("successful get user", func(t *testing.T) {
		repo := new(MockUserRepository)
		service := NewUserService(repo, logger)

		userID := domain.ULID(ulid.Make())
		expectedUser := &domain.User{
			ID:        userID,
			Name:      "Test User",
			Email:     "test@example.com",
			Phone:     "1234567890",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		repo.On("FindByID", ctx, userID).Return(expectedUser, nil)

		user, err := service.GetUser(ctx, userID)
		assert.NoError(t, err)
		assert.Equal(t, expectedUser, user)
	})

	t.Run("user not found", func(t *testing.T) {
		repo := new(MockUserRepository)
		service := NewUserService(repo, logger)

		userID := domain.ULID(ulid.Make())
		repo.On("FindByID", ctx, userID).Return(nil, domain.ErrUserNotFound)

		user, err := service.GetUser(ctx, userID)
		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Equal(t, domain.ErrUserNotFound, err)
	})

	t.Run("repository error", func(t *testing.T) {
		repo := new(MockUserRepository)
		service := NewUserService(repo, logger)

		userID := domain.ULID(ulid.Make())
		repo.On("FindByID", ctx, userID).Return(nil, assert.AnError)

		user, err := service.GetUser(ctx, userID)
		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Equal(t, assert.AnError, err)
	})
}

func TestUserService_UpdateUser(t *testing.T) {
	logger, _ := zap.NewProduction()
	ctx := context.Background()

	t.Run("successful update", func(t *testing.T) {
		repo := new(MockUserRepository)
		service := NewUserService(repo, logger)

		userID := domain.ULID(ulid.Make())
		existingUser := &domain.User{
			ID:        userID,
			Name:      "Old Name",
			Email:     "test@example.com",
			Phone:     "1234567890",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		repo.On("FindByID", ctx, userID).Return(existingUser, nil)
		repo.On("Update", ctx, mock.Anything).Return(nil)

		err := service.UpdateUser(ctx, userID, "New Name", "9876543210")
		assert.NoError(t, err)
	})

	t.Run("user not found", func(t *testing.T) {
		repo := new(MockUserRepository)
		service := NewUserService(repo, logger)

		userID := domain.ULID(ulid.Make())
		repo.On("FindByID", ctx, userID).Return(nil, domain.ErrUserNotFound)

		err := service.UpdateUser(ctx, userID, "New Name", "9876543210")
		assert.Error(t, err)
		assert.Equal(t, domain.ErrUserNotFound, err)
	})

	t.Run("repository error on find", func(t *testing.T) {
		repo := new(MockUserRepository)
		service := NewUserService(repo, logger)

		userID := domain.ULID(ulid.Make())
		repo.On("FindByID", ctx, userID).Return(nil, assert.AnError)

		err := service.UpdateUser(ctx, userID, "New Name", "9876543210")
		assert.Error(t, err)
		assert.Equal(t, domain.ErrUserNotFound, err)
	})

	t.Run("repository error on update", func(t *testing.T) {
		repo := new(MockUserRepository)
		service := NewUserService(repo, logger)

		userID := domain.ULID(ulid.Make())
		existingUser := &domain.User{
			ID:        userID,
			Name:      "Old Name",
			Email:     "test@example.com",
			Phone:     "1234567890",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		repo.On("FindByID", ctx, userID).Return(existingUser, nil)
		repo.On("Update", ctx, mock.Anything).Return(assert.AnError)

		err := service.UpdateUser(ctx, userID, "New Name", "9876543210")
		assert.Error(t, err)
		assert.Equal(t, assert.AnError, err)
	})
}

func TestUserService_ListUsers(t *testing.T) {
	logger, _ := zap.NewProduction()
	ctx := context.Background()

	t.Run("successful list users", func(t *testing.T) {
		repo := new(MockUserRepository)
		service := NewUserService(repo, logger)

		expectedUsers := []*domain.User{
			{
				ID:        domain.ULID(ulid.Make()),
				Name:      "User 1",
				Email:     "user1@example.com",
				Phone:     "1234567890",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
			{
				ID:        domain.ULID(ulid.Make()),
				Name:      "User 2",
				Email:     "user2@example.com",
				Phone:     "0987654321",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
		}

		repo.On("List", ctx, 10, 0).Return(expectedUsers, nil)

		users, err := service.ListUsers(ctx, 10, 0)
		assert.NoError(t, err)
		assert.Equal(t, expectedUsers, users)
	})

	t.Run("empty list", func(t *testing.T) {
		repo := new(MockUserRepository)
		service := NewUserService(repo, logger)

		repo.On("List", ctx, 10, 0).Return([]*domain.User{}, nil)

		users, err := service.ListUsers(ctx, 10, 0)
		assert.NoError(t, err)
		assert.Empty(t, users)
	})

	t.Run("repository error", func(t *testing.T) {
		repo := new(MockUserRepository)
		service := NewUserService(repo, logger)

		repo.On("List", ctx, 10, 0).Return(nil, assert.AnError)

		users, err := service.ListUsers(ctx, 10, 0)
		assert.Error(t, err)
		assert.Nil(t, users)
		assert.Equal(t, assert.AnError, err)
	})
}
