package repository

import (
	"context"
	"testing"
	"time"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
)

func TestAccountRepository_Create(t *testing.T) {
	repo := NewAccountRepository()
	userID := ulid.Make()
	account := domain.NewAccount(userID)

	err := repo.Create(context.Background(), account)

	assert.NoError(t, err)
}

func TestAccountRepository_Create_DuplicateUser(t *testing.T) {
	repo := NewAccountRepository()
	userID := ulid.Make()
	account1 := domain.NewAccount(userID)
	account2 := domain.NewAccount(userID)

	// Create first account
	err := repo.Create(context.Background(), account1)
	assert.NoError(t, err)

	// Try to create second account for same user
	err = repo.Create(context.Background(), account2)
	assert.Error(t, err)
	assert.Equal(t, domain.ErrAccountCreationFailed, err)
}

func TestAccountRepository_FindByID(t *testing.T) {
	repo := NewAccountRepository()
	userID := ulid.Make()
	account := domain.NewAccount(userID)

	// Create account
	err := repo.Create(context.Background(), account)
	assert.NoError(t, err)

	// Find by ID
	found, err := repo.FindByID(context.Background(), account.ID)
	assert.NoError(t, err)
	assert.NotNil(t, found)
	assert.Equal(t, account.ID, found.ID)
	assert.Equal(t, account.UserID, found.UserID)
}

func TestAccountRepository_FindByID_NotFound(t *testing.T) {
	repo := NewAccountRepository()
	accountID := ulid.Make()

	found, err := repo.FindByID(context.Background(), accountID)
	assert.Error(t, err)
	assert.Nil(t, found)
	assert.Equal(t, domain.ErrAccountNotFound, err)
}

func TestAccountRepository_FindByUserID(t *testing.T) {
	repo := NewAccountRepository()
	userID := ulid.Make()
	account := domain.NewAccount(userID)

	// Create account
	err := repo.Create(context.Background(), account)
	assert.NoError(t, err)

	// Find by user ID
	found, err := repo.FindByUserID(context.Background(), userID)
	assert.NoError(t, err)
	assert.NotNil(t, found)
	assert.Equal(t, account.ID, found.ID)
	assert.Equal(t, account.UserID, found.UserID)
}

func TestAccountRepository_FindByUserID_NotFound(t *testing.T) {
	repo := NewAccountRepository()
	userID := ulid.Make()

	found, err := repo.FindByUserID(context.Background(), userID)
	assert.Error(t, err)
	assert.Nil(t, found)
	assert.Equal(t, domain.ErrAccountNotFound, err)
}

func TestAccountRepository_Update(t *testing.T) {
	repo := NewAccountRepository()
	userID := ulid.Make()
	account := domain.NewAccount(userID)

	// Create account
	err := repo.Create(context.Background(), account)
	assert.NoError(t, err)

	// Update account
	account.Status = domain.AccountStatusInactive
	account.UpdatedAt = time.Now()
	err = repo.Update(context.Background(), account)
	assert.NoError(t, err)

	// Verify update
	found, err := repo.FindByID(context.Background(), account.ID)
	assert.NoError(t, err)
	assert.Equal(t, domain.AccountStatusInactive, found.Status)
}

func TestAccountRepository_Update_NotFound(t *testing.T) {
	repo := NewAccountRepository()
	account := &domain.Account{
		ID:     ulid.Make(),
		UserID: ulid.Make(),
		Status: domain.AccountStatusActive,
	}

	err := repo.Update(context.Background(), account)
	assert.Error(t, err)
	assert.Equal(t, domain.ErrAccountNotFound, err)
}

func TestAccountRepository_Delete(t *testing.T) {
	repo := NewAccountRepository()
	userID := ulid.Make()
	account := domain.NewAccount(userID)

	// Create account
	err := repo.Create(context.Background(), account)
	assert.NoError(t, err)

	// Delete account
	err = repo.Delete(context.Background(), account.ID)
	assert.NoError(t, err)

	// Verify deletion
	found, err := repo.FindByID(context.Background(), account.ID)
	assert.Error(t, err)
	assert.Nil(t, found)
	assert.Equal(t, domain.ErrAccountNotFound, err)
}

func TestAccountRepository_Delete_NotFound(t *testing.T) {
	repo := NewAccountRepository()
	accountID := ulid.Make()

	err := repo.Delete(context.Background(), accountID)
	assert.Error(t, err)
	assert.Equal(t, domain.ErrAccountNotFound, err)
}

func TestAccountRepository_Concurrency(t *testing.T) {
	repo := NewAccountRepository()
	userID := ulid.Make()
	account := domain.NewAccount(userID)

	// Test concurrent access
	done := make(chan bool, 2)

	go func() {
		err := repo.Create(context.Background(), account)
		assert.NoError(t, err)
		done <- true
	}()

	go func() {
		repo.FindByID(context.Background(), account.ID)
		// This might fail if the account hasn't been created yet
		done <- true
	}()

	<-done
	<-done
}
