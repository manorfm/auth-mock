package application

import (
	"context"
	"testing"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/infrastructure/repository"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

// MockAccountRepository is a mock implementation of domain.AccountRepository
type MockAccountRepository struct {
	mock.Mock
}

func (m *MockAccountRepository) Create(ctx context.Context, account *domain.Account) error {
	args := m.Called(ctx, account)
	return args.Error(0)
}

func (m *MockAccountRepository) FindByID(ctx context.Context, id ulid.ULID) (*domain.Account, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Account), args.Error(1)
}

func (m *MockAccountRepository) FindByUserID(ctx context.Context, userID ulid.ULID) (*domain.Account, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Account), args.Error(1)
}

func (m *MockAccountRepository) Update(ctx context.Context, account *domain.Account) error {
	args := m.Called(ctx, account)
	return args.Error(0)
}

func (m *MockAccountRepository) Delete(ctx context.Context, id ulid.ULID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func TestAccountService_CreateAccount(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockAccountRepository)
	service := NewAccountService(mockRepo, logger)

	userID := ulid.Make()

	mockRepo.On("Create", mock.Anything, mock.MatchedBy(func(account *domain.Account) bool {
		return account.UserID == userID && account.Status == domain.AccountStatusActive
	})).Return(nil)

	account, err := service.CreateAccount(context.Background(), userID)

	assert.NoError(t, err)
	assert.NotNil(t, account)
	assert.Equal(t, userID, account.UserID)
	assert.Equal(t, domain.AccountStatusActive, account.Status)
	mockRepo.AssertExpectations(t)
}

func TestAccountService_CreateAccount_Error(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockAccountRepository)
	service := NewAccountService(mockRepo, logger)

	userID := ulid.Make()

	mockRepo.On("Create", mock.Anything, mock.MatchedBy(func(account *domain.Account) bool {
		return account.UserID == userID && account.Status == domain.AccountStatusActive
	})).Return(domain.ErrAccountCreationFailed)

	account, err := service.CreateAccount(context.Background(), userID)

	assert.Error(t, err)
	assert.Nil(t, account)
	assert.Equal(t, domain.ErrAccountCreationFailed, err)
	mockRepo.AssertExpectations(t)
}

func TestAccountService_GetAccountByUserID(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockAccountRepository)
	service := NewAccountService(mockRepo, logger)

	userID := ulid.Make()
	expectedAccount := &domain.Account{
		ID:     ulid.Make(),
		UserID: userID,
		Status: domain.AccountStatusActive,
	}

	mockRepo.On("FindByUserID", mock.Anything, userID).Return(expectedAccount, nil)

	account, err := service.GetAccountByUserID(context.Background(), userID)

	assert.NoError(t, err)
	assert.NotNil(t, account)
	assert.Equal(t, userID, account.UserID)
	mockRepo.AssertExpectations(t)
}

func TestAccountService_GetAccountByUserID_NotFound(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockAccountRepository)
	service := NewAccountService(mockRepo, logger)

	userID := ulid.Make()

	mockRepo.On("FindByUserID", mock.Anything, userID).Return(nil, domain.ErrAccountNotFound)

	account, err := service.GetAccountByUserID(context.Background(), userID)

	assert.Error(t, err)
	assert.Nil(t, account)
	assert.Equal(t, domain.ErrAccountNotFound, err)
	mockRepo.AssertExpectations(t)
}

func TestAccountService_UpdateAccount(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockAccountRepository)
	service := NewAccountService(mockRepo, logger)

	account := &domain.Account{
		ID:     ulid.Make(),
		UserID: ulid.Make(),
		Status: domain.AccountStatusActive,
	}

	mockRepo.On("Update", mock.Anything, account).Return(nil)

	err := service.UpdateAccount(context.Background(), account)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestAccountService_DeleteAccount(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockAccountRepository)
	service := NewAccountService(mockRepo, logger)

	accountID := ulid.Make()

	mockRepo.On("Delete", mock.Anything, accountID).Return(nil)

	err := service.DeleteAccount(context.Background(), accountID)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestAccountService_Integration(t *testing.T) {
	logger := zap.NewNop()
	repo := repository.NewAccountRepository()
	service := NewAccountService(repo, logger)

	userID := ulid.Make()

	// Test CreateAccount
	account, err := service.CreateAccount(context.Background(), userID)
	assert.NoError(t, err)
	assert.NotNil(t, account)
	assert.Equal(t, userID, account.UserID)

	// Test GetAccountByUserID
	retrievedAccount, err := service.GetAccountByUserID(context.Background(), userID)
	assert.NoError(t, err)
	assert.NotNil(t, retrievedAccount)
	assert.Equal(t, account.ID, retrievedAccount.ID)

	// Test UpdateAccount
	retrievedAccount.Status = domain.AccountStatusInactive
	err = service.UpdateAccount(context.Background(), retrievedAccount)
	assert.NoError(t, err)

	// Verify update
	updatedAccount, err := service.GetAccountByUserID(context.Background(), userID)
	assert.NoError(t, err)
	assert.Equal(t, domain.AccountStatusInactive, updatedAccount.Status)

	// Test DeleteAccount
	err = service.DeleteAccount(context.Background(), account.ID)
	assert.NoError(t, err)

	// Verify deletion
	_, err = service.GetAccountByUserID(context.Background(), userID)
	assert.Error(t, err)
	assert.Equal(t, domain.ErrAccountNotFound, err)
}
