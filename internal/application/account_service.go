package application

import (
	"context"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
)

type AccountService struct {
	accountRepo domain.AccountRepository
	logger      *zap.Logger
}

func NewAccountService(accountRepo domain.AccountRepository, logger *zap.Logger) *AccountService {
	return &AccountService{
		accountRepo: accountRepo,
		logger:      logger,
	}
}

func (s *AccountService) CreateAccount(ctx context.Context, userID ulid.ULID) (*domain.Account, error) {
	account := domain.NewAccount(userID)

	if err := s.accountRepo.Create(ctx, account); err != nil {
		s.logger.Error("failed to create account", zap.Error(err))
		return nil, domain.ErrAccountCreationFailed
	}

	s.logger.Info("account created successfully",
		zap.String("account_id", account.ID.String()),
		zap.String("user_id", userID.String()))

	return account, nil
}

func (s *AccountService) GetAccount(ctx context.Context, id ulid.ULID) (*domain.Account, error) {
	account, err := s.accountRepo.FindByID(ctx, id)
	if err != nil {
		s.logger.Error("failed to get account", zap.Error(err))
		return nil, err
	}

	return account, nil
}

func (s *AccountService) GetAccountByUserID(ctx context.Context, userID ulid.ULID) (*domain.Account, error) {
	account, err := s.accountRepo.FindByUserID(ctx, userID)
	if err != nil {
		s.logger.Error("failed to get account by user id", zap.Error(err))
		return nil, err
	}

	return account, nil
}

func (s *AccountService) UpdateAccount(ctx context.Context, account *domain.Account) error {
	if err := s.accountRepo.Update(ctx, account); err != nil {
		s.logger.Error("failed to update account", zap.Error(err))
		return err
	}

	return nil
}

func (s *AccountService) DeleteAccount(ctx context.Context, id ulid.ULID) error {
	if err := s.accountRepo.Delete(ctx, id); err != nil {
		s.logger.Error("failed to delete account", zap.Error(err))
		return err
	}

	return nil
} 