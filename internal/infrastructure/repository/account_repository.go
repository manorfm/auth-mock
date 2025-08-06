package repository

import (
	"context"
	"sync"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/oklog/ulid/v2"
)

// AccountRepository implements domain.AccountRepository with in-memory storage
type AccountRepository struct {
	accounts map[string]*domain.Account
	mu       sync.RWMutex
}

// NewAccountRepository creates a new in-memory account repository
func NewAccountRepository() *AccountRepository {
	return &AccountRepository{
		accounts: make(map[string]*domain.Account),
	}
}

// Create stores a new account in memory
func (r *AccountRepository) Create(ctx context.Context, account *domain.Account) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if account already exists for this user
	for _, existingAccount := range r.accounts {
		if existingAccount.UserID == account.UserID {
			return domain.ErrAccountCreationFailed
		}
	}

	r.accounts[account.ID.String()] = account
	return nil
}

// FindByID retrieves an account by its ID
func (r *AccountRepository) FindByID(ctx context.Context, id ulid.ULID) (*domain.Account, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	account, exists := r.accounts[id.String()]
	if !exists {
		return nil, domain.ErrAccountNotFound
	}

	return account, nil
}

// FindByUserID retrieves an account by user ID
func (r *AccountRepository) FindByUserID(ctx context.Context, userID ulid.ULID) (*domain.Account, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, account := range r.accounts {
		if account.UserID == userID {
			return account, nil
		}
	}

	return nil, domain.ErrAccountNotFound
}

// Update updates an existing account
func (r *AccountRepository) Update(ctx context.Context, account *domain.Account) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.accounts[account.ID.String()]; !exists {
		return domain.ErrAccountNotFound
	}

	r.accounts[account.ID.String()] = account
	return nil
}

// Delete removes an account by ID
func (r *AccountRepository) Delete(ctx context.Context, id ulid.ULID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.accounts[id.String()]; !exists {
		return domain.ErrAccountNotFound
	}

	delete(r.accounts, id.String())
	return nil
} 