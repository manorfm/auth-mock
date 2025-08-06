package domain

import (
	"context"
	"time"

	"github.com/oklog/ulid/v2"
)

// AccountStatus represents the status of an account
type AccountStatus string

const (
	AccountStatusActive    AccountStatus = "active"
	AccountStatusInactive  AccountStatus = "inactive"
	AccountStatusSuspended AccountStatus = "suspended"
)

// Account represents a user account
type Account struct {
	ID        ulid.ULID     `json:"id"`
	UserID    ulid.ULID     `json:"user_id"`
	Status    AccountStatus `json:"status"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
}

// NewAccount creates a new account for a user
func NewAccount(userID ulid.ULID) *Account {
	return &Account{
		ID:        ulid.Make(),
		UserID:    userID,
		Status:    AccountStatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// AccountRepository defines the interface for account data access
type AccountRepository interface {
	Create(ctx context.Context, account *Account) error
	FindByID(ctx context.Context, id ulid.ULID) (*Account, error)
	FindByUserID(ctx context.Context, userID ulid.ULID) (*Account, error)
	Update(ctx context.Context, account *Account) error
	Delete(ctx context.Context, id ulid.ULID) error
}

// AccountService defines the interface for account business logic
type AccountService interface {
	CreateAccount(ctx context.Context, userID ulid.ULID) (*Account, error)
	GetAccount(ctx context.Context, id ulid.ULID) (*Account, error)
	GetAccountByUserID(ctx context.Context, userID ulid.ULID) (*Account, error)
	UpdateAccount(ctx context.Context, account *Account) error
	DeleteAccount(ctx context.Context, id ulid.ULID) error
}
