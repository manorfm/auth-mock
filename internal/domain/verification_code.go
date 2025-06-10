package domain

import (
	"context"
	"time"

	"github.com/oklog/ulid/v2"
)

// VerificationCodeType represents the type of verification code
type VerificationCodeType string

const (
	EmailVerification VerificationCodeType = "email_verification"
	PasswordReset     VerificationCodeType = "password_reset"
)

// VerificationCode represents a verification code for email verification or password reset
type VerificationCode struct {
	ID        ulid.ULID            `json:"id"`
	UserID    ulid.ULID            `json:"user_id"`
	Code      string               `json:"code"`
	Type      VerificationCodeType `json:"type"`
	ExpiresAt time.Time            `json:"expires_at"`
	CreatedAt time.Time            `json:"created_at"`
}

// NewVerificationCode creates a new verification code
func NewVerificationCode(userID ulid.ULID, code string, codeType VerificationCodeType, expiresIn time.Duration) *VerificationCode {
	now := time.Now()
	return &VerificationCode{
		ID:        ulid.Make(),
		UserID:    userID,
		Code:      code,
		Type:      codeType,
		ExpiresAt: now.Add(expiresIn),
		CreatedAt: now,
	}
}

// IsExpired checks if the verification code is expired
func (vc *VerificationCode) IsExpired() bool {
	return time.Now().After(vc.ExpiresAt)
}

// VerificationCodeRepository defines the interface for verification code operations
type VerificationCodeRepository interface {
	// Create stores a new verification code
	Create(ctx context.Context, code *VerificationCode) error

	// FindByCode finds a verification code by its code value
	FindByCode(ctx context.Context, code string) (*VerificationCode, error)

	// FindByUserIDAndType finds the latest verification code for a user and type
	FindByUserIDAndType(ctx context.Context, userID ulid.ULID, codeType VerificationCodeType) (*VerificationCode, error)

	// DeleteExpired deletes expired verification codes
	DeleteExpired(ctx context.Context, before time.Time) error

	// DeleteByUserIDAndType deletes all verification codes for a user and type
	DeleteByUserIDAndType(ctx context.Context, userID ulid.ULID, codeType VerificationCodeType) error
}
