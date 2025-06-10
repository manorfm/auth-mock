package repository

import (
	"context"
	"time"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
)

type VerificationCodeRepository struct {
	logger            *zap.Logger
	verificationCodes []*domain.VerificationCode
}

func NewVerificationCodeRepository(logger *zap.Logger) *VerificationCodeRepository {
	return &VerificationCodeRepository{
		verificationCodes: make([]*domain.VerificationCode, 0),
		logger:            logger,
	}
}

func (r *VerificationCodeRepository) Create(ctx context.Context, code *domain.VerificationCode) error {
	r.verificationCodes = append(r.verificationCodes, code)
	return nil
}

func (r *VerificationCodeRepository) FindByCode(ctx context.Context, code string) (*domain.VerificationCode, error) {
	for _, c := range r.verificationCodes {
		if c.Code == code {
			return c, nil
		}
	}
	return nil, domain.ErrInvalidVerificationCode
}

func (r *VerificationCodeRepository) FindByUserIDAndType(ctx context.Context, userID ulid.ULID, codeType domain.VerificationCodeType) (*domain.VerificationCode, error) {
	for _, c := range r.verificationCodes {
		if c.UserID == userID && c.Type == codeType {
			return c, nil
		}
	}
	return nil, domain.ErrInvalidVerificationCode
}

func (r *VerificationCodeRepository) DeleteExpired(ctx context.Context, before time.Time) error {
	for i, code := range r.verificationCodes {
		if code.ExpiresAt.Before(before) {
			r.verificationCodes = append(r.verificationCodes[:i], r.verificationCodes[i+1:]...)
		}
	}
	return nil
}

func (r *VerificationCodeRepository) DeleteByUserIDAndType(ctx context.Context, userID ulid.ULID, codeType domain.VerificationCodeType) error {
	for i, code := range r.verificationCodes {
		if code.UserID == userID && code.Type == codeType {
			r.verificationCodes = append(r.verificationCodes[:i], r.verificationCodes[i+1:]...)
		}
	}
	return nil
}
