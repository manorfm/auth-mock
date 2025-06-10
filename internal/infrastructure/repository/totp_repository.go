package repository

import (
	"context"

	"github.com/manorfm/auth-mock/internal/domain"
	"go.uber.org/zap"
)

type TOTPRepository struct {
	secrets map[string]string
	codes   map[string][]string
	logger  *zap.Logger
}

// NewTOTPRepository creates a new TOTP repository
func NewTOTPRepository(logger *zap.Logger) *TOTPRepository {
	return &TOTPRepository{
		secrets: make(map[string]string),
		codes:   make(map[string][]string),
		logger:  logger,
	}
}

// SaveTOTPSecret saves a TOTP secret for a user
func (r *TOTPRepository) SaveTOTPSecret(ctx context.Context, userID string, secret string) error {
	if secret == "" {
		r.logger.Error("invalid secret")
		return domain.ErrInternal
	}

	r.secrets[userID] = secret

	return nil
}

// GetTOTPSecret retrieves a TOTP secret for a user
func (r *TOTPRepository) GetTOTPSecret(ctx context.Context, userID string) (string, error) {
	secret, ok := r.secrets[userID]
	if !ok || secret == "" {
		return "", domain.ErrTOTPNotEnabled
	}
	return secret, nil
}

// SaveBackupCodes saves backup codes for a user
func (r *TOTPRepository) SaveBackupCodes(ctx context.Context, userID string, codes []string) error {
	if len(codes) == 0 {
		r.logger.Error("invalid backup codes")
		return domain.ErrInternal
	}

	r.codes[userID] = codes

	return nil
}

// GetBackupCodes retrieves backup codes for a user
func (r *TOTPRepository) GetBackupCodes(ctx context.Context, userID string) ([]string, error) {
	codes, ok := r.codes[userID]
	if !ok {
		return nil, domain.ErrTOTPNotEnabled
	}
	return codes, nil
}

// MarkBackupCodeAsUsed marks a backup code as used
func (r *TOTPRepository) MarkBackupCodeAsUsed(ctx context.Context, userID string, codeIndex int) error {
	codes, ok := r.codes[userID]
	if !ok {
		return domain.ErrTOTPNotEnabled
	}

	if codeIndex < 0 || codeIndex >= len(codes) {
		r.logger.Error("invalid code index")
		return domain.ErrInternal
	}

	codes[codeIndex] = ""

	return r.SaveBackupCodes(ctx, userID, codes)
}

// DeleteTOTPConfig deletes all TOTP configuration for a user
func (r *TOTPRepository) DeleteTOTPConfig(ctx context.Context, userID string) error {
	delete(r.secrets, userID)
	delete(r.codes, userID)
	return nil
}
