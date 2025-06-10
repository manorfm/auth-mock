package application

import (
	"context"
	"time"

	"github.com/manorfm/auth-mock/internal/domain"
	"go.uber.org/zap"
)

// totpServiceImpl implements the TOTPService interface
type totpServiceImpl struct {
	repo      domain.TOTPRepository
	generator domain.TOTPGenerator
	logger    *zap.Logger
}

// NewTOTPService creates a new TOTP service
func NewTOTPService(repo domain.TOTPRepository, generator domain.TOTPGenerator, logger *zap.Logger) domain.TOTPService {
	return &totpServiceImpl{
		repo:      repo,
		generator: generator,
		logger:    logger,
	}
}

// EnableTOTP enables TOTP for a user
func (s *totpServiceImpl) EnableTOTP(userID string) (*domain.TOTP, error) {
	secret, err := s.repo.GetTOTPSecret(context.Background(), userID)
	if err != nil && err != domain.ErrTOTPNotEnabled {
		s.logger.Error("Failed to get TOTP secret",
			zap.String("user_id", userID),
			zap.Error(err))
		return nil, err
	}
	if secret != "" {
		return nil, domain.ErrTOTPAlreadyEnabled
	}

	secret, err = s.generator.GenerateSecret()
	if err != nil {
		s.logger.Error("Failed to generate TOTP secret",
			zap.String("user_id", userID),
			zap.Error(err))
		return nil, err
	}

	backupCodes, err := s.generator.GenerateBackupCodes(10)
	if err != nil {
		s.logger.Error("Failed to generate backup codes",
			zap.String("user_id", userID),
			zap.Error(err))
		return nil, err
	}

	if err := s.repo.SaveTOTPSecret(context.Background(), userID, secret); err != nil {
		s.logger.Error("Failed to save TOTP secret",
			zap.String("user_id", userID),
			zap.Error(err))
		return nil, err
	}

	if err := s.repo.SaveBackupCodes(context.Background(), userID, backupCodes); err != nil {
		s.logger.Error("Failed to save backup codes",
			zap.String("user_id", userID),
			zap.Error(err))
		return nil, err
	}

	config := &domain.TOTPConfig{
		Issuer:      "User Manager Service",
		AccountName: userID,
		Secret:      secret,
		Period:      30 * time.Second,
		Digits:      6,
		Algorithm:   "SHA1",
	}

	qrCode, err := s.generator.GenerateQRCode(config)
	if err != nil {
		s.logger.Error("Failed to generate QR code",
			zap.String("user_id", userID),
			zap.Error(err))
		return nil, err
	}
	return &domain.TOTP{QRCode: qrCode, BackupCodes: backupCodes}, nil
}

// VerifyTOTP verifies a TOTP code for a user
func (s *totpServiceImpl) VerifyTOTP(userID, code string) error {
	secret, err := s.repo.GetTOTPSecret(context.Background(), userID)
	if err != nil {
		s.logger.Error("Failed to get TOTP secret",
			zap.String("user_id", userID),
			zap.Error(err))
		return err
	}

	if err := s.generator.ValidateCode(secret, code); err != nil {
		s.logger.Error("Failed to validate TOTP code",
			zap.String("user_id", userID),
			zap.Error(err))
		return err
	}

	return nil
}

// VerifyBackupCode verifies a backup code for a user
func (s *totpServiceImpl) VerifyBackupCode(userID, code string) error {
	backupCodes, err := s.repo.GetBackupCodes(context.Background(), userID)
	if err != nil {
		s.logger.Error("Failed to get backup codes",
			zap.String("user_id", userID),
			zap.Error(err))
		return err
	}

	codeIndex, err := s.generator.ValidateBackupCode(backupCodes, code)
	if err != nil {
		s.logger.Error("Failed to validate backup code",
			zap.String("user_id", userID),
			zap.Error(err))
		return err
	}

	if err := s.repo.MarkBackupCodeAsUsed(context.Background(), userID, codeIndex); err != nil {
		s.logger.Error("Failed to mark backup code as used",
			zap.String("user_id", userID),
			zap.Error(err))
		return err
	}

	return nil
}

// DisableTOTP disables TOTP for a user
func (s *totpServiceImpl) DisableTOTP(userID string) error {
	secret, err := s.repo.GetTOTPSecret(context.Background(), userID)
	if err != nil {
		s.logger.Error("Failed to get TOTP secret",
			zap.String("user_id", userID),
			zap.Error(err))
		return err
	}
	if secret == "" {
		return domain.ErrTOTPNotEnabled
	}

	if err := s.repo.DeleteTOTPConfig(context.Background(), userID); err != nil {
		s.logger.Error("Failed to delete TOTP configuration",
			zap.String("user_id", userID),
			zap.Error(err))
		return err
	}

	return nil
}

// GetTOTPSecret retrieves the TOTP secret for a user
func (s *totpServiceImpl) GetTOTPSecret(ctx context.Context, userID string) (string, error) {
	secret, err := s.repo.GetTOTPSecret(ctx, userID)
	if err != nil {
		if err != domain.ErrTOTPNotEnabled {
			s.logger.Error("Failed to get TOTP secret",
				zap.String("user_id", userID),
				zap.Error(err))
		}
		return "", err
	}
	return secret, nil
}
