package domain

import (
	"context"
	"time"
)

// TOTPConfig represents the configuration for TOTP
type TOTPConfig struct {
	Issuer      string
	AccountName string
	Secret      string
	Period      time.Duration
	Digits      int
	Algorithm   string
}

// TOTPBackupCodes represents the backup codes for TOTP
type TOTPBackupCodes struct {
	Codes []string
	Used  []bool
}

type TOTP struct {
	QRCode      string
	BackupCodes []string
}

// TOTPRepository defines the interface for TOTP data access
type TOTPRepository interface {
	// SaveTOTPSecret saves the TOTP secret for a user
	SaveTOTPSecret(ctx context.Context, userID, secret string) error
	// GetTOTPSecret retrieves the TOTP secret for a user
	GetTOTPSecret(ctx context.Context, userID string) (string, error)
	// SaveBackupCodes saves the backup codes for a user
	SaveBackupCodes(ctx context.Context, userID string, codes []string) error
	// GetBackupCodes retrieves the backup codes for a user
	GetBackupCodes(ctx context.Context, userID string) ([]string, error)
	// MarkBackupCodeAsUsed marks a backup code as used
	MarkBackupCodeAsUsed(ctx context.Context, userID string, codeIndex int) error
	// DeleteTOTPConfig deletes the TOTP configuration for a user
	DeleteTOTPConfig(ctx context.Context, userID string) error
}

// TOTPGenerator defines the interface for TOTP code generation and validation
type TOTPGenerator interface {
	// GenerateSecret generates a new TOTP secret
	GenerateSecret() (string, error)
	// GenerateQRCode generates a QR code for the TOTP secret
	GenerateQRCode(config *TOTPConfig) (string, error)
	// GenerateBackupCodes generates backup codes
	GenerateBackupCodes(count int) ([]string, error)
	// ValidateCode validates a TOTP code
	ValidateCode(secret, code string) error
	// ValidateBackupCode validates a backup code
	ValidateBackupCode(backupCodes []string, code string) (int, error)
}

// TOTPService defines the interface for TOTP operations
type TOTPService interface {
	EnableTOTP(userID string) (*TOTP, error)
	VerifyTOTP(userID, code string) error
	VerifyBackupCode(userID, code string) error
	DisableTOTP(userID string) error
	GetTOTPSecret(ctx context.Context, userID string) (string, error)
}
