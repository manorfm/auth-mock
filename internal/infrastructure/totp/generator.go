package totp

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"
)

// Generator implements the domain.TOTPGenerator interface
type Generator struct {
	logger *zap.Logger
}

// NewGenerator creates a new TOTP generator
func NewGenerator(logger *zap.Logger) *Generator {
	return &Generator{logger: logger}
}

// GenerateSecret generates a new TOTP secret
func (g *Generator) GenerateSecret() (string, error) {
	// Generate 20 random bytes
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		g.logger.Error("failed to generate random bytes", zap.Error(err))
		return "", domain.ErrTOTPSecretGeneration
	}

	// Encode as base32
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// GenerateQRCode generates a QR code URL for TOTP configuration
func (g *Generator) GenerateQRCode(config *domain.TOTPConfig) (string, error) {
	// Format the account name and secret
	accountName := strings.ReplaceAll(config.AccountName, ":", "%3A")
	secret := strings.ReplaceAll(config.Secret, "=", "")

	// Generate the TOTP URL
	url := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d",
		config.Issuer,
		accountName,
		secret,
		config.Issuer,
		config.Algorithm,
		config.Digits,
		int(config.Period.Seconds()),
	)

	return url, nil
}

// GenerateBackupCodes generates a specified number of backup codes
func (g *Generator) GenerateBackupCodes(count int) ([]string, error) {
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		// Generate 8 random bytes to ensure at least 10 characters after base32 encoding
		code := make([]byte, 8)
		if _, err := rand.Read(code); err != nil {
			g.logger.Error("failed to generate random bytes", zap.Error(err))
			return nil, domain.ErrTOTPBackupCodesGeneration
		}
		// Encode as base32 and take first 10 characters
		encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(code)
		codes[i] = encoded[:10]
	}
	return codes, nil
}

// ValidateCode validates a TOTP code
func (g *Generator) ValidateCode(secret, code string) error {
	// Validate the code
	valid, err := totp.ValidateCustom(code, secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    6,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		g.logger.Error("failed to validate TOTP code", zap.Error(err))
		return domain.ErrInvalidTOTPCode
	}

	if !valid {
		g.logger.Error("invalid TOTP code")
		return domain.ErrInvalidTOTPCode
	}

	return nil
}

// ValidateBackupCode validates a backup code
func (g *Generator) ValidateBackupCode(backupCodes []string, code string) (int, error) {
	// Check if the code matches the pattern
	pattern := regexp.MustCompile(`^[A-Z0-9]{10}$`)
	if !pattern.MatchString(code) {
		g.logger.Error("invalid backup code format")
		return -1, domain.ErrInvalidTOTPBackupCode
	}

	// Find the code in the list
	for i, backupCode := range backupCodes {
		if backupCode == code {
			return i, nil
		}
	}

	g.logger.Error("invalid backup code")
	return -1, domain.ErrInvalidTOTPBackupCode
}
