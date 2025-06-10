package integration

import (
	"context"
	"testing"
	"time"

	"github.com/manorfm/auth-mock/internal/application"
	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/infrastructure/repository"
	"github.com/manorfm/auth-mock/internal/infrastructure/totp"
	"github.com/oklog/ulid/v2"
	extotp "github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestTOTPService_Integration(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	// Setup repositories
	userRepo := repository.NewUserRepository(logger)
	totpRepo := repository.NewTOTPRepository(logger)

	// Setup TOTP service with real generator
	totpGenerator := totp.NewGenerator(logger)
	totpService := application.NewTOTPService(totpRepo, totpGenerator, logger)

	t.Run("Enable and Verify TOTP", func(t *testing.T) {
		// Create a test user
		user := &domain.User{
			ID:            ulid.Make(),
			Name:          "Test User",
			Email:         "test@example.com",
			Password:      "password123",
			Phone:         "1234567890",
			Roles:         []string{"user"},
			EmailVerified: true,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}
		t.Logf("Creating user with ID: %s", user.ID.String())
		err := userRepo.Create(ctx, user)
		if err != nil {
			t.Logf("userRepo.Create error: %+v", err)
			t.FailNow()
		}
		require.NoError(t, err)

		// Ensure user exists in DB
		fetched, err := userRepo.FindByID(ctx, user.ID)
		if err != nil {
			t.Fatalf("user should exist in DB before enabling TOTP: %v", err)
		}
		require.Equal(t, user.ID, fetched.ID)

		t.Logf("Enabling TOTP for user ID: %s", user.ID.String())
		// Enable TOTP
		totp, err := totpService.EnableTOTP(user.ID.String())
		if err != nil {
			t.Logf("EnableTOTP error: %+v", err)
		}
		require.NoError(t, err)
		assert.NotNil(t, totp.QRCode)
		assert.NotEmpty(t, totp.BackupCodes)
		assert.Len(t, totp.BackupCodes, 10)

		// Retrieve the TOTP secret
		secret, err := totpService.GetTOTPSecret(ctx, user.ID.String())
		require.NoError(t, err)
		assert.NotEmpty(t, secret)

		// Generate a valid TOTP code
		code, err := extotp.GenerateCode(secret, time.Now())
		require.NoError(t, err)
		assert.NotEmpty(t, code)

		// Verify TOTP code
		err = totpService.VerifyTOTP(user.ID.String(), code)
		require.NoError(t, err)

		// Verify backup code
		err = totpService.VerifyBackupCode(user.ID.String(), totp.BackupCodes[0])
		require.NoError(t, err)

		// Disable TOTP
		err = totpService.DisableTOTP(user.ID.String())
		require.NoError(t, err)

		// Verify TOTP is disabled
		err = totpService.VerifyTOTP(user.ID.String(), code)
		assert.ErrorIs(t, err, domain.ErrTOTPNotEnabled)
	})

	t.Run("Invalid TOTP Operations", func(t *testing.T) {
		// Try to enable TOTP for non-existent user
		_, err := totpService.EnableTOTP("non-existent")

		// Try to verify TOTP for non-existent user
		err = totpService.VerifyTOTP("non-existent", "123456")
		assert.ErrorIs(t, err, domain.ErrInvalidTOTPCode)

		// Try to verify backup code for non-existent user
		err = totpService.VerifyBackupCode("non-existent", "backup-code")
		assert.ErrorIs(t, err, domain.ErrInvalidTOTPBackupCode)
	})

	t.Run("Invalid TOTP Codes", func(t *testing.T) {
		// Create a test user
		user := &domain.User{
			ID:            ulid.Make(),
			Name:          "Test User Invalid",
			Email:         "test-invalid@example.com",
			Password:      "password123",
			Phone:         "1234567890",
			Roles:         []string{"user"},
			EmailVerified: true,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}
		err := userRepo.Create(ctx, user)
		require.NoError(t, err)

		// Enable TOTP
		totp, err := totpService.EnableTOTP(user.ID.String())
		require.NoError(t, err)

		// Try invalid TOTP code
		err = totpService.VerifyTOTP(user.ID.String(), "000000")
		assert.ErrorIs(t, err, domain.ErrInvalidTOTPCode)

		// Try invalid backup code
		err = totpService.VerifyBackupCode(user.ID.String(), "invalid-backup-code")
		assert.ErrorIs(t, err, domain.ErrInvalidTOTPBackupCode)

		// Try reusing a backup code
		err = totpService.VerifyBackupCode(user.ID.String(), totp.BackupCodes[0])
		require.NoError(t, err)
		err = totpService.VerifyBackupCode(user.ID.String(), totp.BackupCodes[0])
		assert.ErrorIs(t, err, domain.ErrInvalidTOTPBackupCode)
	})

	t.Run("Re-enable TOTP", func(t *testing.T) {
		// Create a test user
		user := &domain.User{
			ID:            ulid.Make(),
			Name:          "Test User Re-enable",
			Email:         "test-reenable@example.com",
			Password:      "password123",
			Phone:         "1234567890",
			Roles:         []string{"user"},
			EmailVerified: true,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}
		err := userRepo.Create(ctx, user)
		require.NoError(t, err)

		// Enable TOTP first time
		totp1, err := totpService.EnableTOTP(user.ID.String())
		require.NoError(t, err)

		// Store the first secret
		secret1, err := totpService.GetTOTPSecret(ctx, user.ID.String())
		require.NoError(t, err)
		assert.NotEmpty(t, secret1)

		// Try to enable TOTP again
		_, err = totpService.EnableTOTP(user.ID.String())
		assert.ErrorIs(t, err, domain.ErrTOTPAlreadyEnabled)

		// Disable TOTP
		err = totpService.DisableTOTP(user.ID.String())
		require.NoError(t, err)

		// Enable TOTP second time
		totp2, err := totpService.EnableTOTP(user.ID.String())
		require.NoError(t, err)

		// Retrieve the new secret
		secret2, err := totpService.GetTOTPSecret(ctx, user.ID.String())
		require.NoError(t, err)
		assert.NotEmpty(t, secret2)

		// Verify new configuration is different
		assert.NotEqual(t, totp1.QRCode, totp2.QRCode)
		assert.NotEqual(t, totp1.BackupCodes, totp2.BackupCodes)

		// Verify old TOTP code doesn't work
		oldCode, err := extotp.GenerateCode(secret1, time.Now())
		require.NoError(t, err)
		err = totpService.VerifyTOTP(user.ID.String(), oldCode)
		if err != nil {
			t.Logf("Returned error when verifying old TOTP code: %v", err)
		}
		assert.ErrorIs(t, err, domain.ErrInvalidTOTPCode)

		// Verify new TOTP code works
		newCode, err := extotp.GenerateCode(secret2, time.Now())
		require.NoError(t, err)
		err = totpService.VerifyTOTP(user.ID.String(), newCode)
		require.NoError(t, err)
	})
}
