package totp

import (
	"testing"
	"time"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestTOTPGenerator_GenerateSecret(t *testing.T) {
	// Setup
	generator := NewGenerator(zap.NewNop())

	// Execute
	secret, err := generator.GenerateSecret()

	// Assert
	assert.NoError(t, err)
	assert.NotEmpty(t, secret)
	assert.Len(t, secret, 32) // Base32 encoded secret should be 32 characters
}

func TestTOTPGenerator_GenerateQRCode(t *testing.T) {
	// Setup
	generator := NewGenerator(zap.NewNop())
	config := &domain.TOTPConfig{
		Issuer:      "test",
		AccountName: "user@example.com",
		Secret:      "JBSWY3DPEHPK3PXP",
		Period:      30 * time.Second,
		Digits:      6,
		Algorithm:   "SHA1",
	}

	// Execute
	qrCode, err := generator.GenerateQRCode(config)

	// Assert
	assert.NoError(t, err)
	assert.NotEmpty(t, qrCode)
	assert.Contains(t, qrCode, "otpauth://totp/")
	assert.Contains(t, qrCode, "issuer=test")
	assert.Contains(t, qrCode, "secret=JBSWY3DPEHPK3PXP")
}

func TestTOTPGenerator_GenerateBackupCodes(t *testing.T) {
	// Setup
	generator := NewGenerator(zap.NewNop())
	count := 10

	// Execute
	codes, err := generator.GenerateBackupCodes(count)

	// Assert
	assert.NoError(t, err)
	assert.Len(t, codes, count)
	for _, code := range codes {
		assert.Len(t, code, 10)                  // Each backup code should be 10 characters
		assert.Regexp(t, "^[A-Z0-9]{10}$", code) // Should be uppercase alphanumeric
	}
}

func TestTOTPGenerator_ValidateCode(t *testing.T) {
	// Setup
	generator := NewGenerator(zap.NewNop())
	secret := "JBSWY3DPEHPK3PXP"

	// Generate a valid TOTP code for the current time
	validCode, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate valid TOTP code: %v", err)
	}

	tests := []struct {
		name        string
		secret      string
		code        string
		expectError bool
	}{
		{
			name:        "Valid Code",
			secret:      secret,
			code:        validCode,
			expectError: false,
		},
		{
			name:        "Invalid Secret",
			secret:      "invalid",
			code:        validCode,
			expectError: true,
		},
		{
			name:        "Invalid Code Format",
			secret:      secret,
			code:        "invalid",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Execute
			err := generator.ValidateCode(tt.secret, tt.code)

			// Assert
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTOTPGenerator_ValidateBackupCode(t *testing.T) {
	// Setup
	generator := NewGenerator(zap.NewNop())
	codes := []string{"ABCDEF1234", "GHIJKL5678"}

	tests := []struct {
		name          string
		codes         []string
		code          string
		expectedIndex int
		expectError   bool
	}{
		{
			name:          "Valid Code",
			codes:         codes,
			code:          "ABCDEF1234",
			expectedIndex: 0,
			expectError:   false,
		},
		{
			name:          "Invalid Code",
			codes:         codes,
			code:          "INVALID123",
			expectedIndex: -1,
			expectError:   true,
		},
		{
			name:          "Nil Codes",
			codes:         nil,
			code:          "ABCDEF1234",
			expectedIndex: -1,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Execute
			index, err := generator.ValidateBackupCode(tt.codes, tt.code)

			// Assert
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedIndex, index)
		})
	}
}
