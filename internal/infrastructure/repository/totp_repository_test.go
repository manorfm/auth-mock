package repository

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestTOTPRepository_SaveTOTPSecret(t *testing.T) {
	// Setup
	repo := NewTOTPRepository(zap.NewNop())
	ctx := context.Background()

	// Test cases
	tests := []struct {
		name      string
		userID    string
		secret    string
		wantError bool
	}{
		{
			name:      "Success",
			userID:    "user1",
			secret:    "JBSWY3DPEHPK3PXP",
			wantError: false,
		},
		{
			name:      "Empty Secret",
			userID:    "user2",
			secret:    "",
			wantError: true,
		},
		{
			name:      "Update Existing",
			userID:    "user1",
			secret:    "NEWSECRET123",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Execute
			err := repo.SaveTOTPSecret(ctx, tt.userID, tt.secret)

			// Assert
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify the secret was saved
				savedSecret, err := repo.GetTOTPSecret(ctx, tt.userID)
				assert.NoError(t, err)
				assert.Equal(t, tt.secret, savedSecret)
			}
		})
	}
}

func TestTOTPRepository_GetTOTPSecret(t *testing.T) {
	// Setup
	repo := NewTOTPRepository(zap.NewNop())
	ctx := context.Background()

	// Insert test data
	userID := "user1"
	secret := "JBSWY3DPEHPK3PXP"
	err := repo.SaveTOTPSecret(ctx, userID, secret)
	require.NoError(t, err)

	// Test cases
	tests := []struct {
		name      string
		userID    string
		want      string
		wantError bool
	}{
		{
			name:      "Success",
			userID:    userID,
			want:      secret,
			wantError: false,
		},
		{
			name:      "User Not Found",
			userID:    "nonexistent",
			want:      "",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Execute
			got, err := repo.GetTOTPSecret(ctx, tt.userID)

			// Assert
			if tt.wantError {
				assert.Error(t, err)
				assert.Empty(t, got)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestTOTPRepository_SaveBackupCodes(t *testing.T) {
	// Setup
	repo := NewTOTPRepository(zap.NewNop())
	ctx := context.Background()

	// Test cases
	tests := []struct {
		name      string
		userID    string
		codes     []string
		wantError bool
	}{
		{
			name:      "Success",
			userID:    "user1",
			codes:     []string{"ABCDEF1234", "GHIJKL5678"},
			wantError: false,
		},
		{
			name:      "Empty Codes",
			userID:    "user2",
			codes:     []string{},
			wantError: true,
		},
		{
			name:      "Update Existing",
			userID:    "user1",
			codes:     []string{"NEWCODE1234", "NEWCODE5678"},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Execute
			err := repo.SaveBackupCodes(ctx, tt.userID, tt.codes)

			// Assert
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify the codes were saved
				savedCodes, err := repo.GetBackupCodes(ctx, tt.userID)
				assert.NoError(t, err)
				assert.Equal(t, tt.codes, savedCodes)
			}
		})
	}
}

func TestTOTPRepository_GetBackupCodes(t *testing.T) {
	// Setup
	repo := NewTOTPRepository(zap.NewNop())
	ctx := context.Background()

	// Insert test data
	userID := "user1"
	codes := []string{"ABCDEF1234", "GHIJKL5678"}
	err := repo.SaveBackupCodes(ctx, userID, codes)
	require.NoError(t, err)

	// Test cases
	tests := []struct {
		name      string
		userID    string
		want      []string
		wantError bool
	}{
		{
			name:      "Success",
			userID:    userID,
			want:      codes,
			wantError: false,
		},
		{
			name:      "User Not Found",
			userID:    "nonexistent",
			want:      nil,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Execute
			got, err := repo.GetBackupCodes(ctx, tt.userID)

			// Assert
			if tt.wantError {
				assert.Error(t, err)
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestTOTPRepository_MarkBackupCodeAsUsed(t *testing.T) {
	// Setup
	repo := NewTOTPRepository(zap.NewNop())
	ctx := context.Background()

	// Insert test data
	userID := "user1"
	codes := []string{"ABCDEF1234", "GHIJKL5678"}
	err := repo.SaveBackupCodes(ctx, userID, codes)
	require.NoError(t, err)

	// Test cases
	tests := []struct {
		name      string
		userID    string
		codeIndex int
		wantError bool
	}{
		{
			name:      "Success",
			userID:    userID,
			codeIndex: 0,
			wantError: false,
		},
		{
			name:      "User Not Found",
			userID:    "nonexistent",
			codeIndex: 0,
			wantError: true,
		},
		{
			name:      "Invalid Code Index",
			userID:    userID,
			codeIndex: 2,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Execute
			err := repo.MarkBackupCodeAsUsed(ctx, tt.userID, tt.codeIndex)

			// Assert
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify the code was marked as used
				savedCodes, err := repo.GetBackupCodes(ctx, tt.userID)
				assert.NoError(t, err)
				assert.Equal(t, "", savedCodes[tt.codeIndex]) // Code should be empty string
			}
		})
	}
}

func TestTOTPRepository_DeleteTOTPConfig(t *testing.T) {
	// Setup
	repo := NewTOTPRepository(zap.NewNop())
	ctx := context.Background()

	// Insert test data
	userID := "user1"
	secret := "JBSWY3DPEHPK3PXP"
	err := repo.SaveTOTPSecret(ctx, userID, secret)
	require.NoError(t, err)

	codes := []string{"ABCDEF1234", "GHIJKL5678"}
	err = repo.SaveBackupCodes(ctx, userID, codes)
	require.NoError(t, err)

	// Test cases
	tests := []struct {
		name      string
		userID    string
		wantError bool
	}{
		{
			name:      "Success",
			userID:    userID,
			wantError: false,
		},
		{
			name:      "User Not Found",
			userID:    "nonexistent",
			wantError: false, // No error when deleting non-existent config
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Execute
			err := repo.DeleteTOTPConfig(ctx, tt.userID)

			// Assert
			assert.NoError(t, err)

			// Verify the config was deleted
			secret, err := repo.GetTOTPSecret(ctx, tt.userID)
			assert.Error(t, err)
			assert.Empty(t, secret)

			codes, err := repo.GetBackupCodes(ctx, tt.userID)
			assert.Error(t, err)
			assert.Nil(t, codes)
		})
	}
}

func contains(slice []string, item string) bool {
	for _, i := range slice {
		if i == item {
			return true
		}
	}
	return false
}
