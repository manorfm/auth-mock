package application

import (
	"context"
	"testing"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

// MockTOTPRepository is a mock implementation of TOTPRepository
type MockTOTPRepository struct {
	mock.Mock
}

func (m *MockTOTPRepository) SaveTOTPSecret(ctx context.Context, userID string, secret string) error {
	args := m.Called(ctx, userID, secret)
	return args.Error(0)
}

func (m *MockTOTPRepository) GetTOTPSecret(ctx context.Context, userID string) (string, error) {
	args := m.Called(ctx, userID)
	return args.String(0), args.Error(1)
}

func (m *MockTOTPRepository) SaveBackupCodes(ctx context.Context, userID string, codes []string) error {
	args := m.Called(ctx, userID, codes)
	return args.Error(0)
}

func (m *MockTOTPRepository) GetBackupCodes(ctx context.Context, userID string) ([]string, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockTOTPRepository) MarkBackupCodeAsUsed(ctx context.Context, userID string, codeIndex int) error {
	args := m.Called(ctx, userID, codeIndex)
	return args.Error(0)
}

func (m *MockTOTPRepository) DeleteTOTPConfig(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

// MockTOTPGenerator is a mock implementation of TOTPGenerator
type MockTOTPGenerator struct {
	mock.Mock
}

func (m *MockTOTPGenerator) GenerateSecret() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *MockTOTPGenerator) GenerateQRCode(config *domain.TOTPConfig) (string, error) {
	args := m.Called(config)
	return args.String(0), args.Error(1)
}

func (m *MockTOTPGenerator) GenerateBackupCodes(count int) ([]string, error) {
	args := m.Called(count)
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockTOTPGenerator) ValidateCode(secret string, code string) error {
	args := m.Called(secret, code)
	return args.Error(0)
}

func (m *MockTOTPGenerator) ValidateBackupCode(backupCodes []string, code string) (int, error) {
	args := m.Called(backupCodes, code)
	return args.Int(0), args.Error(1)
}

func TestTOTPService_EnableTOTP(t *testing.T) {
	// Setup
	logger := zap.NewNop()
	mockRepo := new(MockTOTPRepository)
	mockGenerator := new(MockTOTPGenerator)
	service := NewTOTPService(mockRepo, mockGenerator, logger)

	tests := []struct {
		name          string
		userID        string
		setupMocks    func()
		expectedError error
	}{
		{
			name:   "Success",
			userID: "user1",
			setupMocks: func() {
				mockRepo.On("GetTOTPSecret", mock.Anything, "user1").Return("", domain.ErrTOTPNotEnabled)
				mockGenerator.On("GenerateSecret").Return("secret", nil)
				mockGenerator.On("GenerateBackupCodes", 10).Return([]string{"code1", "code2"}, nil)
				mockRepo.On("SaveTOTPSecret", mock.Anything, "user1", "secret").Return(nil)
				mockRepo.On("SaveBackupCodes", mock.Anything, "user1", []string{"code1", "code2"}).Return(nil)
				mockGenerator.On("GenerateQRCode", mock.AnythingOfType("*domain.TOTPConfig")).Return("secret", nil)
			},
			expectedError: nil,
		},
		{
			name:   "Already Enabled",
			userID: "user1",
			setupMocks: func() {
				mockRepo.On("GetTOTPSecret", mock.Anything, "user1").Return("secret", nil)
			},
			expectedError: domain.ErrTOTPAlreadyEnabled,
		},
		{
			name:   "Secret Generation Failed",
			userID: "user1",
			setupMocks: func() {
				mockRepo.On("GetTOTPSecret", mock.Anything, "user1").Return("", domain.ErrTOTPNotEnabled)
				mockGenerator.On("GenerateSecret").Return("", domain.ErrTOTPSecretGeneration)
			},
			expectedError: domain.ErrTOTPSecretGeneration,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			mockRepo.ExpectedCalls = nil
			mockGenerator.ExpectedCalls = nil
			tt.setupMocks()

			// Execute
			totp, err := service.EnableTOTP(tt.userID)

			// Assert
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err)
				if totp != nil {
					assert.Nil(t, totp.QRCode)
					assert.Len(t, totp.BackupCodes, 0)
				} else {
					assert.Nil(t, totp)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, totp.QRCode)
				assert.NotNil(t, totp.BackupCodes)
				assert.Equal(t, "secret", totp.QRCode)
				assert.Len(t, totp.BackupCodes, 2)
			}

			// Verify mocks
			mockRepo.AssertExpectations(t)
			mockGenerator.AssertExpectations(t)
		})
	}
}

func TestTOTPService_VerifyTOTP(t *testing.T) {
	// Setup
	logger := zap.NewNop()
	mockRepo := new(MockTOTPRepository)
	mockGenerator := new(MockTOTPGenerator)
	service := NewTOTPService(mockRepo, mockGenerator, logger)

	tests := []struct {
		name          string
		userID        string
		code          string
		setupMocks    func()
		expectedError error
	}{
		{
			name:   "Success",
			userID: "user1",
			code:   "123456",
			setupMocks: func() {
				mockRepo.On("GetTOTPSecret", mock.Anything, "user1").Return("secret", nil)
				mockGenerator.On("ValidateCode", "secret", "123456").Return(nil)
			},
			expectedError: nil,
		},
		{
			name:   "Not Enabled",
			userID: "user1",
			code:   "123456",
			setupMocks: func() {
				mockRepo.On("GetTOTPSecret", mock.Anything, "user1").Return("", domain.ErrTOTPNotEnabled)
			},
			expectedError: domain.ErrTOTPNotEnabled,
		},
		{
			name:   "Invalid Code",
			userID: "user1",
			code:   "123456",
			setupMocks: func() {
				mockRepo.On("GetTOTPSecret", mock.Anything, "user1").Return("secret", nil)
				mockGenerator.On("ValidateCode", "secret", "123456").Return(domain.ErrInvalidTOTPCode)
			},
			expectedError: domain.ErrInvalidTOTPCode,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			mockRepo.ExpectedCalls = nil
			mockGenerator.ExpectedCalls = nil
			tt.setupMocks()

			// Execute
			err := service.VerifyTOTP(tt.userID, tt.code)

			// Assert
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err)
			} else {
				assert.NoError(t, err)
			}

			// Verify mocks
			mockRepo.AssertExpectations(t)
			mockGenerator.AssertExpectations(t)
		})
	}
}

func TestTOTPService_VerifyBackupCode(t *testing.T) {
	// Setup
	logger := zap.NewNop()
	mockRepo := new(MockTOTPRepository)
	mockGenerator := new(MockTOTPGenerator)
	service := NewTOTPService(mockRepo, mockGenerator, logger)

	tests := []struct {
		name          string
		userID        string
		code          string
		setupMocks    func()
		expectedError error
	}{
		{
			name:   "Success",
			userID: "user1",
			code:   "code1",
			setupMocks: func() {
				mockRepo.On("GetBackupCodes", mock.Anything, "user1").Return([]string{"code1", "code2"}, nil)
				mockGenerator.On("ValidateBackupCode", []string{"code1", "code2"}, "code1").Return(0, nil)
				mockRepo.On("MarkBackupCodeAsUsed", mock.Anything, "user1", 0).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:   "Not Enabled",
			userID: "user1",
			code:   "code1",
			setupMocks: func() {
				mockRepo.On("GetBackupCodes", mock.Anything, "user1").Return([]string{}, domain.ErrTOTPNotEnabled)
			},
			expectedError: domain.ErrTOTPNotEnabled,
		},
		{
			name:   "Invalid Code",
			userID: "user1",
			code:   "invalid",
			setupMocks: func() {
				mockRepo.On("GetBackupCodes", mock.Anything, "user1").Return([]string{"code1", "code2"}, nil)
				mockGenerator.On("ValidateBackupCode", []string{"code1", "code2"}, "invalid").Return(-1, domain.ErrInvalidTOTPBackupCode)
			},
			expectedError: domain.ErrInvalidTOTPBackupCode,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			mockRepo.ExpectedCalls = nil
			mockGenerator.ExpectedCalls = nil
			tt.setupMocks()

			// Execute
			err := service.VerifyBackupCode(tt.userID, tt.code)

			// Assert
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err)
			} else {
				assert.NoError(t, err)
			}

			// Verify mocks
			mockRepo.AssertExpectations(t)
			mockGenerator.AssertExpectations(t)
		})
	}
}

func TestTOTPService_DisableTOTP(t *testing.T) {
	// Setup
	logger := zap.NewNop()
	mockRepo := new(MockTOTPRepository)
	mockGenerator := new(MockTOTPGenerator)
	service := NewTOTPService(mockRepo, mockGenerator, logger)

	tests := []struct {
		name          string
		userID        string
		setupMocks    func()
		expectedError error
	}{
		{
			name:   "Success",
			userID: "user1",
			setupMocks: func() {
				mockRepo.On("GetTOTPSecret", mock.Anything, "user1").Return("secret", nil)
				mockRepo.On("DeleteTOTPConfig", mock.Anything, "user1").Return(nil)
			},
			expectedError: nil,
		},
		{
			name:   "Not Enabled",
			userID: "user1",
			setupMocks: func() {
				mockRepo.On("GetTOTPSecret", mock.Anything, "user1").Return("", domain.ErrTOTPNotEnabled)
			},
			expectedError: domain.ErrTOTPNotEnabled,
		},
		{
			name:   "Delete Failed",
			userID: "user1",
			setupMocks: func() {
				mockRepo.On("GetTOTPSecret", mock.Anything, "user1").Return("secret", nil)
				mockRepo.On("DeleteTOTPConfig", mock.Anything, "user1").Return(domain.ErrInternal)
			},
			expectedError: domain.ErrInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			mockRepo.ExpectedCalls = nil
			mockGenerator.ExpectedCalls = nil
			tt.setupMocks()

			// Execute
			err := service.DisableTOTP(tt.userID)

			// Assert
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err)
			} else {
				assert.NoError(t, err)
			}

			// Verify mocks
			mockRepo.AssertExpectations(t)
		})
	}
}
