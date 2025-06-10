package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

// MockTOTPService is a mock implementation of the TOTP service
type MockTOTPService struct {
	mock.Mock
}

func (m *MockTOTPService) EnableTOTP(userID string) (*domain.TOTP, error) {
	args := m.Called(userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.TOTP), args.Error(1)
}

func (m *MockTOTPService) VerifyTOTP(userID, code string) error {
	args := m.Called(userID, code)
	return args.Error(0)
}

func (m *MockTOTPService) VerifyBackupCode(userID, code string) error {
	args := m.Called(userID, code)
	return args.Error(0)
}

func (m *MockTOTPService) DisableTOTP(userID string) error {
	args := m.Called(userID)
	return args.Error(0)
}

func (m *MockTOTPService) GetTOTPSecret(ctx context.Context, userID string) (string, error) {
	args := m.Called(ctx, userID)
	return args.String(0), args.Error(1)
}

func TestTOTPHandler_EnableTOTP(t *testing.T) {
	tests := []struct {
		name           string
		userID         string
		mockSetup      func(*MockTOTPService)
		expectedStatus int
		expectedBody   map[string]interface{}
	}{
		{
			name:   "Success",
			userID: "test-user",
			mockSetup: func(m *MockTOTPService) {
				m.On("EnableTOTP", "test-user").Return(
					&domain.TOTP{QRCode: "test-secret", BackupCodes: []string{"backup1", "backup2"}},
					nil,
				)
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"QRCode":      "test-secret",
				"BackupCodes": []string{"backup1", "backup2"},
			},
		},
		{
			name:   "Already Enabled",
			userID: "test-user",
			mockSetup: func(m *MockTOTPService) {
				m.On("EnableTOTP", "test-user").Return(
					nil,
					domain.ErrTOTPAlreadyEnabled,
				)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"code":    "U0046",
				"message": "TOTP is already enabled for this user",
			},
		},
		{
			name:   "Unauthorized",
			userID: "",
			mockSetup: func(m *MockTOTPService) {
				// No mock setup needed
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody: map[string]interface{}{
				"code":    "U0014",
				"message": "Unauthorized",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock service
			mockService := new(MockTOTPService)
			tt.mockSetup(mockService)

			// Create handler
			logger := zap.NewNop()
			handler := NewTOTPHandler(mockService, logger)

			// Create request
			req := httptest.NewRequest(http.MethodPost, "/totp/enable", nil)
			if tt.userID != "" {
				req = req.WithContext(context.WithValue(req.Context(), "sub", tt.userID))
			}

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			handler.EnableTOTP(w, req)

			// Assert response
			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)

			if codes, ok := response["BackupCodes"]; ok {
				// Convert []interface{} to []string for comparison
				actualCodes := make([]string, len(codes.([]interface{})))
				for i, v := range codes.([]interface{}) {
					actualCodes[i] = v.(string)
				}
				assert.ElementsMatch(t, tt.expectedBody["BackupCodes"].([]string), actualCodes)
				delete(response, "BackupCodes")
				delete(tt.expectedBody, "BackupCodes")
			}
			assert.Equal(t, tt.expectedBody, response)

			// Verify mock expectations
			mockService.AssertExpectations(t)
		})
	}
}

func TestTOTPHandler_VerifyTOTP(t *testing.T) {
	tests := []struct {
		name           string
		userID         string
		requestBody    map[string]interface{}
		mockSetup      func(*MockTOTPService)
		expectedStatus int
		expectedBody   map[string]interface{}
	}{
		{
			name:   "Success",
			userID: "test-user",
			requestBody: map[string]interface{}{
				"code": "123456",
			},
			mockSetup: func(m *MockTOTPService) {
				m.On("VerifyTOTP", "test-user", "123456").Return(nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"message": "TOTP code verified successfully",
			},
		},
		{
			name:   "Invalid Code",
			userID: "test-user",
			requestBody: map[string]interface{}{
				"code": "123456",
			},
			mockSetup: func(m *MockTOTPService) {
				m.On("VerifyTOTP", "test-user", "123456").Return(domain.ErrInvalidTOTPCode)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"code":    "U0047",
				"message": "Invalid TOTP code",
			},
		},
		{
			name:   "TOTP Not Enabled",
			userID: "test-user",
			requestBody: map[string]interface{}{
				"code": "123456",
			},
			mockSetup: func(m *MockTOTPService) {
				m.On("VerifyTOTP", "test-user", "123456").Return(domain.ErrTOTPNotEnabled)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"code":    "U0045",
				"message": "TOTP is not enabled for this user",
			},
		},
		{
			name:   "Missing Code",
			userID: "test-user",
			requestBody: map[string]interface{}{
				"code": "",
			},
			mockSetup: func(m *MockTOTPService) {
				// No mock setup needed
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"code":    "U0011",
				"message": "Invalid field",
			},
		},
		{
			name:   "Unauthorized",
			userID: "",
			requestBody: map[string]interface{}{
				"code": "123456",
			},
			mockSetup: func(m *MockTOTPService) {
				// No mock setup needed
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody: map[string]interface{}{
				"code":    "U0014",
				"message": "Unauthorized",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock service
			mockService := new(MockTOTPService)
			tt.mockSetup(mockService)

			// Create handler
			logger := zap.NewNop()
			handler := NewTOTPHandler(mockService, logger)

			// Create request body
			body, err := json.Marshal(tt.requestBody)
			assert.NoError(t, err)

			// Create request
			req := httptest.NewRequest(http.MethodPost, "/totp/verify", bytes.NewBuffer(body))
			if tt.userID != "" {
				req = req.WithContext(context.WithValue(req.Context(), "sub", tt.userID))
			}

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			handler.VerifyTOTP(w, req)

			// Assert response
			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedBody, response)

			// Verify mock expectations
			mockService.AssertExpectations(t)
		})
	}
}

func TestTOTPHandler_VerifyBackupCode(t *testing.T) {
	tests := []struct {
		name           string
		userID         string
		requestBody    map[string]interface{}
		mockSetup      func(*MockTOTPService)
		expectedStatus int
		expectedBody   map[string]interface{}
	}{
		{
			name:   "Success",
			userID: "test-user",
			requestBody: map[string]interface{}{
				"code": "BACKUP123",
			},
			mockSetup: func(m *MockTOTPService) {
				m.On("VerifyBackupCode", "test-user", "BACKUP123").Return(nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"message": "Backup code verified successfully",
			},
		},
		{
			name:   "Invalid Code",
			userID: "test-user",
			requestBody: map[string]interface{}{
				"code": "BACKUP123",
			},
			mockSetup: func(m *MockTOTPService) {
				m.On("VerifyBackupCode", "test-user", "BACKUP123").Return(domain.ErrInvalidTOTPBackupCode)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"code":    "U0051",
				"message": "Invalid TOTP backup code",
			},
		},
		{
			name:   "TOTP Not Enabled",
			userID: "test-user",
			requestBody: map[string]interface{}{
				"code": "BACKUP123",
			},
			mockSetup: func(m *MockTOTPService) {
				m.On("VerifyBackupCode", "test-user", "BACKUP123").Return(domain.ErrTOTPNotEnabled)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"code":    "U0045",
				"message": "TOTP is not enabled for this user",
			},
		},
		{
			name:   "Missing Code",
			userID: "test-user",
			requestBody: map[string]interface{}{
				"code": "",
			},
			mockSetup: func(m *MockTOTPService) {
				// No mock setup needed
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"code":    "U0011",
				"message": "Invalid field",
			},
		},
		{
			name:   "Unauthorized",
			userID: "",
			requestBody: map[string]interface{}{
				"code": "BACKUP123",
			},
			mockSetup: func(m *MockTOTPService) {
				// No mock setup needed
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody: map[string]interface{}{
				"code":    "U0014",
				"message": "Unauthorized",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock service
			mockService := new(MockTOTPService)
			tt.mockSetup(mockService)

			// Create handler
			logger := zap.NewNop()
			handler := NewTOTPHandler(mockService, logger)

			// Create request body
			body, err := json.Marshal(tt.requestBody)
			assert.NoError(t, err)

			// Create request
			req := httptest.NewRequest(http.MethodPost, "/totp/verify-backup", bytes.NewBuffer(body))
			if tt.userID != "" {
				req = req.WithContext(context.WithValue(req.Context(), "sub", tt.userID))
			}

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			handler.VerifyBackupCode(w, req)

			// Assert response
			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedBody, response)

			// Verify mock expectations
			mockService.AssertExpectations(t)
		})
	}
}

func TestTOTPHandler_DisableTOTP(t *testing.T) {
	tests := []struct {
		name           string
		userID         string
		mockSetup      func(*MockTOTPService)
		expectedStatus int
		expectedBody   map[string]interface{}
	}{
		{
			name:   "Success",
			userID: "test-user",
			mockSetup: func(m *MockTOTPService) {
				m.On("DisableTOTP", "test-user").Return(nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"message": "TOTP disabled successfully",
			},
		},
		{
			name:   "TOTP Not Enabled",
			userID: "test-user",
			mockSetup: func(m *MockTOTPService) {
				m.On("DisableTOTP", "test-user").Return(domain.ErrTOTPNotEnabled)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"code":    "U0045",
				"message": "TOTP is not enabled for this user",
			},
		},
		{
			name:   "Unauthorized",
			userID: "",
			mockSetup: func(m *MockTOTPService) {
				// No mock setup needed
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody: map[string]interface{}{
				"code":    "U0014",
				"message": "Unauthorized",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock service
			mockService := new(MockTOTPService)
			tt.mockSetup(mockService)

			// Create handler
			logger := zap.NewNop()
			handler := NewTOTPHandler(mockService, logger)

			// Create request
			req := httptest.NewRequest(http.MethodPost, "/totp/disable", nil)
			if tt.userID != "" {
				req = req.WithContext(context.WithValue(req.Context(), "sub", tt.userID))
			}

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			handler.DisableTOTP(w, req)

			// Assert response
			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedBody, response)

			// Verify mock expectations
			mockService.AssertExpectations(t)
		})
	}
}
