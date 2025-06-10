package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/interfaces/http/errors"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

type mockAuthService struct {
	mock.Mock
}

func (m *mockAuthService) Register(ctx context.Context, name, email, password, phone string, roles []string) (*domain.User, error) {
	args := m.Called(ctx, name, email, password, phone)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *mockAuthService) Login(ctx context.Context, email, password string) (interface{}, error) {
	args := m.Called(ctx, email, password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0), args.Error(1)
}

func (m *mockAuthService) VerifyMFA(ctx context.Context, ticketID, code string) (*domain.TokenPair, error) {
	args := m.Called(ctx, ticketID, code)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.TokenPair), args.Error(1)
}

func (m *mockAuthService) VerifyEmail(ctx context.Context, email, code string) error {
	args := m.Called(ctx, email, code)
	return args.Error(0)
}

func (m *mockAuthService) RequestPasswordReset(ctx context.Context, email string) error {
	args := m.Called(ctx, email)
	return args.Error(0)
}

func (m *mockAuthService) ResetPassword(ctx context.Context, email, code, newPassword string) error {
	args := m.Called(ctx, email, code, newPassword)
	return args.Error(0)
}

func TestAuthHandler_Register(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		mockSetup      func(*mockAuthService)
		expectedStatus int
		expectedBody   interface{}
	}{
		{
			name: "successful registration",
			requestBody: map[string]interface{}{
				"name":     "John Doe",
				"email":    "john@example.com",
				"password": "password123",
				"phone":    "1234567890",
			},
			mockSetup: func(m *mockAuthService) {
				m.On("Register", mock.Anything, "John Doe", "john@example.com", "password123", "1234567890").Return(&domain.User{
					ID:    ulid.Make(),
					Name:  "John Doe",
					Email: "john@example.com",
					Phone: "1234567890",
				}, nil)
			},
			expectedStatus: http.StatusCreated,
			expectedBody: map[string]interface{}{
				"id":    ulid.Make().String(),
				"name":  "John Doe",
				"email": "john@example.com",
				"phone": "1234567890",
			},
		},
		{
			name: "user already exists",
			requestBody: map[string]interface{}{
				"name":     "John Doe",
				"email":    "john@example.com",
				"password": "password123",
				"phone":    "1234567890",
			},
			mockSetup: func(m *mockAuthService) {
				m.On("Register", mock.Anything, "John Doe", "john@example.com", "password123", "1234567890").Return(nil, domain.ErrAlreadyExists("User"))
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: errors.ErrorResponse{
				Code:    "U0009",
				Message: "User already exists",
			},
		},
		{
			name: "validation error - missing required fields",
			requestBody: map[string]interface{}{
				"name":  "John Doe",
				"phone": "1234567890",
				// missing email and password
			},
			mockSetup: func(m *mockAuthService) {
				// No mock setup needed for validation errors
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: errors.ErrorResponse{
				Code:    "U0011",
				Message: "Invalid field",
				Details: []errors.ErrorDetail{
					{
						Field:   "email",
						Message: "email is required",
					},
					{
						Field:   "password",
						Message: "password is required",
					},
				},
			},
		},
		{
			name:        "invalid request body",
			requestBody: "invalid json",
			mockSetup: func(m *mockAuthService) {
				// No mock setup needed for invalid request body
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: errors.ErrorResponse{
				Code:    "U0013",
				Message: "Invalid request body",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock service
			mockService := new(mockAuthService)
			tt.mockSetup(mockService)

			// Create handler with mock service
			handler := NewAuthHandler(mockService, zap.NewNop())

			// Create test request
			var body []byte
			if str, ok := tt.requestBody.(string); ok {
				body = []byte(str)
			} else {
				body, _ = json.Marshal(tt.requestBody)
			}
			req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
			w := httptest.NewRecorder()

			// Call handler
			handler.RegisterHandler(w, req)

			// Assert response
			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedStatus == http.StatusCreated {
				var responseMap map[string]interface{}
				err := json.NewDecoder(w.Body).Decode(&responseMap)
				assert.NoError(t, err)
				assert.Equal(t, "John Doe", responseMap["name"])
				assert.Equal(t, "john@example.com", responseMap["email"])
				assert.Equal(t, "1234567890", responseMap["phone"])
				assert.NotEmpty(t, responseMap["id"])
			} else {
				var response errors.ErrorResponse
				err := json.NewDecoder(w.Body).Decode(&response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedBody, response)
			}

			// Verify mock expectations
			mockService.AssertExpectations(t)
		})
	}
}

func TestAuthHandler_Login(t *testing.T) {
	logger, _ := zap.NewProduction()
	mockService := new(mockAuthService)
	handler := NewAuthHandler(mockService, logger)

	tests := []struct {
		name           string
		requestBody    interface{}
		mockSetup      func()
		expectedStatus int
		expectedBody   interface{}
	}{
		{
			name: "successful login",
			requestBody: map[string]string{
				"email":    "test@example.com",
				"password": "password123",
			},
			mockSetup: func() {
				mockService.On("Login", mock.Anything, "test@example.com", "password123").
					Return(
						&domain.TokenPair{
							AccessToken:  "access_token",
							RefreshToken: "refresh_token",
						},
						nil,
					)
			},
			expectedStatus: http.StatusOK,
			expectedBody: &domain.TokenPair{
				AccessToken:  "access_token",
				RefreshToken: "refresh_token",
			},
		},
		{
			name: "invalid credentials",
			requestBody: map[string]string{
				"email":    "test@example.com",
				"password": "wrongpassword",
			},
			mockSetup: func() {
				mockService.On("Login", mock.Anything, "test@example.com", "wrongpassword").
					Return(nil, domain.ErrInvalidCredentials)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: errors.ErrorResponse{
				Code:    "U0001",
				Message: "Invalid credentials",
			},
		},
		{
			name: "validation error - missing required fields",
			requestBody: map[string]string{
				"email": "test@example.com",
				// missing password
			},
			mockSetup: func() {
				// No mock setup needed for validation errors
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: errors.ErrorResponse{
				Code:    "U0011",
				Message: "Invalid field",
				Details: []errors.ErrorDetail{
					{
						Field:   "password",
						Message: "password is required",
					},
				},
			},
		},
		{
			name:        "invalid request body",
			requestBody: "invalid json",
			mockSetup: func() {
				// No mock setup needed for invalid request body
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: errors.ErrorResponse{
				Code:    "U0013",
				Message: "Invalid request body",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockSetup()

			var body []byte
			if str, ok := tt.requestBody.(string); ok {
				body = []byte(str)
			} else {
				body, _ = json.Marshal(tt.requestBody)
			}

			req := httptest.NewRequest("POST", "/users/login", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler.LoginHandler(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedStatus == http.StatusOK {
				var response domain.TokenPair
				err := json.NewDecoder(rr.Body).Decode(&response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedBody.(*domain.TokenPair), &response)
			} else {
				var response errors.ErrorResponse
				err := json.NewDecoder(rr.Body).Decode(&response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedBody.(errors.ErrorResponse), response)
			}

			mockService.AssertExpectations(t)
		})
	}
}
