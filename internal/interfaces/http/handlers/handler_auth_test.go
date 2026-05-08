package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/infrastructure/config"
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
	args := m.Called(ctx, name, email, password, phone, roles)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *mockAuthService) Login(ctx context.Context, email, password, channel string) (interface{}, error) {
	args := m.Called(ctx, email, password, channel)
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

func (m *mockAuthService) RegisterClient(ctx context.Context, name, email, password, phone string) (*domain.User, error) {
	args := m.Called(ctx, name, email, password, phone)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *mockAuthService) RegisterManagementOwner(ctx context.Context, name, email, password, phone string) (*domain.User, error) {
	args := m.Called(ctx, name, email, password, phone)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *mockAuthService) CreateStandaloneUserByAdmin(ctx context.Context, name, email, password, phone string, channels, roles []string) (*domain.User, error) {
	args := m.Called(ctx, name, email, password, phone, channels, roles)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *mockAuthService) AssignRoleToStandalone(ctx context.Context, userID, role string) ([]string, error) {
	args := m.Called(ctx, userID, role)
	return args.Get(0).([]string), args.Error(1)
}

func (m *mockAuthService) RemoveRoleFromStandalone(ctx context.Context, userID, role string) ([]string, error) {
	args := m.Called(ctx, userID, role)
	return args.Get(0).([]string), args.Error(1)
}

func (m *mockAuthService) ListRolesByUser(ctx context.Context, userID string) ([]domain.RoleDefinition, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]domain.RoleDefinition), args.Error(1)
}

func (m *mockAuthService) CreateCustomRole(ctx context.Context, role string) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}

func (m *mockAuthService) DeleteCustomRole(ctx context.Context, role string) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}

func (m *mockAuthService) ListRoles(ctx context.Context) ([]domain.RoleDefinition, error) {
	args := m.Called(ctx)
	return args.Get(0).([]domain.RoleDefinition), args.Error(1)
}

func (m *mockAuthService) RenameCustomRole(ctx context.Context, fromName, toName string) error {
	args := m.Called(ctx, fromName, toName)
	return args.Error(0)
}

func (m *mockAuthService) RefreshWithRefreshToken(ctx context.Context, refreshToken string) (*domain.TokenPair, error) {
	args := m.Called(ctx, refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.TokenPair), args.Error(1)
}

func (m *mockAuthService) ResendVerificationEmail(ctx context.Context, email string) error {
	args := m.Called(ctx, email)
	return args.Error(0)
}

func (m *mockAuthService) LogoutWithRefreshToken(ctx context.Context, refreshToken string) error {
	args := m.Called(ctx, refreshToken)
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
				m.On("RegisterClient", mock.Anything, "John Doe", "john@example.com", "password123", "1234567890").Return(&domain.User{
					ID:            ulid.Make(),
					Name:          "John Doe",
					Email:         "john@example.com",
					Phone:         "1234567890",
					UserType:      domain.UserTypeClient,
					Channels:      []string{domain.ChannelClientApp},
					Roles:         []string{domain.RoleUser},
					EmailVerified: false,
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
				m.On("RegisterClient", mock.Anything, "John Doe", "john@example.com", "password123", "1234567890").Return(nil, domain.ErrAlreadyExists("User"))
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
			testCfg := &config.Config{JWTRefreshDuration: 24 * time.Hour}
			handler := NewAuthHandler(mockService, testCfg, zap.NewNop())

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
			handler.RegisterClientHandler(w, req)

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
				assert.Equal(t, "client", responseMap["user_type"])
				assert.Equal(t, "email_verify", responseMap["status"])
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
	testCfg := &config.Config{JWTRefreshDuration: 24 * time.Hour}
	handler := NewAuthHandler(mockService, testCfg, logger)

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
				"channel":  "management_panel",
			},
			mockSetup: func() {
				mockService.On("Login", mock.Anything, "test@example.com", "password123", "management_panel").
					Return(
						&domain.TokenPair{
							AccessToken:  "access_token",
							RefreshToken: "refresh_token",
						},
						nil,
					)
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]string{
				"access_token": "access_token",
			},
		},
		{
			name: "invalid credentials",
			requestBody: map[string]string{
				"email":    "test@example.com",
				"password": "wrongpassword",
				"channel":  "management_panel",
			},
			mockSetup: func() {
				mockService.On("Login", mock.Anything, "test@example.com", "wrongpassword", "management_panel").
					Return(nil, domain.ErrAuthInvalidCredentials)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: errors.ErrorResponse{
				Code:    domain.ErrAuthInvalidCredentials.GetCode(),
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
			name: "successful login without channel defaults to management panel",
			requestBody: map[string]string{
				"email":    "test@example.com",
				"password": "password123",
			},
			mockSetup: func() {
				mockService.On("Login", mock.Anything, "test@example.com", "password123", "").
					Return(
						&domain.TokenPair{
							AccessToken:  "access_token",
							RefreshToken: "refresh_token",
						},
						nil,
					)
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]string{
				"access_token": "access_token",
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
				var response map[string]string
				err := json.NewDecoder(rr.Body).Decode(&response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedBody.(map[string]string), response)
				var refresh *http.Cookie
				for _, c := range rr.Result().Cookies() {
					if c.Name == refreshTokenCookieName {
						refresh = c
						break
					}
				}
				assert.NotNil(t, refresh)
				assert.Equal(t, "refresh_token", refresh.Value)
				assert.True(t, refresh.HttpOnly)
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

func TestAuthHandler_Logout(t *testing.T) {
	logger := zap.NewNop()
	mockService := new(mockAuthService)
	testCfg := &config.Config{JWTRefreshDuration: 24 * time.Hour}
	handler := NewAuthHandler(mockService, testCfg, logger)

	t.Run("logout with refresh cookie", func(t *testing.T) {
		mockService.On("LogoutWithRefreshToken", mock.Anything, "refresh_token").Return(nil).Once()

		req := httptest.NewRequest(http.MethodPost, "/auth/logout", bytes.NewBuffer(nil))
		req.AddCookie(&http.Cookie{Name: refreshTokenCookieName, Value: "refresh_token"})
		rr := httptest.NewRecorder()

		handler.LogoutHandler(rr, req)

		assert.Equal(t, http.StatusNoContent, rr.Code)
		var cleared *http.Cookie
		for _, c := range rr.Result().Cookies() {
			if c.Name == refreshTokenCookieName {
				cleared = c
				break
			}
		}
		assert.NotNil(t, cleared)
		assert.Equal(t, "", cleared.Value)
		assert.Equal(t, -1, cleared.MaxAge)
	})

	t.Run("missing refresh token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/logout", bytes.NewBuffer(nil))
		rr := httptest.NewRecorder()

		handler.LogoutHandler(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		var response errors.ErrorResponse
		err := json.NewDecoder(rr.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, domain.ErrInvalidRequestBody.GetCode(), response.Code)
	})

	mockService.AssertExpectations(t)
}
