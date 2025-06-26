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

func TestAuthHandler_VerifyMFA(t *testing.T) {
	logger, _ := zap.NewProduction()
	// refreshTokenDuration está fixo no construtor do handler por enquanto.
	// Os testes refletirão isso.

	tests := []struct {
		name            string
		requestBody     interface{}
		mockSetup       func(m *mockAuthService)
		expectedStatus  int
		expectedBody    interface{} // Pode ser LoginResponsePayload ou errors.ErrorResponse
		expectCookie    bool
		expectedCookie  *http.Cookie       // Para verificar Nome, HttpOnly, Secure, Path, SameSite
		expectedTokenFn func() *domain.TokenPair // Para obter o refresh_token esperado para o cookie
	}{
		{
			name: "successful MFA verification",
			requestBody: map[string]string{
				"ticket": "valid_ticket",
				"code":   "123456",
			},
			mockSetup: func(m *mockAuthService) {
				m.On("VerifyMFA", mock.Anything, "valid_ticket", "123456").
					Return(
						&domain.TokenPair{
							AccessToken:  "mfa_access_token",
							RefreshToken: "mfa_refresh_token",
						},
						nil,
					)
			},
			expectedStatus: http.StatusOK,
			expectedBody: LoginResponsePayload{
				AccessToken: "mfa_access_token",
			},
			expectCookie: true,
			expectedCookie: &http.Cookie{
				Name:     "refresh_token",
				HttpOnly: true,
				Secure:   true,
				Path:     "/",
				SameSite: http.SameSiteStrictMode,
			},
			expectedTokenFn: func() *domain.TokenPair {
				return &domain.TokenPair{
					AccessToken:  "mfa_access_token",
					RefreshToken: "mfa_refresh_token",
				}
			},
		},
		{
			name: "invalid MFA code",
			requestBody: map[string]string{
				"ticket": "valid_ticket",
				"code":   "wrong_code",
			},
			mockSetup: func(m *mockAuthService) {
				m.On("VerifyMFA", mock.Anything, "valid_ticket", "wrong_code").
					Return(nil, domain.ErrInvalidTOTPCode) // Exemplo de erro
			},
			expectedStatus: http.StatusBadRequest, // Ou o status que ErrInvalidTOTPCode mapeia
			expectedBody: errors.ErrorResponse{ // Ajustar conforme o erro real
				Code:    "A0005", // Supondo que ErrInvalidTOTPCode mapeie para este
				Message: "Invalid TOTP code",
			},
			expectCookie: false,
		},
		{
			name: "validation error - missing ticket",
			requestBody: map[string]string{
				"code": "123456",
			},
			mockSetup: func(m *mockAuthService) {
				// Nenhuma chamada ao serviço esperada
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: errors.ErrorResponse{
				Code:    "U0011",
				Message: "Invalid field",
				Details: []errors.ErrorDetail{
					{Field: "ticket", Message: "ticket is required"},
				},
			},
			expectCookie: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(mockAuthService)
			tt.mockSetup(mockService)
			currentHandler := NewAuthHandler(mockService, logger)

			bodyBytes, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/mfa/verify", bytes.NewBuffer(bodyBytes))
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			currentHandler.VerifyMFAHandler(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code, "Status code mismatch")

			if tt.expectedStatus == http.StatusOK {
				var responseBody LoginResponsePayload
				err := json.NewDecoder(rr.Body).Decode(&responseBody)
				assert.NoError(t, err, "Failed to decode response body for successful MFA verification")
				assert.Equal(t, tt.expectedBody.(LoginResponsePayload).AccessToken, responseBody.AccessToken)

				assert.True(t, tt.expectCookie, "Cookie was expected but not set as per test config")
				cookies := rr.Result().Cookies()
				assert.NotEmpty(t, cookies, "No cookies were set for successful MFA verification")

				foundCookie := false
				for _, cookie := range cookies {
					if cookie.Name == tt.expectedCookie.Name {
						foundCookie = true
						assert.Equal(t, tt.expectedTokenFn().RefreshToken, cookie.Value, "Cookie refresh token value mismatch")
						assert.Equal(t, tt.expectedCookie.HttpOnly, cookie.HttpOnly, "Cookie HttpOnly flag mismatch")
						assert.Equal(t, tt.expectedCookie.Secure, cookie.Secure, "Cookie Secure flag mismatch")
						assert.Equal(t, tt.expectedCookie.Path, cookie.Path, "Cookie Path mismatch")
						assert.Equal(t, tt.expectedCookie.SameSite, cookie.SameSite, "Cookie SameSite mismatch")
						assert.True(t, cookie.Expires.After(time.Now()), "Cookie expiration should be in the future")
						break
					}
				}
				assert.True(t, foundCookie, "Refresh token cookie was not found")

			} else { // Error status codes
				var errorResponse errors.ErrorResponse
				err := json.NewDecoder(rr.Body).Decode(&errorResponse)
				assert.NoError(t, err, "Failed to decode error response body")
				assert.Equal(t, tt.expectedBody.(errors.ErrorResponse), errorResponse, "Error response body mismatch")
				assert.Empty(t, rr.Result().Cookies(), "No cookies should be set on error")
			}
			mockService.AssertExpectations(t)
		})
	}
}

func TestAuthHandler_Login(t *testing.T) {
	logger, _ := zap.NewProduction()
	// Criar o handler com a duração do token de atualização (mesmo que fixo por enquanto no handler real)
	// Idealmente, o mock do config seria injetado aqui também.
	handler := NewAuthHandler(new(mockAuthService), logger) // mockAuthService será re-instanciado por teste

	tests := []struct {
		name            string
		requestBody     interface{}
		mockSetup       func(m *mockAuthService)
		expectedStatus  int
		expectedBody    interface{}
		expectCookie    bool
		expectedCookie  *http.Cookie // Para verificar nome, HttpOnly, Secure, Path, SameSite. Valor e Expires são verificados separadamente.
		expectedTokenFn func() *domain.TokenPair // Função para obter o token pair esperado para o cookie
	}{
		{
			name: "successful login",
			requestBody: map[string]string{
				"email":    "test@example.com",
				"password": "password123",
			},
			mockSetup: func(m *mockAuthService) {
				m.On("Login", mock.Anything, "test@example.com", "password123").
					Return(
						&domain.TokenPair{
							AccessToken:  "test_access_token",
							RefreshToken: "test_refresh_token",
						},
						nil,
					)
			},
			expectedStatus: http.StatusOK,
			expectedBody: LoginResponsePayload{
				AccessToken: "test_access_token",
			},
			expectCookie: true,
			expectedCookie: &http.Cookie{
				Name:     "refresh_token",
				HttpOnly: true,
				Secure:   true,
				Path:     "/",
				SameSite: http.SameSiteStrictMode,
			},
			expectedTokenFn: func() *domain.TokenPair {
				return &domain.TokenPair{
					AccessToken:  "test_access_token",
					RefreshToken: "test_refresh_token",
				}
			},
		},
		{
			name: "invalid credentials",
			requestBody: map[string]string{
				"email":    "test@example.com",
				"password": "wrongpassword",
			},
			mockSetup: func(m *mockAuthService) {
				m.On("Login", mock.Anything, "test@example.com", "wrongpassword").
					Return(nil, domain.ErrInvalidCredentials)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: errors.ErrorResponse{
				Code:    "U0001",
				Message: "Invalid credentials",
			},
			expectCookie: false,
		},
		{
			name: "validation error - missing required fields",
			requestBody: map[string]string{
				"email": "test@example.com",
				// missing password
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
						Field:   "password",
						Message: "password is required",
					},
				},
			},
			expectCookie: false,
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
			expectCookie: false,
		},
		{
			name: "login returns MFA ticket",
			requestBody: map[string]string{
				"email":    "mfa_user@example.com",
				"password": "password123",
			},
			mockSetup: func(m *mockAuthService) {
				// Use a fixed ULID for predictable test output if needed, or allow any ULID.
				// For this test, we'll check User field and that Ticket is not empty.
				m.On("Login", mock.Anything, "mfa_user@example.com", "password123").
					Return(
						&domain.MFATicket{Ticket: ulid.Make(), User: "user_mfa_test_id"},
						nil,
					)
			},
			expectedStatus: http.StatusOK,
			// For MFATicket, we will verify the type and a specific field, not the exact body due to ULID.
			expectedBody:   &domain.MFATicket{User: "user_mfa_test_id"},
			expectCookie:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(mockAuthService) // Create a new mock for each test run
			tt.mockSetup(mockService)

			// Create handler with the fresh mockService
			// Note: refreshTokenDuration in the actual handler is hardcoded for now.
			// This test setup correctly reflects that the handler itself would have this duration.
			currentHandler := NewAuthHandler(mockService, logger)

			var bodyBytes []byte
			if str, ok := tt.requestBody.(string); ok {
				bodyBytes = []byte(str)
			} else {
				bodyBytes, _ = json.Marshal(tt.requestBody)
			}

			req := httptest.NewRequest("POST", "/users/login", bytes.NewBuffer(bodyBytes))
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			currentHandler.LoginHandler(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedStatus == http.StatusOK {
				if tt.expectCookie {
					var responseBody LoginResponsePayload
					err := json.NewDecoder(rr.Body).Decode(&responseBody)
					assert.NoError(t, err, "Failed to decode response body for successful login")
					assert.Equal(t, tt.expectedBody.(LoginResponsePayload).AccessToken, responseBody.AccessToken)

					cookies := rr.Result().Cookies()
					assert.NotEmpty(t, cookies, "No cookies were set for successful login")

					foundCookie := false
					for _, cookie := range cookies {
						if cookie.Name == tt.expectedCookie.Name {
							foundCookie = true
							assert.Equal(t, tt.expectedTokenFn().RefreshToken, cookie.Value, "Cookie refresh token value mismatch")
							assert.Equal(t, tt.expectedCookie.HttpOnly, cookie.HttpOnly, "Cookie HttpOnly flag mismatch")
							assert.Equal(t, tt.expectedCookie.Secure, cookie.Secure, "Cookie Secure flag mismatch")
							assert.Equal(t, tt.expectedCookie.Path, cookie.Path, "Cookie Path mismatch")
							assert.Equal(t, tt.expectedCookie.SameSite, cookie.SameSite, "Cookie SameSite mismatch")
							assert.True(t, cookie.Expires.After(time.Now()), "Cookie expiration should be in the future")
							// Consider a more precise check for Expires if refreshTokenDuration was injected and mockable
							break
						}
					}
					assert.True(t, foundCookie, "Refresh token cookie was not found")

				} else if expectedMfaTicket, ok := tt.expectedBody.(*domain.MFATicket); ok {
					var responseMFATicket domain.MFATicket
					err := json.NewDecoder(rr.Body).Decode(&responseMFATicket)
					assert.NoError(t, err, "Failed to decode MFA ticket response body")
					assert.NotEmpty(t, responseMFATicket.Ticket, "MFA Ticket ID should not be empty")
					assert.Equal(t, expectedMfaTicket.User, responseMFATicket.User, "MFA Ticket User mismatch")
				}

			} else { // Error status codes
				var errorResponse errors.ErrorResponse
				err := json.NewDecoder(rr.Body).Decode(&errorResponse)
				assert.NoError(t, err, "Failed to decode error response body")

				// For validation errors, details can have a variable order or content.
				// A more robust check might involve comparing elements specifically.
				// For now, direct comparison is used as in the original test.
				assert.Equal(t, tt.expectedBody.(errors.ErrorResponse), errorResponse, "Error response body mismatch")
				assert.Empty(t, rr.Result().Cookies(), "No cookies should be set on error")
			}

			mockService.AssertExpectations(t)
		})
	}
}
