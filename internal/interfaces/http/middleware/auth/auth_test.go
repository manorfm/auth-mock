package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
	"github.com/manorfm/auth-mock/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

type MockJWT struct {
	mock.Mock
}

func (m *MockJWT) GenerateTokenPair(ctx context.Context, user *domain.User) (*domain.TokenPair, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.TokenPair), args.Error(1)
}

func (m *MockJWT) ValidateToken(token string) (*domain.Claims, error) {
	args := m.Called(token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Claims), args.Error(1)
}

func (m *MockJWT) GetJWKS(ctx context.Context) (map[string]interface{}, error) {
	args := m.Called(ctx)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockJWT) GetPublicKey() *rsa.PublicKey {
	return nil
}

func (m *MockJWT) BlacklistToken(tokenID string, expiresAt time.Time) error {
	args := m.Called(tokenID, expiresAt)
	return args.Error(0)
}

func (m *MockJWT) IsTokenBlacklisted(tokenID string) bool {
	args := m.Called(tokenID)
	return args.Bool(0)
}

func (m *MockJWT) RotateKeys() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockJWT) GetLastRotation() time.Time {
	args := m.Called()
	return args.Get(0).(time.Time)
}

func (m *MockJWT) GetAccessDuration() time.Duration {
	args := m.Called()
	return args.Get(0).(time.Duration)
}

func TestAuthMiddleware_Authenticator(t *testing.T) {
	tests := []struct {
		name           string
		token          string
		mockSetup      func(*MockJWT)
		expectedStatus int
		expectedBody   string
	}{
		{
			name:  "missing token",
			token: "",
			mockSetup: func(m *MockJWT) {
				// No setup needed
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `{"code":"U0014","message":"Unauthorized"}`,
		},
		{
			name:  "invalid token",
			token: "invalid-token",
			mockSetup: func(m *MockJWT) {
				m.On("ValidateToken", "invalid-token").Return(nil, domain.ErrInvalidToken)
			},
			expectedStatus: http.StatusForbidden,
			expectedBody:   `{"code":"U0019","message":"Invalid token"}`,
		},
		{
			name:  "valid token",
			token: "valid-token",
			mockSetup: func(m *MockJWT) {
				claims := &domain.Claims{
					RegisteredClaims: &jwt.RegisteredClaims{
						Subject: "test-user",
					},
					Roles: []string{"admin"},
				}
				m.On("ValidateToken", "valid-token").Return(claims, nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody:   `{"message":"success"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockJWT := new(MockJWT)
			tt.mockSetup(mockJWT)

			middleware := NewAuthMiddleware(mockJWT, zap.NewNop())

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"message":"success"}`))
			})

			req := httptest.NewRequest("GET", "/", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}

			w := httptest.NewRecorder()
			middleware.Authenticator(handler).ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.JSONEq(t, tt.expectedBody, w.Body.String())
		})
	}
}

func TestAuthMiddleware_RequireRole(t *testing.T) {
	logger := zap.NewNop()
	tests := []struct {
		name           string
		requiredRole   string
		userRoles      []string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "no roles in context",
			requiredRole:   "admin",
			userRoles:      nil,
			expectedStatus: http.StatusForbidden,
			expectedBody:   `{"code":"U0018","message":"Forbidden"}`,
		},
		{
			name:           "role not found",
			requiredRole:   "admin",
			userRoles:      []string{"user"},
			expectedStatus: http.StatusForbidden,
			expectedBody:   `{"code":"U0018","message":"Forbidden"}`,
		},
		{
			name:           "role found",
			requiredRole:   "admin",
			userRoles:      []string{"admin", "user"},
			expectedStatus: http.StatusOK,
			expectedBody:   `{"message":"success"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware := NewAuthMiddleware(nil, logger)

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"message":"success"}`))
			})

			req := httptest.NewRequest("GET", "/", nil)
			ctx := context.WithValue(req.Context(), "roles", tt.userRoles)
			req = req.WithContext(ctx)

			w := httptest.NewRecorder()
			middleware.RequireRole(tt.requiredRole)(handler).ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.JSONEq(t, tt.expectedBody, w.Body.String())
		})
	}
}
