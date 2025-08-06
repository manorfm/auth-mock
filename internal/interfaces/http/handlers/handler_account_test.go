package handlers

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

// MockAccountService is a mock implementation of domain.AccountService
type MockAccountService struct {
	mock.Mock
}

func (m *MockAccountService) CreateAccount(ctx context.Context, userID ulid.ULID) (*domain.Account, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Account), args.Error(1)
}

func (m *MockAccountService) GetAccount(ctx context.Context, id ulid.ULID) (*domain.Account, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Account), args.Error(1)
}

func (m *MockAccountService) GetAccountByUserID(ctx context.Context, userID ulid.ULID) (*domain.Account, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Account), args.Error(1)
}

func (m *MockAccountService) UpdateAccount(ctx context.Context, account *domain.Account) error {
	args := m.Called(ctx, account)
	return args.Error(0)
}

func (m *MockAccountService) DeleteAccount(ctx context.Context, id ulid.ULID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// MockUserService is a mock implementation of domain.UserService
type MockUserService struct {
	mock.Mock
}

func (m *MockUserService) GetUser(ctx context.Context, userID ulid.ULID) (*domain.User, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserService) ListUsers(ctx context.Context, limit, offset int) ([]*domain.User, error) {
	args := m.Called(ctx, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.User), args.Error(1)
}

func (m *MockUserService) UpdateUser(ctx context.Context, id ulid.ULID, name, phone string) error {
	args := m.Called(ctx, id, name, phone)
	return args.Error(0)
}

// MockAccountTOTPService is a mock implementation of domain.TOTPService
type MockAccountTOTPService struct {
	mock.Mock
}

func (m *MockAccountTOTPService) EnableTOTP(userID string) (*domain.TOTP, error) {
	args := m.Called(userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.TOTP), args.Error(1)
}

func (m *MockAccountTOTPService) VerifyTOTP(userID, code string) error {
	args := m.Called(userID, code)
	return args.Error(0)
}

func (m *MockAccountTOTPService) VerifyBackupCode(userID, code string) error {
	args := m.Called(userID, code)
	return args.Error(0)
}

func (m *MockAccountTOTPService) DisableTOTP(userID string) error {
	args := m.Called(userID)
	return args.Error(0)
}

func (m *MockAccountTOTPService) GetTOTPSecret(ctx context.Context, userID string) (string, error) {
	args := m.Called(ctx, userID)
	return args.String(0), args.Error(1)
}

type MockJWTService struct {
	mock.Mock
}

func (m *MockJWTService) ValidateToken(token string) (*domain.Claims, error) {
	args := m.Called(token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Claims), args.Error(1)
}

func (m *MockJWTService) GetJWKS(ctx context.Context) (map[string]interface{}, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockJWTService) GenerateTokenPair(ctx context.Context, user *domain.User) (*domain.TokenPair, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.TokenPair), args.Error(1)
}

func (m *MockJWTService) GetPublicKey() *rsa.PublicKey {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*rsa.PublicKey)
}

func (m *MockJWTService) RotateKeys() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockJWTService) BlacklistToken(tokenID string, expiresAt time.Time) error {
	args := m.Called(tokenID, expiresAt)
	return args.Error(0)
}

func (m *MockJWTService) IsTokenBlacklisted(tokenID string) bool {
	args := m.Called(tokenID)
	return args.Bool(0)
}

func TestHandlerAccount_GetAccountsHandler(t *testing.T) {
	tests := []struct {
		name           string
		userID         string
		setupMocks     func(*MockAccountService)
		expectedStatus int
		expectedError  error
	}{
		{
			name:   "successful get account",
			userID: ulid.Make().String(),
			setupMocks: func(m *MockAccountService) {
				userID, _ := ulid.Parse(ulid.Make().String())
				account := &domain.Account{
					ID:     ulid.Make(),
					UserID: userID,
					Status: domain.AccountStatusActive,
				}
				m.On("GetAccountByUserID", mock.Anything, mock.AnythingOfType("ulid.ULID")).Return(account, nil)
			},
			expectedStatus: http.StatusOK,
			expectedError:  nil,
		},
		{
			name:   "account not found",
			userID: ulid.Make().String(),
			setupMocks: func(m *MockAccountService) {
				m.On("GetAccountByUserID", mock.Anything, mock.AnythingOfType("ulid.ULID")).Return(nil, domain.ErrAccountNotFound)
			},
			expectedStatus: http.StatusNotFound,
			expectedError:  domain.ErrAccountNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAccountSvc := new(MockAccountService)
			mockUserSvc := new(MockUserService)
			mockTOTPSvc := new(MockAccountTOTPService)
			mockJWTService := new(MockJWTService)
			logger := zap.NewNop()

			handler := NewAccountHandler(mockAccountSvc, mockUserSvc, mockTOTPSvc, mockJWTService, logger)

			tt.setupMocks(mockAccountSvc)

			req := httptest.NewRequest("GET", "/api/accounts", nil)
			ctx := context.WithValue(req.Context(), domain.ContextKeySubject, tt.userID)
			req = req.WithContext(ctx)

			w := httptest.NewRecorder()
			handler.GetAccountsHandler(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			mockAccountSvc.AssertExpectations(t)
		})
	}
}

func TestHandlerAccount_GetMeHandler(t *testing.T) {
	tests := []struct {
		name           string
		userID         string
		setupMocks     func(*MockAccountService, *MockUserService, *MockAccountTOTPService, *MockJWTService)
		expectedStatus int
		expectedError  error
	}{
		{
			name:   "successful get me",
			userID: ulid.Make().String(),
			setupMocks: func(m *MockAccountService, u *MockUserService, t *MockAccountTOTPService, j *MockJWTService) {
				userID, _ := ulid.Parse(ulid.Make().String())
				account := &domain.Account{
					ID:     ulid.Make(),
					UserID: userID,
					Status: domain.AccountStatusActive,
				}
				user := &domain.User{
					ID:    userID,
					Name:  "Test User",
					Email: "test@example.com",
					Phone: "1234567890",
				}
				claims := &domain.Claims{
					RegisteredClaims: &jwt.RegisteredClaims{
						Subject: userID.String(),
					},
					Roles: []string{"user"},
				}
				m.On("GetAccountByUserID", mock.Anything, mock.AnythingOfType("ulid.ULID")).Return(account, nil)
				u.On("GetUser", mock.Anything, mock.AnythingOfType("ulid.ULID")).Return(user, nil)
				t.On("GetTOTPSecret", mock.Anything, mock.Anything).Return("", domain.ErrTOTPNotEnabled)
				j.On("ValidateToken", mock.Anything).Return(claims, nil)
			},
			expectedStatus: http.StatusOK,
			expectedError:  nil,
		},
		{
			name:   "account not found",
			userID: ulid.Make().String(),
			setupMocks: func(m *MockAccountService, u *MockUserService, t *MockAccountTOTPService, j *MockJWTService) {
				userID, _ := ulid.Parse(ulid.Make().String())
				claims := &domain.Claims{
					RegisteredClaims: &jwt.RegisteredClaims{
						Subject: userID.String(),
					},
					Roles: []string{"user"},
				}
				m.On("GetAccountByUserID", mock.Anything, mock.AnythingOfType("ulid.ULID")).Return(nil, domain.ErrAccountNotFound)
				j.On("ValidateToken", mock.Anything).Return(claims, nil)
			},
			expectedStatus: http.StatusNotFound,
			expectedError:  domain.ErrAccountNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAccountSvc := new(MockAccountService)
			mockUserSvc := new(MockUserService)
			mockTOTPSvc := new(MockAccountTOTPService)
			mockJWTService := new(MockJWTService)
			logger := zap.NewNop()

			handler := NewAccountHandler(mockAccountSvc, mockUserSvc, mockTOTPSvc, mockJWTService, logger)

			tt.setupMocks(mockAccountSvc, mockUserSvc, mockTOTPSvc, mockJWTService)

			req := httptest.NewRequest("GET", "/api/accounts/me", nil)
			req.Header.Set("Authorization", "Bearer test-token")

			w := httptest.NewRecorder()
			handler.GetMeHandler(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			mockAccountSvc.AssertExpectations(t)
			mockUserSvc.AssertExpectations(t)
			mockTOTPSvc.AssertExpectations(t)
			mockJWTService.AssertExpectations(t)
		})
	}
}

func TestHandlerAccount_UpdateAccountHandler(t *testing.T) {
	tests := []struct {
		name           string
		userID         string
		requestBody    UpdateAccountRequest
		setupMocks     func(*MockAccountService)
		expectedStatus int
		expectedError  error
	}{
		{
			name:   "successful update account",
			userID: ulid.Make().String(),
			requestBody: UpdateAccountRequest{
				Status: domain.AccountStatusInactive,
			},
			setupMocks: func(m *MockAccountService) {
				userID, _ := ulid.Parse(ulid.Make().String())
				account := &domain.Account{
					ID:     ulid.Make(),
					UserID: userID,
					Status: domain.AccountStatusActive,
				}
				m.On("GetAccountByUserID", mock.Anything, mock.AnythingOfType("ulid.ULID")).Return(account, nil)
				m.On("UpdateAccount", mock.Anything, mock.AnythingOfType("*domain.Account")).Return(nil)
			},
			expectedStatus: http.StatusOK,
			expectedError:  nil,
		},
		{
			name:   "account not found",
			userID: ulid.Make().String(),
			requestBody: UpdateAccountRequest{
				Status: domain.AccountStatusInactive,
			},
			setupMocks: func(m *MockAccountService) {
				m.On("GetAccountByUserID", mock.Anything, mock.AnythingOfType("ulid.ULID")).Return(nil, domain.ErrAccountNotFound)
			},
			expectedStatus: http.StatusNotFound,
			expectedError:  domain.ErrAccountNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAccountSvc := new(MockAccountService)
			mockUserSvc := new(MockUserService)
			mockTOTPSvc := new(MockAccountTOTPService)
			mockJWTService := new(MockJWTService)
			logger := zap.NewNop()

			handler := NewAccountHandler(mockAccountSvc, mockUserSvc, mockTOTPSvc, mockJWTService, logger)

			tt.setupMocks(mockAccountSvc)

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest("PUT", "/api/accounts", bytes.NewBuffer(body))
			ctx := context.WithValue(req.Context(), domain.ContextKeySubject, tt.userID)
			req = req.WithContext(ctx)

			w := httptest.NewRecorder()
			handler.UpdateAccountHandler(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			mockAccountSvc.AssertExpectations(t)
		})
	}
}

func TestHandlerAccount_DeleteAccountHandler(t *testing.T) {
	tests := []struct {
		name           string
		userID         string
		setupMocks     func(*MockAccountService)
		expectedStatus int
		expectedError  error
	}{
		{
			name:   "successful delete account",
			userID: ulid.Make().String(),
			setupMocks: func(m *MockAccountService) {
				userID, _ := ulid.Parse(ulid.Make().String())
				account := &domain.Account{
					ID:     ulid.Make(),
					UserID: userID,
					Status: domain.AccountStatusActive,
				}
				m.On("GetAccountByUserID", mock.Anything, mock.AnythingOfType("ulid.ULID")).Return(account, nil)
				m.On("DeleteAccount", mock.Anything, mock.AnythingOfType("ulid.ULID")).Return(nil)
			},
			expectedStatus: http.StatusNoContent,
			expectedError:  nil,
		},
		{
			name:   "account not found",
			userID: ulid.Make().String(),
			setupMocks: func(m *MockAccountService) {
				m.On("GetAccountByUserID", mock.Anything, mock.AnythingOfType("ulid.ULID")).Return(nil, domain.ErrAccountNotFound)
			},
			expectedStatus: http.StatusNotFound,
			expectedError:  domain.ErrAccountNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAccountSvc := new(MockAccountService)
			mockUserSvc := new(MockUserService)
			mockTOTPSvc := new(MockAccountTOTPService)
			mockJWTService := new(MockJWTService)
			logger := zap.NewNop()

			handler := NewAccountHandler(mockAccountSvc, mockUserSvc, mockTOTPSvc, mockJWTService, logger)

			tt.setupMocks(mockAccountSvc)

			req := httptest.NewRequest("DELETE", "/api/accounts", nil)
			ctx := context.WithValue(req.Context(), domain.ContextKeySubject, tt.userID)
			req = req.WithContext(ctx)

			w := httptest.NewRecorder()
			handler.DeleteAccountHandler(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			mockAccountSvc.AssertExpectations(t)
		})
	}
}

func TestNewAccountResponse(t *testing.T) {
	account := &domain.Account{
		ID:        ulid.Make(),
		UserID:    ulid.Make(),
		Status:    domain.AccountStatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	response := NewAccountResponse(account)

	assert.NotNil(t, response)
	assert.Equal(t, account.ID.String(), response.ID)
	assert.Equal(t, account.UserID.String(), response.UserID)
	assert.Equal(t, account.Status, response.Status)
}

func TestNewAccountMeResponse(t *testing.T) {
	account := &domain.Account{
		ID:        ulid.Make(),
		UserID:    ulid.Make(),
		Status:    domain.AccountStatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	user := &domain.User{
		ID:    account.UserID,
		Name:  "Test User",
		Email: "test@example.com",
		Phone: "1234567890",
	}

	response := NewAccountMeResponse(account, user, true)

	assert.NotNil(t, response)
	assert.Equal(t, account.ID.String(), response.ID)
	assert.Equal(t, string(account.Status), response.Status)
	assert.Equal(t, user.ID.String(), response.User.ID)
	assert.Equal(t, user.Name, response.User.Name)
	assert.Equal(t, user.Email, response.User.Email)
	assert.Equal(t, user.Phone, response.User.Phone)
	assert.Equal(t, "active", response.MFA)
}

func TestNewAccountMeResponse_MFAInactive(t *testing.T) {
	account := &domain.Account{
		ID:        ulid.Make(),
		UserID:    ulid.Make(),
		Status:    domain.AccountStatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	user := &domain.User{
		ID:    account.UserID,
		Name:  "Test User",
		Email: "test@example.com",
		Phone: "1234567890",
	}

	response := NewAccountMeResponse(account, user, false)

	assert.NotNil(t, response)
	assert.Equal(t, "inactive", response.MFA)
}
