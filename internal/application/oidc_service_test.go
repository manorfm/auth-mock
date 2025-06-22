package application

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"testing"
	"time"

	"crypto/rsa"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/infrastructure/config"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

// Mock OAuth2Service for testing
type mockOAuth2Service struct {
	mock.Mock
}

func (m *mockOAuth2Service) ValidateClient(ctx context.Context, clientID, redirectURI string) (*domain.OAuth2Client, error) {
	args := m.Called(ctx, clientID, redirectURI)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.OAuth2Client), args.Error(1)
}

func (m *mockOAuth2Service) GenerateAuthorizationCode(ctx context.Context, clientID, userID string, scopes []string, codeChallenge, codeChallengeMethod string) (string, error) {
	args := m.Called(ctx, clientID, userID, scopes, codeChallenge, codeChallengeMethod)
	return args.String(0), args.Error(1)
}

func (m *mockOAuth2Service) ValidateAuthorizationCode(ctx context.Context, code string) (*domain.OAuth2Client, string, []string, error) {
	args := m.Called(ctx, code)
	if args.Get(0) == nil {
		return nil, "", nil, args.Error(3)
	}
	return args.Get(0).(*domain.OAuth2Client), args.String(1), args.Get(2).([]string), args.Error(3)
}

func (m *mockOAuth2Service) ValidatePKCE(ctx context.Context, codeVerifier, codeChallenge, codeChallengeMethod string) error {
	args := m.Called(ctx, codeVerifier, codeChallenge, codeChallengeMethod)
	return args.Error(0)
}

type mockOAuth2Repository struct {
	mock.Mock
}

func (m *mockOAuth2Repository) CreateClient(ctx context.Context, client *domain.OAuth2Client) error {
	args := m.Called(ctx, client)
	return args.Error(0)
}

func (m *mockOAuth2Repository) FindClientByID(ctx context.Context, id string) (*domain.OAuth2Client, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.OAuth2Client), args.Error(1)
}

func (m *mockOAuth2Repository) UpdateClient(ctx context.Context, client *domain.OAuth2Client) error {
	args := m.Called(ctx, client)
	return args.Error(0)
}

func (m *mockOAuth2Repository) DeleteClient(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockOAuth2Repository) ListClients(ctx context.Context) ([]*domain.OAuth2Client, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*domain.OAuth2Client), args.Error(1)
}

func (m *mockOAuth2Repository) CreateAuthorizationCode(ctx context.Context, code *domain.AuthorizationCode) error {
	args := m.Called(ctx, code)
	return args.Error(0)
}

func (m *mockOAuth2Repository) DeleteAuthorizationCode(ctx context.Context, code string) error {
	args := m.Called(ctx, code)
	return args.Error(0)
}

func (m *mockOAuth2Repository) GetAuthorizationCode(ctx context.Context, code string) (*domain.AuthorizationCode, error) {
	args := m.Called(ctx, code)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.AuthorizationCode), args.Error(1)
}

type mockUserRepository struct {
	mock.Mock
}

func (m *mockUserRepository) GetUserByID(ctx context.Context, id string) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *mockUserRepository) Create(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *mockUserRepository) Delete(ctx context.Context, id ulid.ULID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockUserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	args := m.Called(ctx, email)
	return args.Bool(0), args.Error(1)
}

func (m *mockUserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *mockUserRepository) FindByID(ctx context.Context, id ulid.ULID) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *mockUserRepository) List(ctx context.Context, page, pageSize int) ([]*domain.User, error) {
	args := m.Called(ctx, page, pageSize)
	return args.Get(0).([]*domain.User), args.Error(1)
}

func (m *mockUserRepository) RemoveRole(ctx context.Context, userID ulid.ULID, role string) error {
	args := m.Called(ctx, userID, role)
	return args.Error(0)
}

func (m *mockUserRepository) Update(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *mockUserRepository) AddRole(ctx context.Context, userID ulid.ULID, role string) error {
	args := m.Called(ctx, userID, role)
	return args.Error(0)
}

func (m *mockUserRepository) UpdatePassword(ctx context.Context, userID ulid.ULID, hashedPassword string) error {
	args := m.Called(ctx, userID, hashedPassword)
	return args.Error(0)
}

// Mock JWT para simular chave pública inválida
type mockJWTWithNilKey struct{}

func (m *mockJWTWithNilKey) GetPublicKey() *rsa.PublicKey { return nil }

// Mock JWT para simular fluxo de refresh token
type mockJWTRefresh struct{}

func (m *mockJWTRefresh) ValidateToken(token string) (*domain.Claims, error) {
	return &domain.Claims{
		RegisteredClaims: &jwtv5.RegisteredClaims{
			Subject: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		},
		Roles: []string{"user"},
	}, nil
}

func (m *mockJWTRefresh) GetPublicKey() *rsa.PublicKey { return nil }

func (m *mockJWTRefresh) GetJWKS(ctx context.Context) (map[string]interface{}, error) {
	return nil, nil
}

func (m *mockJWTRefresh) GenerateTokenPair(userID ulid.ULID, roles []string) (*domain.TokenPair, error) {
	return &domain.TokenPair{
		AccessToken:  "mock_access_token",
		RefreshToken: "mock_refresh_token",
	}, nil
}

func (m *mockJWTRefresh) BlacklistToken(tokenID string, expiresAt time.Time) error {
	return nil
}

func (m *mockJWTRefresh) IsTokenBlacklisted(tokenID string) bool {
	return false
}

func (m *mockJWTRefresh) RotateKeys() error {
	return nil
}

func (m *mockJWTRefresh) GetLastRotation() time.Time {
	return time.Now()
}

// Mock JWT para simular erro de validação
type mockJWTError struct{}

func (m *mockJWTError) ValidateToken(token string) (*domain.Claims, error) {
	return nil, domain.ErrInvalidCredentials
}

func (m *mockJWTError) GetPublicKey() *rsa.PublicKey {
	return nil
}

func (m *mockJWTError) GetJWKS(ctx context.Context) (map[string]interface{}, error) {
	return nil, nil
}

func (m *mockJWTError) GenerateTokenPair(userID ulid.ULID, roles []string) (*domain.TokenPair, error) {
	return nil, nil
}

func (m *mockJWTError) BlacklistToken(tokenID string, expiresAt time.Time) error {
	return nil
}

func (m *mockJWTError) IsTokenBlacklisted(tokenID string) bool {
	return false
}

func (m *mockJWTError) RotateKeys() error {
	return nil
}

// Mock TOTPService for testing
type mockTOTPService struct {
	mock.Mock
}

func (m *mockTOTPService) EnableTOTP(userID string) (*domain.TOTP, error) {
	args := m.Called(userID)
	return args.Get(0).(*domain.TOTP), args.Error(1)
}

func (m *mockTOTPService) VerifyTOTP(userID, code string) error {
	args := m.Called(userID, code)
	return args.Error(0)
}

func (m *mockTOTPService) VerifyBackupCode(userID, code string) error {
	args := m.Called(userID, code)
	return args.Error(0)
}

func (m *mockTOTPService) DisableTOTP(userID string) error {
	args := m.Called(userID)
	return args.Error(0)
}

func (m *mockTOTPService) GetTOTPSecret(ctx context.Context, userID string) (string, error) {
	args := m.Called(ctx, userID)
	return args.String(0), args.Error(1)
}

// Mock JWT para simular erro de parsing do userID
type mockJWTInvalidUserID struct{}

func (m *mockJWTInvalidUserID) ValidateToken(token string) (*domain.Claims, error) {
	return &domain.Claims{
		RegisteredClaims: &jwtv5.RegisteredClaims{
			Subject: "invalid_user_id",
		},
		Roles: []string{"user"},
	}, nil
}

func (m *mockJWTInvalidUserID) GetPublicKey() *rsa.PublicKey {
	return nil
}

func (m *mockJWTInvalidUserID) GetJWKS(ctx context.Context) (map[string]interface{}, error) {
	return nil, nil
}

func (m *mockJWTInvalidUserID) GenerateTokenPair(userID ulid.ULID, roles []string) (*domain.TokenPair, error) {
	return nil, nil
}

func (m *mockJWTInvalidUserID) BlacklistToken(tokenID string, expiresAt time.Time) error {
	return nil
}

func (m *mockJWTInvalidUserID) IsTokenBlacklisted(tokenID string) bool {
	return false
}

func (m *mockJWTInvalidUserID) RotateKeys() error {
	return nil
}

// Mock JWT para simular erro de geração de token
type mockJWTTokenGenError struct{}

func (m *mockJWTTokenGenError) ValidateToken(token string) (*domain.Claims, error) {
	return &domain.Claims{
		RegisteredClaims: &jwtv5.RegisteredClaims{
			Subject: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		},
		Roles: []string{"user"},
	}, nil
}

func (m *mockJWTTokenGenError) GetPublicKey() *rsa.PublicKey {
	return nil
}

func (m *mockJWTTokenGenError) GetJWKS(ctx context.Context) (map[string]interface{}, error) {
	return nil, nil
}

func (m *mockJWTTokenGenError) GenerateTokenPair(userID ulid.ULID, roles []string) (*domain.TokenPair, error) {
	return nil, domain.ErrInternal
}

func (m *mockJWTTokenGenError) BlacklistToken(tokenID string, expiresAt time.Time) error {
	return nil
}

func (m *mockJWTTokenGenError) IsTokenBlacklisted(tokenID string) bool {
	return false
}

func (m *mockJWTTokenGenError) RotateKeys() error {
	return nil
}

func TestOIDCService_GetUserInfo(t *testing.T) {
	userID := ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAV")
	tests := []struct {
		name          string
		userID        ulid.ULID
		mockSetup     func(*mockUserRepository, *mockTOTPService)
		expectedError error
		expectedInfo  *domain.UserInfo
	}{
		{
			name:   "successful user info retrieval",
			userID: userID,
			mockSetup: func(m *mockUserRepository, t *mockTOTPService) {
				m.On("FindByID", mock.Anything, userID).Return(&domain.User{
					ID:    userID,
					Name:  "Test User",
					Email: "test@example.com",
				}, nil)
				t.On("GetTOTPSecret", mock.Anything, userID.String()).Return("", domain.ErrTOTPNotEnabled)
			},
			expectedInfo: &domain.UserInfo{
				Sub:           userID.String(),
				Name:          "Test User",
				Email:         "test@example.com",
				EmailVerified: true,
				AMR:           []string{"pwd"},
			},
		},
		{
			name:   "user not found",
			userID: ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAW"),
			mockSetup: func(m *mockUserRepository, t *mockTOTPService) {
				m.On("FindByID", mock.Anything, ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAW")).Return(nil, domain.ErrUserNotFound)
			},
			expectedError: domain.ErrUserNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUserRepo := new(mockUserRepository)
			mockOAuth2Service := new(mockOAuth2Service)
			mockTOTPService := new(mockTOTPService)
			tt.mockSetup(mockUserRepo, mockTOTPService)
			cfg, err := config.LoadConfig(zap.NewNop())
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}
			service := NewOIDCService(mockOAuth2Service, nil, mockUserRepo, mockTOTPService, cfg, zap.NewNop())

			info, err := service.GetUserInfo(context.Background(), tt.userID.String())

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
				assert.Nil(t, info)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedInfo, info)
			}

			mockUserRepo.AssertExpectations(t)
			mockTOTPService.AssertExpectations(t)
		})
	}
}

func TestOIDCService_Authorize(t *testing.T) {
	tests := []struct {
		name        string
		clientID    string
		redirectURI string
		state       string
		scope       string
		setupMocks  func(*mockOAuth2Service)
		setupCtx    func(context.Context) context.Context
		wantCode    string
		wantErr     error
	}{
		{
			name:        "success",
			clientID:    "test-client",
			redirectURI: "http://localhost:8080/callback",
			state:       "state123",
			scope:       "openid profile",
			setupMocks: func(m *mockOAuth2Service) {
				m.On("ValidateClient", mock.Anything, "test-client", "http://localhost:8080/callback").Return(
					&domain.OAuth2Client{
						ID:     "test-client",
						Scopes: []string{"openid", "profile", "email"},
					},
					nil,
				)
				m.On("GenerateAuthorizationCode",
					mock.Anything,
					"test-client",
					"01H1VEC8SYM3K9TSDAPFN25XZV",
					[]string{"openid", "profile"},
					"challenge",
					"S256",
				).Return("auth-code", nil)
			},
			setupCtx: func(ctx context.Context) context.Context {
				ctx = domain.WithSubject(ctx, "01H1VEC8SYM3K9TSDAPFN25XZV")
				ctx = domain.WithCodeChallenge(ctx, "challenge")
				ctx = domain.WithCodeChallengeMethod(ctx, "S256")
				return ctx
			},
			wantCode: "auth-code",
			wantErr:  nil,
		},
		{
			name:        "client validation failed",
			clientID:    "invalid-client",
			redirectURI: "http://localhost:8080/callback",
			state:       "state123",
			scope:       "openid",
			setupMocks: func(m *mockOAuth2Service) {
				m.On("ValidateClient", mock.Anything, "invalid-client", "http://localhost:8080/callback").Return(
					nil,
					domain.ErrClientNotFound,
				)
			},
			setupCtx: func(ctx context.Context) context.Context {
				ctx = domain.WithSubject(ctx, "01H1VEC8SYM3K9TSDAPFN25XZV")
				return ctx
			},
			wantErr: domain.ErrClientNotFound,
		},
		{
			name:        "no user ID in context",
			clientID:    "test-client",
			redirectURI: "http://localhost:8080/callback",
			state:       "state123",
			scope:       "openid",
			setupMocks: func(m *mockOAuth2Service) {
				// No mock setup needed
			},
			setupCtx: func(ctx context.Context) context.Context {
				return ctx
			},
			wantErr: domain.ErrUnauthorized,
		},
		{
			name:        "invalid scope",
			clientID:    "test-client",
			redirectURI: "http://localhost:8080/callback",
			state:       "state123",
			scope:       "invalid-scope",
			setupMocks: func(m *mockOAuth2Service) {
				m.On("ValidateClient", mock.Anything, "test-client", "http://localhost:8080/callback").Return(
					&domain.OAuth2Client{
						ID:     "test-client",
						Scopes: []string{"openid", "profile"},
					},
					nil,
				)
			},
			setupCtx: func(ctx context.Context) context.Context {
				ctx = domain.WithSubject(ctx, "01H1VEC8SYM3K9TSDAPFN25XZV")
				return ctx
			},
			wantErr: domain.ErrInvalidScope,
		},
		{
			name:        "code generation failed",
			clientID:    "test-client",
			redirectURI: "http://localhost:8080/callback",
			state:       "state123",
			scope:       "openid",
			setupMocks: func(m *mockOAuth2Service) {
				m.On("ValidateClient", mock.Anything, "test-client", "http://localhost:8080/callback").Return(
					&domain.OAuth2Client{
						ID:     "test-client",
						Scopes: []string{"openid"},
					},
					nil,
				)
				m.On("GenerateAuthorizationCode",
					mock.Anything,
					"test-client",
					"01H1VEC8SYM3K9TSDAPFN25XZV",
					[]string{"openid"},
					"challenge",
					"S256",
				).Return("", domain.ErrInternal)
			},
			setupCtx: func(ctx context.Context) context.Context {
				ctx = domain.WithSubject(ctx, "01H1VEC8SYM3K9TSDAPFN25XZV")
				ctx = domain.WithCodeChallenge(ctx, "challenge")
				ctx = domain.WithCodeChallengeMethod(ctx, "S256")
				return ctx
			},
			wantErr: domain.ErrInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockOAuth2 := new(mockOAuth2Service)
			mockTOTPService := new(mockTOTPService)
			tt.setupMocks(mockOAuth2)

			cfg, err := config.LoadConfig(zap.NewNop())
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}
			service := NewOIDCService(mockOAuth2, nil, nil, mockTOTPService, cfg, zap.NewNop())
			code, err := service.Authorize(tt.setupCtx(context.Background()), tt.clientID, tt.redirectURI, tt.state, tt.scope)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Empty(t, code)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantCode, code)
			}

			mockOAuth2.AssertExpectations(t)
		})
	}
}

func TestOIDCService_ExchangeCode(t *testing.T) {
	logger := zap.NewNop()
	tests := []struct {
		name          string
		code          string
		codeVerifier  string
		mockSetup     func(*mockOAuth2Service)
		expectedError error
		expectedToken *domain.TokenPair
	}{
		{
			name:         "successful code exchange",
			code:         "valid_code",
			codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			mockSetup: func(m *mockOAuth2Service) {
				m.On("ValidateAuthorizationCode", mock.Anything, "valid_code").Return(&domain.OAuth2Client{
					ID: "client123",
				}, "01ARZ3NDEKTSV4RRFFQ69G5FAV", []string{"openid", "profile", "email"}, nil)
			},
			expectedToken: &domain.TokenPair{
				AccessToken:  "mock_access_token",
				RefreshToken: "mock_refresh_token",
			},
		},
		{
			name:         "invalid code",
			code:         "invalid_code",
			codeVerifier: "verifier",
			mockSetup: func(m *mockOAuth2Service) {
				m.On("ValidateAuthorizationCode", mock.Anything, "invalid_code").Return(nil, "", nil, domain.ErrInvalidAuthorizationCode)
			},
			expectedError: domain.ErrInvalidAuthorizationCode,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockOAuth2Service := new(mockOAuth2Service)
			mockUserRepo := new(mockUserRepository)
			mockJWT := &mockJWTRefresh{}
			mockTOTPService := new(mockTOTPService)

			tt.mockSetup(mockOAuth2Service)
			if tt.name == "successful code exchange" {
				mockUserRepo.On("FindByID", mock.Anything, ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAV")).Return(&domain.User{
					ID:    ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAV"),
					Name:  "Test User",
					Email: "test@example.com",
					Roles: []string{"user"},
				}, nil)
			}

			cfg, err := config.LoadConfig(logger)
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}
			service := NewOIDCService(mockOAuth2Service, mockJWT, mockUserRepo, mockTOTPService, cfg, logger)

			token, err := service.ExchangeCode(context.Background(), tt.code, tt.codeVerifier)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err)
				assert.Nil(t, token)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, token)
				assert.Equal(t, tt.expectedToken, token)
			}

			mockOAuth2Service.AssertExpectations(t)
			mockUserRepo.AssertExpectations(t)
		})
	}
}

func TestOIDCService_GetOpenIDConfiguration(t *testing.T) {
	tests := []struct {
		name           string
		setupCtx       func(context.Context) context.Context // Function to set up the context
		expectedError  error
		expectedConfig map[string]interface{}
		config         *config.Config // Allow per-test config
	}{
		{
			name: "successful retrieval with X-Forwarded-Proto and X-Forwarded-Host",
			setupCtx: func(ctx context.Context) context.Context {
				req := &http.Request{Header: http.Header{}}
				req.Header.Set("X-Forwarded-Proto", "https")
				req.Header.Set("X-Forwarded-Host", "proxy.example.com")
				return context.WithValue(ctx, domain.RequestKey, req)
			},
			expectedConfig: map[string]interface{}{
				"issuer":                                "https://proxy.example.com",
				"authorization_endpoint":                "https://proxy.example.com/oauth2/authorize",
				"token_endpoint":                        "https://proxy.example.com/oauth2/token",
				"userinfo_endpoint":                     "https://proxy.example.com/oauth2/userinfo",
				"jwks_uri":                              "https://proxy.example.com/.well-known/jwks.json",
				"response_types_supported":              []string{"code", "token", "id_token"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
				"scopes_supported":                      []string{"openid", "profile", "email"},
				"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
				"claims_supported":                      []string{"sub", "iss", "name", "email"},
			},
			config: &config.Config{ServerURL: "http://fallback:1234"}, // Fallback should not be used
		},
		{
			name: "successful retrieval from request URL (HTTP)",
			setupCtx: func(ctx context.Context) context.Context {
				req := &http.Request{
					URL:  &url.URL{Scheme: "http", Host: "service.example.com:8080"},
					Host: "service.example.com:8080",
				}
				return context.WithValue(ctx, domain.RequestKey, req)
			},
			expectedConfig: map[string]interface{}{
				"issuer":                                "http://service.example.com:8080",
				"authorization_endpoint":                "http://service.example.com:8080/oauth2/authorize",
				"token_endpoint":                        "http://service.example.com:8080/oauth2/token",
				"userinfo_endpoint":                     "http://service.example.com:8080/oauth2/userinfo",
				"jwks_uri":                              "http://service.example.com:8080/.well-known/jwks.json",
				"response_types_supported":              []string{"code", "token", "id_token"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
				"scopes_supported":                      []string{"openid", "profile", "email"},
				"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
				"claims_supported":                      []string{"sub", "iss", "name", "email"},
			},
			config: &config.Config{ServerURL: "http://fallback:1234"},
		},
		{
			name: "successful retrieval from request URL (HTTPS via TLS)",
			setupCtx: func(ctx context.Context) context.Context {
				req := &http.Request{
					URL:  &url.URL{Host: "secure.example.com"}, // Scheme might be empty
					Host: "secure.example.com",
					TLS:  &tls.ConnectionState{},
				}
				return context.WithValue(ctx, domain.RequestKey, req)
			},
			expectedConfig: map[string]interface{}{
				"issuer":                                "https://secure.example.com",
				"authorization_endpoint":                "https://secure.example.com/oauth2/authorize",
				"token_endpoint":                        "https://secure.example.com/oauth2/token",
				"userinfo_endpoint":                     "https://secure.example.com/oauth2/userinfo",
				"jwks_uri":                              "https://secure.example.com/.well-known/jwks.json",
				"response_types_supported":              []string{"code", "token", "id_token"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
				"scopes_supported":                      []string{"openid", "profile", "email"},
				"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
				"claims_supported":                      []string{"sub", "iss", "name", "email"},
			},
			config: &config.Config{ServerURL: "http://fallback:1234"},
		},
		{
			name: "fallback to config ServerURL when request context is missing",
			setupCtx: func(ctx context.Context) context.Context {
				return ctx // No request in context
			},
			expectedConfig: map[string]interface{}{
				"issuer":                                "http://config.example.com:8080",
				"authorization_endpoint":                "http://config.example.com:8080/oauth2/authorize",
				"token_endpoint":                        "http://config.example.com:8080/oauth2/token",
				"userinfo_endpoint":                     "http://config.example.com:8080/oauth2/userinfo",
				"jwks_uri":                              "http://config.example.com:8080/.well-known/jwks.json",
				"response_types_supported":              []string{"code", "token", "id_token"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
				"scopes_supported":                      []string{"openid", "profile", "email"},
				"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
				"claims_supported":                      []string{"sub", "iss", "name", "email"},
			},
			config: &config.Config{ServerURL: "http://config.example.com:8080"},
		},
		{
			name: "nil configuration provided to service",
			setupCtx: func(ctx context.Context) context.Context {
				return ctx
			},
			expectedError: domain.ErrInternal,
			config:        nil, // Service config is nil
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockOAuth2Service := new(mockOAuth2Service) // Mocks are generally not needed for this specific test
			mockTOTPService := new(mockTOTPService)

			// Use the config from the test case
			service := NewOIDCService(mockOAuth2Service, nil, nil, mockTOTPService, tt.config, zap.NewNop())

			// Setup context using the provided function
			ctx := tt.setupCtx(context.Background())

			openIDConfig, err := service.GetOpenIDConfiguration(ctx)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
				assert.Nil(t, openIDConfig)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedConfig, openIDConfig)
			}
		})
	}
}

func TestOIDCService_RefreshToken(t *testing.T) {
	logger := zap.NewNop()
	tests := []struct {
		name          string
		refreshToken  string
		mockSetup     func(*mockUserRepository, interface{})
		expectedError error
		expectedToken *domain.TokenPair
	}{
		{
			name:         "successful token refresh",
			refreshToken: "valid_refresh_token",
			mockSetup: func(m *mockUserRepository, _ interface{}) {
				userID := ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAV")
				m.On("FindByID", mock.Anything, userID).Return(&domain.User{
					ID:    userID,
					Name:  "Test User",
					Email: "test@example.com",
					Roles: []string{"user"},
				}, nil)
			},
			expectedToken: &domain.TokenPair{
				AccessToken:  "mock_access_token",
				RefreshToken: "mock_refresh_token",
			},
		},
		{
			name:         "invalid refresh token",
			refreshToken: "invalid_token",
			mockSetup: func(m *mockUserRepository, _ interface{}) {
				// No mock setup needed
			},
			expectedError: domain.ErrInvalidCredentials,
		},
		{
			name:         "user not found",
			refreshToken: "valid_refresh_token",
			mockSetup: func(m *mockUserRepository, _ interface{}) {
				userID := ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAV")
				m.On("FindByID", mock.Anything, userID).Return(nil, domain.ErrUserNotFound).Once()
			},
			expectedError: domain.ErrInvalidCredentials,
		},
		{
			name:         "invalid user ID in token",
			refreshToken: "valid_refresh_token",
			mockSetup: func(m *mockUserRepository, _ interface{}) {
				// No mock setup needed
			},
			expectedError: domain.ErrInvalidUserID,
		},
		{
			name:         "token generation error",
			refreshToken: "valid_refresh_token",
			mockSetup: func(m *mockUserRepository, _ interface{}) {
				userID := ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAV")
				m.On("FindByID", mock.Anything, userID).Return(&domain.User{
					ID:    userID,
					Name:  "Test User",
					Email: "test@example.com",
					Roles: []string{"user"},
				}, nil)
			},
			expectedError: domain.ErrInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUserRepo := new(mockUserRepository)
			mockOAuth2Service := new(mockOAuth2Service)
			mockTOTPService := new(mockTOTPService)
			var jwtService domain.JWTService
			switch tt.name {
			case "successful token refresh":
				jwtService = &mockJWTRefresh{}
			case "invalid refresh token":
				jwtService = &mockJWTError{}
			case "invalid user ID in token":
				jwtService = &mockJWTInvalidUserID{}
			case "token generation error":
				jwtService = &mockJWTTokenGenError{}
			default:
				jwtService = &mockJWTError{}
			}
			tt.mockSetup(mockUserRepo, jwtService)

			cfg, err := config.LoadConfig(logger)
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}
			service := NewOIDCService(mockOAuth2Service, jwtService, mockUserRepo, mockTOTPService, cfg, logger)

			token, err := service.RefreshToken(context.Background(), tt.refreshToken)

			if tt.expectedError != nil {
				assert.Error(t, err)
				if tt.expectedError.Error() != "" {
					assert.Equal(t, tt.expectedError.Error(), err.Error())
				}
				assert.Nil(t, token)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, token)
				assert.NotEmpty(t, token.AccessToken)
				assert.NotEmpty(t, token.RefreshToken)
			}

			if tt.name == "invalid refresh token" || tt.name == "user not found" {
				// Skip mock expectations for these cases
			} else {
				mockUserRepo.AssertExpectations(t)
			}
		})
	}
}
