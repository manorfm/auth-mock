package application

import (
	"context"
	"testing"
	"time"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

// MockOAuth2Repository is a mock implementation of domain.OAuth2Repository
type MockOAuth2Repository struct {
	mock.Mock
}

func (m *MockOAuth2Repository) CreateClient(ctx context.Context, client *domain.OAuth2Client) error {
	args := m.Called(ctx, client)
	return args.Error(0)
}

func (m *MockOAuth2Repository) FindClientByID(ctx context.Context, id string) (*domain.OAuth2Client, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.OAuth2Client), args.Error(1)
}

func (m *MockOAuth2Repository) UpdateClient(ctx context.Context, client *domain.OAuth2Client) error {
	args := m.Called(ctx, client)
	return args.Error(0)
}

func (m *MockOAuth2Repository) DeleteClient(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockOAuth2Repository) ListClients(ctx context.Context) ([]*domain.OAuth2Client, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*domain.OAuth2Client), args.Error(1)
}

func (m *MockOAuth2Repository) CreateAuthorizationCode(ctx context.Context, code *domain.AuthorizationCode) error {
	args := m.Called(ctx, code)
	return args.Error(0)
}

func (m *MockOAuth2Repository) GetAuthorizationCode(ctx context.Context, code string) (*domain.AuthorizationCode, error) {
	args := m.Called(ctx, code)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.AuthorizationCode), args.Error(1)
}

func (m *MockOAuth2Repository) DeleteAuthorizationCode(ctx context.Context, code string) error {
	args := m.Called(ctx, code)
	return args.Error(0)
}

func TestOAuth2Service_ValidateClient(t *testing.T) {
	tests := []struct {
		name        string
		clientID    string
		redirectURI string
		setupMock   func(*MockOAuth2Repository)
		wantErr     error
	}{
		{
			name:        "success",
			clientID:    "test-client",
			redirectURI: "http://localhost:8080/callback",
			setupMock: func(m *MockOAuth2Repository) {
				m.On("FindClientByID", mock.Anything, "test-client").Return(&domain.OAuth2Client{
					ID:           "test-client",
					RedirectURIs: []string{"http://localhost:8080/callback"},
				}, nil)
			},
			wantErr: nil,
		},
		{
			name:        "client not found",
			clientID:    "non-existent",
			redirectURI: "http://localhost:8080/callback",
			setupMock: func(m *MockOAuth2Repository) {
				m.On("FindClientByID", mock.Anything, "non-existent").Return(nil, domain.ErrClientNotFound)
			},
			wantErr: domain.ErrClientNotFound,
		},
		{
			name:        "invalid redirect URI",
			clientID:    "test-client",
			redirectURI: "http://invalid.com/callback",
			setupMock: func(m *MockOAuth2Repository) {
				m.On("FindClientByID", mock.Anything, "test-client").Return(&domain.OAuth2Client{
					ID:           "test-client",
					RedirectURIs: []string{"http://localhost:8080/callback"},
				}, nil)
			},
			wantErr: domain.ErrInvalidRedirectURI,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockOAuth2Repository)
			tt.setupMock(mockRepo)

			service := NewOAuth2Service(mockRepo, zap.NewNop())
			client, err := service.ValidateClient(context.Background(), tt.clientID, tt.redirectURI)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.Equal(t, tt.clientID, client.ID)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestOAuth2Service_GenerateAuthorizationCode(t *testing.T) {
	tests := []struct {
		name                string
		clientID            string
		userID              string
		scopes              []string
		codeChallenge       string
		codeChallengeMethod string
		setupMock           func(*MockOAuth2Repository)
		wantErr             error
	}{
		{
			name:                "success",
			clientID:            "test-client",
			userID:              "test-user",
			scopes:              []string{"openid", "profile"},
			codeChallenge:       "challenge",
			codeChallengeMethod: "S256",
			setupMock: func(m *MockOAuth2Repository) {
				m.On("CreateAuthorizationCode", mock.Anything, mock.MatchedBy(func(code *domain.AuthorizationCode) bool {
					return code.ClientID == "test-client" &&
						code.UserID == "test-user" &&
						len(code.Scopes) == 2 &&
						code.CodeChallenge == "challenge" &&
						code.CodeChallengeMethod == "S256"
				})).Return(nil)
			},
			wantErr: nil,
		},
		{
			name:                "repository error",
			clientID:            "test-client",
			userID:              "test-user",
			scopes:              []string{"openid"},
			codeChallenge:       "challenge",
			codeChallengeMethod: "S256",
			setupMock: func(m *MockOAuth2Repository) {
				m.On("CreateAuthorizationCode", mock.Anything, mock.Anything).Return(domain.ErrInternal)
			},
			wantErr: domain.ErrInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockOAuth2Repository)
			tt.setupMock(mockRepo)

			service := NewOAuth2Service(mockRepo, zap.NewNop())
			code, err := service.GenerateAuthorizationCode(
				context.Background(),
				tt.clientID,
				tt.userID,
				tt.scopes,
				tt.codeChallenge,
				tt.codeChallengeMethod,
			)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Empty(t, code)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, code)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestOAuth2Service_ValidateAuthorizationCode(t *testing.T) {
	tests := []struct {
		name       string
		code       string
		setupMock  func(*MockOAuth2Repository)
		wantClient *domain.OAuth2Client
		wantUserID string
		wantScopes []string
		wantErr    error
	}{
		{
			name: "success",
			code: "valid-code",
			setupMock: func(m *MockOAuth2Repository) {
				m.On("GetAuthorizationCode", mock.Anything, "valid-code").Return(&domain.AuthorizationCode{
					Code:      "valid-code",
					ClientID:  "test-client",
					UserID:    "test-user",
					Scopes:    []string{"openid", "profile"},
					ExpiresAt: time.Now().Add(time.Hour),
				}, nil)
				m.On("FindClientByID", mock.Anything, "test-client").Return(&domain.OAuth2Client{
					ID: "test-client",
				}, nil)
				m.On("DeleteAuthorizationCode", mock.Anything, "valid-code").Return(nil)
			},
			wantClient: &domain.OAuth2Client{ID: "test-client"},
			wantUserID: "test-user",
			wantScopes: []string{"openid", "profile"},
			wantErr:    nil,
		},
		{
			name: "code not found",
			code: "invalid-code",
			setupMock: func(m *MockOAuth2Repository) {
				m.On("GetAuthorizationCode", mock.Anything, "invalid-code").Return(nil, domain.ErrInvalidAuthorizationCode)
			},
			wantErr: domain.ErrInvalidAuthorizationCode,
		},
		{
			name: "expired code",
			code: "expired-code",
			setupMock: func(m *MockOAuth2Repository) {
				m.On("GetAuthorizationCode", mock.Anything, "expired-code").Return(&domain.AuthorizationCode{
					Code:      "expired-code",
					ExpiresAt: time.Now().Add(-time.Hour),
				}, nil)
			},
			wantErr: domain.ErrAuthorizationCodeExpired,
		},
		{
			name: "client not found",
			code: "valid-code",
			setupMock: func(m *MockOAuth2Repository) {
				m.On("GetAuthorizationCode", mock.Anything, "valid-code").Return(&domain.AuthorizationCode{
					Code:      "valid-code",
					ClientID:  "non-existent",
					ExpiresAt: time.Now().Add(time.Hour),
				}, nil)
				m.On("FindClientByID", mock.Anything, "non-existent").Return(nil, domain.ErrClientNotFound)
			},
			wantErr: domain.ErrClientNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockOAuth2Repository)
			tt.setupMock(mockRepo)

			service := NewOAuth2Service(mockRepo, zap.NewNop())
			client, userID, scopes, err := service.ValidateAuthorizationCode(context.Background(), tt.code)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, client)
				assert.Empty(t, userID)
				assert.Nil(t, scopes)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantClient, client)
				assert.Equal(t, tt.wantUserID, userID)
				assert.Equal(t, tt.wantScopes, scopes)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestOAuth2Service_ValidatePKCE(t *testing.T) {
	tests := []struct {
		name                string
		codeVerifier        string
		codeChallenge       string
		codeChallengeMethod string
		wantErr             error
	}{
		{
			name:                "success S256",
			codeVerifier:        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			codeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			codeChallengeMethod: "S256",
			wantErr:             nil,
		},
		{
			name:                "success plain",
			codeVerifier:        "verifier",
			codeChallenge:       "verifier",
			codeChallengeMethod: "plain",
			wantErr:             nil,
		},
		{
			name:                "invalid method",
			codeVerifier:        "verifier",
			codeChallenge:       "challenge",
			codeChallengeMethod: "invalid",
			wantErr:             domain.ErrInvalidCodeChallengeMethod,
		},
		{
			name:                "challenge mismatch S256",
			codeVerifier:        "verifier",
			codeChallenge:       "invalid",
			codeChallengeMethod: "S256",
			wantErr:             domain.ErrInvalidCodeChallenge,
		},
		{
			name:                "challenge mismatch plain",
			codeVerifier:        "verifier",
			codeChallenge:       "invalid",
			codeChallengeMethod: "plain",
			wantErr:             domain.ErrInvalidCodeChallenge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := NewOAuth2Service(nil, zap.NewNop())
			err := service.ValidatePKCE(context.Background(), tt.codeVerifier, tt.codeChallenge, tt.codeChallengeMethod)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
