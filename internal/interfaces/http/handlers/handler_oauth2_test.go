package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
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

func setupTest() (*OAuth2Handler, *MockOAuth2Repository) {
	logger, _ := zap.NewDevelopment()
	mockRepo := new(MockOAuth2Repository)
	handler := NewOAuth2Handler(mockRepo, logger)
	return handler, mockRepo
}

func TestCreateClientHandler(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    OAuth2ClientRequest
		mockSetup      func(*MockOAuth2Repository)
		expectedStatus int
		expectedError  bool
	}{
		{
			name: "Success",
			requestBody: OAuth2ClientRequest{
				ID:           "test-client",
				Secret:       "test-secret",
				RedirectURIs: []string{"http://localhost:8080/callback"},
				GrantTypes:   []string{"authorization_code"},
				Scopes:       []string{"openid", "profile"},
			},
			mockSetup: func(m *MockOAuth2Repository) {
				m.On("FindClientByID", mock.Anything, "test-client").Return(nil, domain.ErrInvalidClient)
				m.On("CreateClient", mock.Anything, mock.MatchedBy(func(client *domain.OAuth2Client) bool {
					return client.ID == "test-client" &&
						client.Secret == "test-secret" &&
						len(client.RedirectURIs) == 1 &&
						len(client.GrantTypes) == 1 &&
						len(client.Scopes) == 2
				})).Return(nil)
			},
			expectedStatus: http.StatusCreated,
			expectedError:  false,
		},
		{
			name: "Client Already Exists",
			requestBody: OAuth2ClientRequest{
				ID:           "existing-client",
				Secret:       "test-secret",
				RedirectURIs: []string{"http://localhost:8080/callback"},
				GrantTypes:   []string{"authorization_code"},
				Scopes:       []string{"openid", "profile"},
			},
			mockSetup: func(m *MockOAuth2Repository) {
				m.On("FindClientByID", mock.Anything, "existing-client").Return(&domain.OAuth2Client{
					ID:           "existing-client",
					Secret:       "test-secret",
					RedirectURIs: []string{"http://localhost:8080/callback"},
					GrantTypes:   []string{"authorization_code"},
					Scopes:       []string{"openid", "profile"},
					CreatedAt:    time.Now(),
					UpdatedAt:    time.Now(),
				}, nil)
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  true,
		},
		{
			name: "Invalid Request - Missing Required Fields",
			requestBody: OAuth2ClientRequest{
				ID: "test-client",
				// Missing other required fields
			},
			mockSetup:      func(m *MockOAuth2Repository) {},
			expectedStatus: http.StatusBadRequest,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockRepo := setupTest()
			tt.mockSetup(mockRepo)

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/oauth2/clients", bytes.NewBuffer(body))
			w := httptest.NewRecorder()

			handler.CreateClientHandler(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedError {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Contains(t, response, "message")
				assert.Contains(t, response, "code")
			} else {
				var client domain.OAuth2Client
				err := json.Unmarshal(w.Body.Bytes(), &client)
				assert.NoError(t, err)
				assert.Equal(t, tt.requestBody.ID, client.ID)
			}
		})
	}
}

func TestUpdateClientHandler(t *testing.T) {
	tests := []struct {
		name           string
		clientID       string
		requestBody    OAuth2ClientRequest
		mockSetup      func(*MockOAuth2Repository)
		expectedStatus int
		expectedError  bool
	}{
		{
			name:     "Success",
			clientID: "test-client",
			requestBody: OAuth2ClientRequest{
				ID:           "test-client",
				Secret:       "new-secret",
				RedirectURIs: []string{"http://localhost:8080/new-callback"},
				GrantTypes:   []string{"authorization_code"},
				Scopes:       []string{"openid", "profile", "email"},
			},
			mockSetup: func(m *MockOAuth2Repository) {
				existingClient := &domain.OAuth2Client{
					ID:           "test-client",
					Secret:       "old-secret",
					RedirectURIs: []string{"http://localhost:8080/callback"},
					GrantTypes:   []string{"authorization_code"},
					Scopes:       []string{"openid", "profile"},
					CreatedAt:    time.Now(),
					UpdatedAt:    time.Now(),
				}
				m.On("FindClientByID", mock.Anything, "test-client").Return(existingClient, nil)
				m.On("UpdateClient", mock.Anything, mock.MatchedBy(func(client *domain.OAuth2Client) bool {
					return client.ID == "test-client" &&
						client.Secret == "new-secret" &&
						len(client.RedirectURIs) == 1 &&
						len(client.GrantTypes) == 1 &&
						len(client.Scopes) == 3
				})).Return(nil)
			},
			expectedStatus: http.StatusOK,
			expectedError:  false,
		},
		{
			name:     "Client Not Found",
			clientID: "non-existent",
			requestBody: OAuth2ClientRequest{
				ID:           "non-existent",
				Secret:       "test-secret",
				RedirectURIs: []string{"http://localhost:8080/callback"},
				GrantTypes:   []string{"authorization_code"},
				Scopes:       []string{"openid", "profile"},
			},
			mockSetup: func(m *MockOAuth2Repository) {
				m.On("FindClientByID", mock.Anything, "non-existent").Return(nil, domain.ErrInvalidClient)
			},
			expectedStatus: http.StatusNotFound,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockRepo := setupTest()
			tt.mockSetup(mockRepo)

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPut, "/oauth2/clients/"+tt.clientID, bytes.NewBuffer(body))
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("id", tt.clientID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, chiCtx))
			w := httptest.NewRecorder()

			handler.UpdateClientHandler(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedError {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Contains(t, response, "message")
				assert.Contains(t, response, "code")
			} else {
				var client domain.OAuth2Client
				err := json.Unmarshal(w.Body.Bytes(), &client)
				assert.NoError(t, err)
				assert.Equal(t, tt.requestBody.Secret, client.Secret)
				assert.Equal(t, tt.requestBody.RedirectURIs, client.RedirectURIs)
				assert.Equal(t, tt.requestBody.Scopes, client.Scopes)
			}
		})
	}
}

func TestDeleteClientHandler(t *testing.T) {
	tests := []struct {
		name           string
		clientID       string
		mockSetup      func(*MockOAuth2Repository)
		expectedStatus int
		expectedError  bool
	}{
		{
			name:     "Success",
			clientID: "test-client",
			mockSetup: func(m *MockOAuth2Repository) {
				m.On("FindClientByID", mock.Anything, "test-client").Return(&domain.OAuth2Client{
					ID:           "test-client",
					Secret:       "test-secret",
					RedirectURIs: []string{"http://localhost:8080/callback"},
					GrantTypes:   []string{"authorization_code"},
					Scopes:       []string{"openid", "profile"},
					CreatedAt:    time.Now(),
					UpdatedAt:    time.Now(),
				}, nil)
				m.On("DeleteClient", mock.Anything, "test-client").Return(nil)
			},
			expectedStatus: http.StatusNoContent,
			expectedError:  false,
		},
		{
			name:     "Client Not Found",
			clientID: "non-existent",
			mockSetup: func(m *MockOAuth2Repository) {
				m.On("FindClientByID", mock.Anything, "non-existent").Return(nil, domain.ErrClientNotFound)
			},
			expectedStatus: http.StatusNotFound,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockRepo := setupTest()
			tt.mockSetup(mockRepo)

			req := httptest.NewRequest(http.MethodDelete, "/oauth2/clients/"+tt.clientID, nil)
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("id", tt.clientID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, chiCtx))
			w := httptest.NewRecorder()

			handler.DeleteClientHandler(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedError {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Contains(t, response, "message")
				assert.Contains(t, response, "code")
			}
		})
	}
}

func TestListClientsHandler(t *testing.T) {
	tests := []struct {
		name           string
		mockSetup      func(*MockOAuth2Repository)
		expectedStatus int
		expectedError  bool
		expectedCount  int
	}{
		{
			name: "Success",
			mockSetup: func(m *MockOAuth2Repository) {
				clients := []*domain.OAuth2Client{
					{
						ID:           "client1",
						Secret:       "secret1",
						RedirectURIs: []string{"http://localhost:8080/callback"},
						GrantTypes:   []string{"authorization_code"},
						Scopes:       []string{"openid", "profile"},
						CreatedAt:    time.Now(),
						UpdatedAt:    time.Now(),
					},
					{
						ID:           "client2",
						Secret:       "secret2",
						RedirectURIs: []string{"http://localhost:8080/callback"},
						GrantTypes:   []string{"authorization_code"},
						Scopes:       []string{"openid", "profile"},
						CreatedAt:    time.Now(),
						UpdatedAt:    time.Now(),
					},
				}
				m.On("ListClients", mock.Anything).Return(clients, nil)
			},
			expectedStatus: http.StatusOK,
			expectedError:  false,
			expectedCount:  2,
		},
		{
			name: "Empty List",
			mockSetup: func(m *MockOAuth2Repository) {
				m.On("ListClients", mock.Anything).Return([]*domain.OAuth2Client{}, nil)
			},
			expectedStatus: http.StatusOK,
			expectedError:  false,
			expectedCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockRepo := setupTest()
			tt.mockSetup(mockRepo)

			req := httptest.NewRequest(http.MethodGet, "/oauth2/clients", nil)
			w := httptest.NewRecorder()

			handler.ListClientsHandler(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedError {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Contains(t, response, "message")
				assert.Contains(t, response, "code")
			} else {
				var clients []*domain.OAuth2Client
				err := json.Unmarshal(w.Body.Bytes(), &clients)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedCount, len(clients))
			}
		})
	}
}

func TestGetClientHandler(t *testing.T) {
	tests := []struct {
		name           string
		clientID       string
		mockSetup      func(*MockOAuth2Repository)
		expectedStatus int
		expectedError  bool
	}{
		{
			name:     "Success",
			clientID: "test-client",
			mockSetup: func(m *MockOAuth2Repository) {
				client := &domain.OAuth2Client{
					ID:           "test-client",
					Secret:       "test-secret",
					RedirectURIs: []string{"http://localhost:8080/callback"},
					GrantTypes:   []string{"authorization_code"},
					Scopes:       []string{"openid", "profile"},
					CreatedAt:    time.Now(),
					UpdatedAt:    time.Now(),
				}
				m.On("FindClientByID", mock.Anything, "test-client").Return(client, nil)
			},
			expectedStatus: http.StatusOK,
			expectedError:  false,
		},
		{
			name:     "Client Not Found",
			clientID: "non-existent",
			mockSetup: func(m *MockOAuth2Repository) {
				m.On("FindClientByID", mock.Anything, "non-existent").Return(nil, domain.ErrInvalidClient)
			},
			expectedStatus: http.StatusNotFound,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockRepo := setupTest()
			tt.mockSetup(mockRepo)

			req := httptest.NewRequest(http.MethodGet, "/oauth2/clients/"+tt.clientID, nil)
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("id", tt.clientID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, chiCtx))
			w := httptest.NewRecorder()

			handler.GetClientHandler(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedError {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Contains(t, response, "message")
				assert.Contains(t, response, "code")
			} else {
				var client domain.OAuth2Client
				err := json.Unmarshal(w.Body.Bytes(), &client)
				assert.NoError(t, err)
				assert.Equal(t, tt.clientID, client.ID)
			}
		})
	}
}
