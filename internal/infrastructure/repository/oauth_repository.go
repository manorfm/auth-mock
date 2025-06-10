package repository

import (
	"context"

	"github.com/manorfm/auth-mock/internal/domain"
	"go.uber.org/zap"
)

// PostgresOAuth2Repository implements OAuth2Repository using PostgreSQL
type PostgresOAuth2Repository struct {
	clients            map[string]*domain.OAuth2Client
	authorizationCodes map[string]*domain.AuthorizationCode
	logger             *zap.Logger
}

// NewOAuth2Repository creates a new PostgresOAuth2Repository
func NewOAuth2Repository(logger *zap.Logger) domain.OAuth2Repository {
	return &PostgresOAuth2Repository{
		clients:            make(map[string]*domain.OAuth2Client),
		authorizationCodes: make(map[string]*domain.AuthorizationCode),
		logger:             logger,
	}
}

func (r *PostgresOAuth2Repository) CreateClient(ctx context.Context, client *domain.OAuth2Client) error {
	r.clients[client.ID] = client
	return nil
}

func (r *PostgresOAuth2Repository) FindClientByID(ctx context.Context, id string) (*domain.OAuth2Client, error) {
	client := &domain.OAuth2Client{}

	client, ok := r.clients[id]
	if !ok {
		return nil, domain.ErrClientNotFound
	}

	return client, nil
}

func (r *PostgresOAuth2Repository) UpdateClient(ctx context.Context, client *domain.OAuth2Client) error {
	r.clients[client.ID] = client
	return nil
}

func (r *PostgresOAuth2Repository) DeleteClient(ctx context.Context, id string) error {
	delete(r.clients, id)
	return nil
}

func (r *PostgresOAuth2Repository) ListClients(ctx context.Context) ([]*domain.OAuth2Client, error) {
	clients := make([]*domain.OAuth2Client, 0, len(r.clients))
	for _, client := range r.clients {
		clients = append(clients, client)
	}

	return clients, nil
}

func (r *PostgresOAuth2Repository) CreateAuthorizationCode(ctx context.Context, code *domain.AuthorizationCode) error {
	r.authorizationCodes[code.Code] = code
	return nil
}

func (r *PostgresOAuth2Repository) GetAuthorizationCode(ctx context.Context, code string) (*domain.AuthorizationCode, error) {
	authCode := &domain.AuthorizationCode{}

	authCode, ok := r.authorizationCodes[code]
	if !ok {
		return nil, domain.ErrInvalidAuthorizationCode
	}
	return authCode, nil
}

func (r *PostgresOAuth2Repository) DeleteAuthorizationCode(ctx context.Context, code string) error {
	delete(r.authorizationCodes, code)
	return nil
}
