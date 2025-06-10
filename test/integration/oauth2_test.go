package integration

import (
	"context"
	"testing"
	"time"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/infrastructure/repository"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestOAuth2Repository_Integration(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	// Setup repository
	oauth2Repo := repository.NewOAuth2Repository(logger)
	userRepo := repository.NewUserRepository(logger)

	t.Run("Client Management", func(t *testing.T) {
		// Create a new client
		client := &domain.OAuth2Client{
			ID:           "test-client",
			Secret:       "test-secret",
			RedirectURIs: []string{"http://localhost:8080/callback"},
			GrantTypes:   []string{"authorization_code"},
			Scopes:       []string{"openid", "profile"},
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		err := oauth2Repo.CreateClient(ctx, client)
		require.NoError(t, err)

		// Get client by ID
		retrievedClient, err := oauth2Repo.FindClientByID(ctx, "test-client")
		require.NoError(t, err)
		assert.Equal(t, client.ID, retrievedClient.ID)
		assert.Equal(t, client.Secret, retrievedClient.Secret)
		assert.Equal(t, client.RedirectURIs, retrievedClient.RedirectURIs)
		assert.Equal(t, client.GrantTypes, retrievedClient.GrantTypes)
		assert.Equal(t, client.Scopes, retrievedClient.Scopes)

		// Update client
		client.Scopes = append(client.Scopes, "email")
		client.UpdatedAt = time.Now()
		err = oauth2Repo.UpdateClient(ctx, client)
		require.NoError(t, err)

		// Verify update
		updatedClient, err := oauth2Repo.FindClientByID(ctx, "test-client")
		require.NoError(t, err)
		assert.Equal(t, client.Scopes, updatedClient.Scopes)

		// List clients
		clients, err := oauth2Repo.ListClients(ctx)
		require.NoError(t, err)
		assert.Len(t, clients, 1)
		assert.Equal(t, client.ID, clients[0].ID)

		// Delete client
		err = oauth2Repo.DeleteClient(ctx, "test-client")
		require.NoError(t, err)

		// Verify deletion
		_, err = oauth2Repo.FindClientByID(ctx, "test-client")
		assert.ErrorIs(t, err, domain.ErrClientNotFound)
	})

	t.Run("Authorization Code Management", func(t *testing.T) {
		// Insert a test user to satisfy the foreign key constraint
		user := &domain.User{
			ID:            ulid.Make(),
			Name:          "Test User",
			Email:         "test@example.com",
			Password:      "password123",
			Phone:         "1234567890",
			Roles:         []string{"user"},
			EmailVerified: true,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}
		err := userRepo.Create(ctx, user)
		require.NoError(t, err)

		// Now proceed with the authorization code test
		// Create a client first
		client := &domain.OAuth2Client{
			ID:           "test-client",
			Secret:       "test-secret",
			RedirectURIs: []string{"http://localhost:8080/callback"},
			GrantTypes:   []string{"authorization_code"},
			Scopes:       []string{"openid", "profile"},
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		err = oauth2Repo.CreateClient(ctx, client)
		require.NoError(t, err)

		// Create authorization code
		code := &domain.AuthorizationCode{
			Code:                "test-code",
			ClientID:            "test-client",
			UserID:              "test-user-id",
			Scopes:              []string{"openid", "profile"},
			ExpiresAt:           time.Now().Add(time.Hour),
			CreatedAt:           time.Now(),
			CodeVerifier:        "verifier",
			CodeChallenge:       "challenge",
			CodeChallengeMethod: "S256",
		}

		err = oauth2Repo.CreateAuthorizationCode(ctx, code)
		require.NoError(t, err)

		// Get authorization code
		retrievedCode, err := oauth2Repo.GetAuthorizationCode(ctx, "test-code")
		require.NoError(t, err)
		assert.Equal(t, code.Code, retrievedCode.Code)
		assert.Equal(t, code.ClientID, retrievedCode.ClientID)
		assert.Equal(t, code.UserID, retrievedCode.UserID)
		assert.Equal(t, code.Scopes, retrievedCode.Scopes)
		assert.Equal(t, code.CodeVerifier, retrievedCode.CodeVerifier)
		assert.Equal(t, code.CodeChallenge, retrievedCode.CodeChallenge)
		assert.Equal(t, code.CodeChallengeMethod, retrievedCode.CodeChallengeMethod)

		// Delete authorization code
		err = oauth2Repo.DeleteAuthorizationCode(ctx, "test-code")
		require.NoError(t, err)

		// Verify deletion
		_, err = oauth2Repo.GetAuthorizationCode(ctx, "test-code")
		assert.ErrorIs(t, err, domain.ErrInvalidAuthorizationCode)

		// Clean up client
		err = oauth2Repo.DeleteClient(ctx, "test-client")
		require.NoError(t, err)
	})
}
