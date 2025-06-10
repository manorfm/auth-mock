package application

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
)

type OAuth2Service struct {
	oauthRepo domain.OAuth2Repository
	logger    *zap.Logger
}

func NewOAuth2Service(oauthRepo domain.OAuth2Repository, logger *zap.Logger) *OAuth2Service {
	return &OAuth2Service{
		oauthRepo: oauthRepo,
		logger:    logger,
	}
}

func (s *OAuth2Service) ValidateClient(ctx context.Context, clientID, redirectURI string) (*domain.OAuth2Client, error) {
	s.logger.Debug("Validating client",
		zap.String("client_id", clientID),
		zap.String("redirect_uri", redirectURI))

	// Get client from repository
	client, err := s.oauthRepo.FindClientByID(ctx, clientID)
	if err != nil {
		s.logger.Error("Failed to find client",
			zap.String("client_id", clientID),
			zap.Error(err))
		return nil, domain.ErrClientNotFound
	}

	// Validate redirect URI
	valid := false
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			valid = true
			break
		}
	}
	if !valid {
		s.logger.Error("Invalid redirect URI",
			zap.String("client_id", clientID),
			zap.String("redirect_uri", redirectURI))
		return nil, domain.ErrInvalidRedirectURI
	}

	return client, nil
}

func (s *OAuth2Service) GenerateAuthorizationCode(ctx context.Context, clientID, userID string, scopes []string, codeChallenge, codeChallengeMethod string) (string, error) {
	s.logger.Debug("Generating authorization code",
		zap.String("client_id", clientID),
		zap.String("user_id", userID),
		zap.Strings("scopes", scopes))

	// Generate random code
	code := ulid.Make().String()

	// Create authorization code
	authCode := &domain.AuthorizationCode{
		Code:                code,
		ClientID:            clientID,
		UserID:              userID,
		Scopes:              scopes,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}

	// Store code in repository
	err := s.oauthRepo.CreateAuthorizationCode(ctx, authCode)
	if err != nil {
		s.logger.Error("Failed to store authorization code",
			zap.Error(err))
		return "", domain.ErrInternal
	}

	return code, nil
}

func (s *OAuth2Service) ValidateAuthorizationCode(ctx context.Context, code string) (*domain.OAuth2Client, string, []string, error) {
	s.logger.Debug("Validating authorization code",
		zap.String("code", code))

	// Get code from repository
	authCode, err := s.oauthRepo.GetAuthorizationCode(ctx, code)
	if err != nil {
		s.logger.Error("Failed to find authorization code",
			zap.String("code", code),
			zap.Error(err))
		return nil, "", nil, domain.ErrInvalidAuthorizationCode
	}

	// Check if code is expired
	if time.Now().After(authCode.ExpiresAt) {
		s.logger.Error("Authorization code expired",
			zap.String("code", code),
			zap.Time("expires_at", authCode.ExpiresAt))
		return nil, "", nil, domain.ErrAuthorizationCodeExpired
	}

	// Get client from repository
	client, err := s.oauthRepo.FindClientByID(ctx, authCode.ClientID)
	if err != nil {
		s.logger.Error("Failed to find client",
			zap.String("client_id", authCode.ClientID),
			zap.Error(err))
		return nil, "", nil, domain.ErrClientNotFound
	}

	// Delete the authorization code after use
	err = s.oauthRepo.DeleteAuthorizationCode(ctx, code)
	if err != nil {
		s.logger.Error("Failed to delete authorization code",
			zap.String("code", code),
			zap.Error(err))
		// Don't return error here as the code was still valid
	}

	return client, authCode.UserID, authCode.Scopes, nil
}

func (s *OAuth2Service) ValidatePKCE(ctx context.Context, codeVerifier, codeChallenge, codeChallengeMethod string) error {
	s.logger.Debug("Validating PKCE",
		zap.String("code_verifier", codeVerifier),
		zap.String("code_challenge", codeChallenge),
		zap.String("code_challenge_method", codeChallengeMethod))

	// Validate code challenge method
	if codeChallengeMethod != "S256" && codeChallengeMethod != "plain" {
		s.logger.Error("Invalid code challenge method",
			zap.String("method", codeChallengeMethod))
		return domain.ErrInvalidCodeChallengeMethod
	}

	// Calculate expected code challenge
	var expectedChallenge string
	if codeChallengeMethod == "S256" {
		hash := sha256.Sum256([]byte(codeVerifier))
		expectedChallenge = base64.RawURLEncoding.EncodeToString(hash[:])
	} else {
		expectedChallenge = codeVerifier
	}

	// Compare challenges
	if expectedChallenge != codeChallenge {
		s.logger.Error("Code challenge mismatch",
			zap.String("expected", expectedChallenge),
			zap.String("received", codeChallenge))
		return domain.ErrInvalidCodeChallenge
	}

	return nil
}
