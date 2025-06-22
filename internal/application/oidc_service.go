package application

import (
	"context"
	"net/http"
	"strings"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/infrastructure/config"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
)

type OIDCService struct {
	oauth2Service domain.OAuth2Service
	jwtService    domain.JWTService
	userRepo      domain.UserRepository
	totpService   domain.TOTPService
	config        *config.Config
	logger        *zap.Logger
}

func NewOIDCService(oauth2Service domain.OAuth2Service, jwtService domain.JWTService, userRepo domain.UserRepository, totpService domain.TOTPService, config *config.Config, logger *zap.Logger) *OIDCService {
	return &OIDCService{
		oauth2Service: oauth2Service,
		jwtService:    jwtService,
		userRepo:      userRepo,
		totpService:   totpService,
		config:        config,
		logger:        logger,
	}
}

func (s *OIDCService) getServerURL(ctx context.Context) string {
	if r, ok := ctx.Value(domain.RequestKey).(*http.Request); ok {
		// Check for X-Forwarded headers first
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			if host := r.Header.Get("X-Forwarded-Host"); host != "" {
				s.logger.Debug("Using X-Forwarded headers for server URL", zap.String("proto", proto), zap.String("host", host))
				return proto + "://" + host
			}
		}
		// If no X-Forwarded headers, try to use request's scheme and host
		if r.URL != nil {
			scheme := r.URL.Scheme
			if scheme == "" {
				// Infer scheme from TLS property if URL.Scheme is not set
				if r.TLS != nil {
					scheme = "https"
				} else {
					scheme = "http"
				}
			}
			host := r.Host // r.Host already includes port if specified
			if host != "" {
				s.logger.Debug("Using request's scheme and host for server URL", zap.String("scheme", scheme), zap.String("host", host))
				return scheme + "://" + host
			}
		}
	}
	// Fallback to config if request details are not available or sufficient
	s.logger.Warn("Falling back to ServerURL from config for OIDC discovery as request context or details are insufficient.", zap.String("fallbackURL", s.config.ServerURL))
	return s.config.ServerURL
}

func (s *OIDCService) GetUserInfo(ctx context.Context, userID string) (*domain.UserInfo, error) {
	s.logger.Debug("Getting user info",
		zap.String("user_id", userID))

	// Parse user ID
	id, err := ulid.Parse(userID)
	if err != nil {
		s.logger.Error("Invalid user ID",
			zap.String("user_id", userID),
			zap.Error(err))
		return nil, domain.ErrInvalidUserID
	}

	// Get user from repository
	user, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to find user",
			zap.String("user_id", userID),
			zap.Error(err))
		return nil, domain.ErrUserNotFound
	}

	amr := []string{"pwd"}
	secret, err := s.totpService.GetTOTPSecret(context.Background(), user.ID.String())
	if err == nil && secret != "" {
		amr = append(amr, "totp")
	}

	// Return user info
	return &domain.UserInfo{
		Sub:           user.ID.String(),
		Name:          user.Name,
		Email:         user.Email,
		EmailVerified: true,
		AMR:           amr,
	}, nil
}

func (s *OIDCService) GetOpenIDConfiguration(ctx context.Context) (map[string]interface{}, error) {
	s.logger.Debug("Getting OpenID configuration")

	if s.config == nil {
		s.logger.Error("Configuration is nil")
		return nil, domain.ErrInternal
	}

	serverURL := s.getServerURL(ctx)

	return map[string]interface{}{
		"issuer":                                serverURL,
		"authorization_endpoint":                serverURL + "/oauth2/authorize",
		"token_endpoint":                        serverURL + "/oauth2/token",
		"userinfo_endpoint":                     serverURL + "/oauth2/userinfo",
		"jwks_uri":                              serverURL + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code", "token", "id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"claims_supported":                      []string{"sub", "iss", "name", "email"},
	}, nil
}

func (s *OIDCService) ExchangeCode(ctx context.Context, code string, codeVerifier string) (*domain.TokenPair, error) {
	s.logger.Debug("Exchanging authorization code",
		zap.String("code", code))

	// Get authorization code from repository
	client, userID, scopes, err := s.oauth2Service.ValidateAuthorizationCode(ctx, code)
	if err != nil {
		return nil, err
	}

	// Parse user ID
	id, err := ulid.Parse(userID)
	if err != nil {
		s.logger.Error("Invalid user ID in authorization code",
			zap.String("user_id", userID),
			zap.Error(err))
		return nil, domain.ErrInvalidUserID
	}

	// Get user from repository
	user, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to find user",
			zap.String("user_id", userID),
			zap.Error(err))
		return nil, domain.ErrUserNotFound
	}

	// Generate token pair with scopes
	tokenPair, err := s.jwtService.GenerateTokenPair(user.ID, user.Roles)
	if err != nil {
		s.logger.Error("Failed to generate token pair",
			zap.Error(err))
		return nil, domain.ErrFailedGenerateToken
	}

	// Log successful exchange
	s.logger.Info("Successfully exchanged authorization code",
		zap.String("client_id", client.ID),
		zap.String("user_id", userID),
		zap.Strings("scopes", scopes))

	return tokenPair, nil
}

func (s *OIDCService) RefreshToken(ctx context.Context, refreshToken string) (*domain.TokenPair, error) {
	s.logger.Debug("Refreshing token")

	// Validate refresh token
	claims, err := s.jwtService.ValidateToken(refreshToken)
	if err != nil {
		s.logger.Error("Failed to validate refresh token",
			zap.Error(err))
		return nil, domain.ErrInvalidCredentials
	}

	// Parse user ID
	userID, err := ulid.Parse(claims.RegisteredClaims.Subject)
	if err != nil {
		s.logger.Error("Invalid user ID in refresh token",
			zap.String("user_id", claims.RegisteredClaims.Subject),
			zap.Error(err))
		return nil, domain.ErrInvalidUserID
	}

	// Get user from repository
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to find user",
			zap.String("user_id", claims.RegisteredClaims.Subject),
			zap.Error(err))
		return nil, domain.ErrInvalidCredentials
	}

	// Generate new token pair
	tokenPair, err := s.jwtService.GenerateTokenPair(user.ID, user.Roles)
	if err != nil {
		s.logger.Error("Failed to generate token pair",
			zap.Error(err))
		return nil, domain.ErrInternal
	}

	return tokenPair, nil
}

func (s *OIDCService) Authorize(ctx context.Context, clientID, redirectURI, state, scope string) (string, error) {
	s.logger.Debug("Authorizing request",
		zap.String("client_id", clientID),
		zap.String("redirect_uri", redirectURI),
		zap.String("state", state),
		zap.String("scope", scope))

	// Get user ID from context
	userID, ok := domain.GetSubject(ctx)
	if !ok {
		s.logger.Error("User ID not found in context")
		return "", domain.ErrUnauthorized
	}

	// Validate client
	client, err := s.oauth2Service.ValidateClient(ctx, clientID, redirectURI)
	if err != nil {
		return "", err
	}

	// Get code challenge from context
	codeChallenge, _ := domain.GetCodeChallenge(ctx)
	codeChallengeMethod, _ := domain.GetCodeChallengeMethod(ctx)

	// Parse and validate scopes
	requestedScopes := strings.Split(scope, " ")
	if len(requestedScopes) == 0 {
		s.logger.Error("No scopes provided")
		return "", domain.ErrInvalidScope
	}

	// Validate that all requested scopes are allowed for this client
	validScopes := make([]string, 0)
	for _, requestedScope := range requestedScopes {
		valid := false
		for _, allowedScope := range client.Scopes {
			if requestedScope == allowedScope {
				valid = true
				validScopes = append(validScopes, requestedScope)
				break
			}
		}
		if !valid {
			s.logger.Error("Invalid scope requested",
				zap.String("scope", requestedScope),
				zap.Strings("allowed_scopes", client.Scopes))
			return "", domain.ErrInvalidScope
		}
	}

	// Generate authorization code
	code, err := s.oauth2Service.GenerateAuthorizationCode(ctx, client.ID, userID, validScopes, codeChallenge, codeChallengeMethod)
	if err != nil {
		return "", err
	}

	return code, nil
}
