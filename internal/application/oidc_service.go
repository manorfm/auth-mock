package application

import (
	"context"
	"net/http"
	"strings"
	"time"

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

type accessTokenIssuer interface {
	GenerateAccessToken(ctx context.Context, subject, name, userType string, roles, channels, audiences, scopes []string, expiresIn time.Duration) (string, error)
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

// getServerURL determines the server URL based on context, headers, or config.
func (s *OIDCService) getServerURL(ctx context.Context) string {
	s.logger.Debug("getServerURL called")
	if r, ok := ctx.Value(domain.RequestKey).(*http.Request); ok {
		s.logger.Debug("Request object found in context", zap.Any("requestURL", r.URL), zap.String("requestHost", r.Host), zap.Any("requestHeader", r.Header))
		// Check for X-Forwarded headers first
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			if host := r.Header.Get("X-Forwarded-Host"); host != "" {
				s.logger.Debug("Using X-Forwarded headers for server URL", zap.String("proto", proto), zap.String("host", host))
				return proto + "://" + host
			}
		}

		host := r.Host
		if host != "" {
			scheme := r.URL.Scheme
			if scheme == "" {
				if r.TLS != nil {
					scheme = "https"
				} else {
					scheme = "http"
				}
			}
			s.logger.Debug("Using request's scheme and host for server URL", zap.String("scheme", scheme), zap.String("host", host))
			return scheme + "://" + host
		}
		s.logger.Debug("Request object present, but Host was empty", zap.Any("requestURL", r.URL))
	} else {
		s.logger.Debug("Request object NOT found in context via domain.RequestKey")
	}
	s.logger.Warn("Falling back to ServerURL from config for OIDC discovery.", zap.String("fallbackURL", s.config.ServerURL))
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
	secret, err := s.totpService.GetTOTPSecret(ctx, user.ID.String())
	if err == nil && secret != "" {
		amr = append(amr, "totp")
	}

	emailVerified := user.Status == domain.UserStatusActive || user.Status == domain.UserStatusChangePassword

	return &domain.UserInfo{
		Sub:           user.ID.String(),
		Name:          user.Name,
		Email:         user.Email,
		EmailVerified: emailVerified,
		Phone:         user.Phone,
		CPF:           user.CPF,
		AMR:           amr,
	}, nil
}

func (s *OIDCService) GetOpenIDConfiguration(ctx context.Context) (map[string]interface{}, error) {
	s.logger.Debug("Getting OpenID configuration")

	if s.config == nil {
		s.logger.Error("Configuration is nil")
		return nil, domain.ErrInternal
	}

	origin := strings.TrimSuffix(s.getServerURL(ctx), "/")
	base := s.config.EffectiveAPIBasePath()
	issuer := origin
	if base != "/" {
		issuer = origin + base
	}

	return map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth2/authorize",
		"token_endpoint":                        issuer + "/oauth2/token",
		"userinfo_endpoint":                     issuer + "/oauth2/userinfo",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code", "token", "id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"claims_supported":                      []string{"sub", "iss", "name", "email", "email_verified", "phone_number", "cpf"},
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
	tokenPair, err := s.jwtService.GenerateTokenPair(ctx, user)
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
	if claims.RegisteredClaims == nil || claims.ID == "" || claims.ExpiresAt == nil {
		s.logger.Error("Invalid refresh token claims for rotation")
		return nil, domain.ErrInvalidCredentials
	}
	if err := s.jwtService.BlacklistToken(claims.ID, claims.ExpiresAt.Time); err != nil {
		s.logger.Error("Failed to blacklist refresh token",
			zap.String("token_id", claims.ID),
			zap.Error(err))
		return nil, domain.ErrInternal
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
	tokenPair, err := s.jwtService.GenerateTokenPair(ctx, user)
	if err != nil {
		s.logger.Error("Failed to generate token pair",
			zap.Error(err))
		return nil, domain.ErrInternal
	}

	return tokenPair, nil
}

func (s *OIDCService) IssueClientCredentialsAccess(ctx context.Context, clientID, clientSecret, scope string) (*domain.OAuth2ClientCredentialsResponse, error) {
	client, err := s.oauth2Service.ValidateClientCredentials(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	if !containsString(client.GrantTypes, "client_credentials") {
		return nil, domain.ErrInvalidClient
	}
	if len(client.M2MRoles) == 0 || len(client.M2MAudiences) == 0 {
		return nil, domain.ErrOAuth2ClientCredentialsConfig
	}
	requestedScopes := splitScope(scope)
	if len(requestedScopes) == 0 {
		return nil, domain.ErrInvalidScope
	}
	for _, requested := range requestedScopes {
		if !containsString(client.Scopes, requested) {
			return nil, domain.ErrInvalidScope
		}
	}
	expiresIn := s.config.JWTAccessDuration
	issuer, ok := s.jwtService.(accessTokenIssuer)
	if !ok {
		return nil, domain.ErrTokenGeneration
	}
	token, err := issuer.GenerateAccessToken(ctx, client.ID, client.ID, domain.UserTypeMachine, client.M2MRoles, nil, client.M2MAudiences, requestedScopes, expiresIn)
	if err != nil {
		return nil, err
	}
	return &domain.OAuth2ClientCredentialsResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int64(expiresIn / time.Second),
		Scope:       strings.Join(requestedScopes, " "),
	}, nil
}

func splitScope(scope string) []string {
	parts := strings.Fields(scope)
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, p := range parts {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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
