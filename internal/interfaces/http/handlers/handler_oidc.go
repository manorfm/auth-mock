package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/go-playground/validator/v10"
	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/interfaces/http/errors"
	"go.uber.org/zap"
)

// TokenRequest represents the token request structure
type TokenRequest struct {
	GrantType    string `json:"grantType" validate:"required"`
	Code         string `json:"code"`
	RefreshToken string `json:"refreshToken"`
	ClientID     string `json:"clientId" validate:"required"`
	ClientSecret string `json:"clientSecret" validate:"required"`
	RedirectURI  string `json:"redirectUri"`
	CodeVerifier string `json:"codeVerifier"`
}

type OIDCHandler struct {
	oidcService domain.OIDCService
	jwtService  domain.JWTService
	logger      *zap.Logger
}

func NewOIDCHandler(oidcService domain.OIDCService, jwtService domain.JWTService, logger *zap.Logger) *OIDCHandler {
	return &OIDCHandler{
		oidcService: oidcService,
		jwtService:  jwtService,
		logger:      logger,
	}
}

func (h *OIDCHandler) GetUserInfoHandler(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("Getting user info from context",
		zap.Any("sub", r.Context().Value("sub")),
		zap.Any("roles", r.Context().Value("roles")))

	userID, ok := r.Context().Value("sub").(string)
	if !ok || userID == "" {
		h.logger.Error("Failed to get user ID from context",
			zap.Any("user_id", r.Context().Value("sub")),
			zap.Bool("ok", ok))
		errors.RespondWithError(w, domain.ErrUnauthorized)
		return
	}

	userInfo, err := h.oidcService.GetUserInfo(r.Context(), userID)
	if err != nil {
		h.logger.Error("Failed to get user info", zap.Error(err))
		errors.RespondWithError(w, err.(domain.Error))
		return
	}

	if userInfo == nil {
		h.logger.Error("User info is nil")
		errors.RespondWithError(w, domain.ErrUserNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(userInfo); err != nil {
		h.logger.Error("Failed to encode user info response", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}
}

func (h *OIDCHandler) GetJWKSHandler(w http.ResponseWriter, r *http.Request) {
	jwks, err := h.jwtService.GetJWKS(r.Context())
	if err != nil {
		h.logger.Error("Failed to get JWKS", zap.Error(err))
		errors.RespondWithError(w, err.(domain.Error))
		return
	}

	if jwks == nil {
		h.logger.Error("JWKS is nil")
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		h.logger.Error("Failed to encode JWKS response", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}
}

func (h *OIDCHandler) GetOpenIDConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	config, err := h.oidcService.GetOpenIDConfiguration(r.Context())
	if err != nil {
		h.logger.Error("Failed to get OpenID configuration",
			zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}

	if config == nil {
		h.logger.Error("OpenID configuration is nil")
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(config); err != nil {
		h.logger.Error("Failed to encode OpenID configuration response",
			zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}
}

func (h *OIDCHandler) TokenHandler(w http.ResponseWriter, r *http.Request) {
	var req TokenRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error("Failed to decode request body", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInvalidRequestBody)
		return
	}

	// Validate request body
	var validate = validator.New()
	if err := validate.Struct(req); err != nil {
		createErrorMessage(w, err)
		return
	}

	h.logger.Debug("Received token request",
		zap.String("grant_type", req.GrantType),
		zap.String("client_id", req.ClientID),
		zap.String("redirect_uri", req.RedirectURI))

	var tokenPair *domain.TokenPair
	var err error

	switch req.GrantType {
	case "authorization_code":
		if req.Code == "" {
			h.logger.Error("Missing authorization code")
			errors.RespondWithError(w, domain.ErrInvalidField)
			return
		}

		if req.RedirectURI == "" {
			h.logger.Error("Missing redirect URI")
			errors.RespondWithError(w, domain.ErrInvalidField)
			return
		}

		if req.CodeVerifier == "" {
			h.logger.Error("Missing code verifier")
			errors.RespondWithError(w, domain.ErrInvalidPKCE)
			return
		}

		tokenPair, err = h.oidcService.ExchangeCode(r.Context(), req.Code, req.CodeVerifier)
		if err != nil {
			h.logger.Error("ExchangeCode failed", zap.Error(err))
			errors.RespondWithError(w, err.(domain.Error))

			return
		}

	case "refresh_token":
		if req.RefreshToken == "" {
			h.logger.Error("Missing refresh token")
			errors.RespondWithError(w, domain.ErrInvalidField)
			return
		}

		tokenPair, err = h.oidcService.RefreshToken(r.Context(), req.RefreshToken)
		if err != nil {
			h.logger.Error("RefreshToken failed", zap.Error(err))
			switch err {
			case domain.ErrInvalidCredentials:
				errors.RespondWithError(w, domain.ErrInvalidCredentials)
			default:
				errors.RespondWithError(w, domain.ErrInternal)
			}
			return
		}

	default:
		h.logger.Error("Unsupported grant type",
			zap.String("grant_type", req.GrantType))
		errors.RespondWithError(w, domain.ErrInvalidField)
		return
	}

	if tokenPair == nil {
		h.logger.Error("Token exchange returned nil tokens")
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}

	h.logger.Debug("Token exchange successful",
		zap.String("grant_type", req.GrantType))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(tokenPair); err != nil {
		h.logger.Error("Failed to encode response", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}
}

func (h *OIDCHandler) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	// Get query parameters
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	scope := r.URL.Query().Get("scope")
	responseType := r.URL.Query().Get("response_type")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

	h.logger.Debug("Received authorization request",
		zap.String("client_id", clientID),
		zap.String("redirect_uri", redirectURI),
		zap.String("state", state),
		zap.String("scope", scope),
		zap.String("response_type", responseType),
		zap.String("code_challenge", codeChallenge),
		zap.String("code_challenge_method", codeChallengeMethod))

	// Validate required parameters
	if clientID == "" || redirectURI == "" {
		details := []errors.ErrorDetail{
			{
				Field:   "client_id",
				Message: "client_id is required",
			},
			{
				Field:   "redirect_uri",
				Message: "redirect_uri is required",
			},
		}
		errors.RespondErrorWithDetails(w, domain.ErrInvalidField, details)
		return
	}

	// Validate response_type
	if responseType != "code" {
		h.logger.Error("Unsupported response type", zap.String("response_type", responseType))
		errors.RespondWithError(w, domain.ErrInvalidField)
		return
	}

	// Validate PKCE parameters
	if codeChallenge == "" {
		h.logger.Error("Missing code challenge")
		errors.RespondWithError(w, domain.ErrInvalidPKCE)
		return
	}

	if codeChallengeMethod != "" && codeChallengeMethod != "S256" && codeChallengeMethod != "plain" {
		h.logger.Error("Unsupported code challenge method", zap.String("method", codeChallengeMethod))
		errors.RespondWithError(w, domain.ErrInvalidField)
		return
	}

	// Get user ID from context (set by auth middleware)
	userID, ok := r.Context().Value("sub").(string)
	if !ok || userID == "" {
		h.logger.Error("User not authenticated")
		errors.RespondWithError(w, domain.ErrUnauthorized)
		return
	}

	// Add PKCE parameters to context
	ctx := context.WithValue(r.Context(), "code_challenge", codeChallenge)
	ctx = context.WithValue(ctx, "code_challenge_method", codeChallengeMethod)

	// Generate authorization code
	code, err := h.oidcService.Authorize(ctx, clientID, redirectURI, state, scope)
	if err != nil {
		h.logger.Error("Authorization failed", zap.Error(err))
		switch err {
		case domain.ErrInvalidClient:
			errors.RespondWithError(w, domain.ErrInvalidClient)
		case domain.ErrInvalidCredentials:
			errors.RespondWithError(w, domain.ErrUnauthorized)
		default:
			errors.RespondWithError(w, domain.ErrInternal)
		}
		return
	}

	// Parse and validate redirect URI
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		h.logger.Error("Failed to parse redirect URI",
			zap.String("redirect_uri", redirectURI),
			zap.Error(err))
		errors.RespondWithError(w, domain.ErrInvalidField)
		return
	}

	// Add authorization code and state to redirect URL
	q := redirectURL.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	redirectURL.RawQuery = q.Encode()

	h.logger.Debug("Redirecting to client",
		zap.String("redirect_uri", redirectURL.String()))

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}
