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

// TokenEndpointResponse define a estrutura de resposta para o endpoint de token,
// omitindo o refresh_token que será enviado como cookie.
type TokenEndpointResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"` // Geralmente "Bearer"
	ExpiresIn   int64  `json:"expires_in"` // Duração em segundos
	IDToken     string `json:"id_token,omitempty"`
	// RefreshToken é omitido, pois será enviado como cookie
}

type OIDCHandler struct {
	oidcService          domain.OIDCService
	jwtService           domain.JWTService
	logger               *zap.Logger
	refreshTokenDuration time.Duration // Adicionado para consistência com AuthHandler
}

func NewOIDCHandler(oidcService domain.OIDCService, jwtService domain.JWTService, logger *zap.Logger /* TODO: Adicionar config */) *OIDCHandler {
	// TODO: Obter refreshTokenDuration da configuração
	// Exemplo: refreshTokenDuration := cfg.JWTRefreshDuration
	// Por agora, vou definir um valor fixo, mas isso DEVE ser da config.
	refreshTokenDuration := 24 * 7 * time.Hour // Exemplo: 7 dias

	return &OIDCHandler{
		oidcService:          oidcService,
		jwtService:           jwtService,
		logger:               logger,
		refreshTokenDuration: refreshTokenDuration, // Adicionado
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
			errors.RespondWithError(w, err.(domain.Error)) // Garantir que err seja do tipo domain.Error ou tratar
			return
		}
		// O refresh token de ExchangeCode também deve ser tratado via cookie.
		// A lógica de resposta comum no final do handler cuidará disso.

	case "refresh_token":
		// 1. Tentar ler o refresh token do cookie
		cookie, errCookie := r.Cookie("refresh_token")
		actualRefreshToken := ""
		if errCookie == nil && cookie.Value != "" {
			actualRefreshToken = cookie.Value
			h.logger.Debug("Refresh token read from cookie")
		} else {
			// 2. Se não estiver no cookie, tentar ler do corpo JSON (fallback ou configuração)
			if req.RefreshToken != "" {
				actualRefreshToken = req.RefreshToken
				h.logger.Debug("Refresh token read from JSON body request")
			}
		}

		if actualRefreshToken == "" {
			h.logger.Error("Missing refresh token from both cookie and request body")
			// TODO: Considerar se o erro deve ser mais específico (ex: ErrMissingToken)
			// ou se ErrInvalidField é apropriado.
			// Por agora, mantendo ErrInvalidField para consistência com a lógica anterior.
			errors.RespondWithError(w, domain.ErrInvalidField)
			return
		}

		// Limpar o campo RefreshToken da requisição se ele foi lido do cookie,
		// para evitar confusão ou uso acidental posteriormente.
		// Não é estritamente necessário se actualRefreshToken for usado consistentemente.
		// req.RefreshToken = "" // Opcional

		tokenPair, err = h.oidcService.RefreshToken(r.Context(), actualRefreshToken)
		if err != nil {
			h.logger.Error("RefreshToken service call failed", zap.Error(err))
			// Se o refresh token for inválido (ex: expirado, revogado),
			// o cookie antigo deve ser removido.
			if err == domain.ErrInvalidCredentials || err == domain.ErrTokenExpired { // Adicionar outros erros relevantes
				http.SetCookie(w, &http.Cookie{
					Name:     "refresh_token",
					Value:    "",
					Path:     "/", // Mesmo path usado ao definir
					Expires:  time.Unix(0, 0), // Expira imediatamente
					HttpOnly: true,
					Secure:   true, // Manter consistência
					SameSite: http.SameSiteStrictMode,
				})
			}

			switch err {
			case domain.ErrInvalidCredentials, domain.ErrTokenExpired: // Assumindo que ErrTokenExpired pode ser retornado
				errors.RespondWithError(w, domain.ErrInvalidCredentials) // Ou um erro mais específico de token inválido
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

	h.logger.Debug("Token exchange successful", zap.String("grant_type", req.GrantType))

	// O oidcService.RefreshToken (e ExchangeCode) retorna um domain.TokenPair.
	// Precisamos extrair o AccessToken e o RefreshToken (novo) dele.
	// O IDToken pode não estar presente em domain.TokenPair; assumimos que o serviço OIDC
	// o adicionaria se necessário, ou que a estrutura TokenPair precisaria ser estendida
	// ou que o serviço retornaria uma estrutura mais rica.
	// Por agora, vamos focar em AccessToken e o novo RefreshToken.

	// Definir o novo refresh_token (se houver e se a rotação estiver habilitada) como cookie.
	// Se tokenPair.RefreshToken estiver vazio, significa que o refresh token não foi rotacionado
	// e o antigo (do cookie) ainda é válido (embora isso seja menos comum para refresh_token grant).
	// Se um novo é emitido, ele DEVE ser usado a partir de agora.
	if tokenPair.RefreshToken != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    tokenPair.RefreshToken,
			Expires:  time.Now().Add(h.refreshTokenDuration),
			HttpOnly: true,
			Secure:   true,
			Path:     "/", // Mesmo path do cookie original
			SameSite: http.SameSiteStrictMode,
		})
		h.logger.Debug("New refresh token set in cookie")
	} else {
		// Se o serviço não retornou um NOVO refresh token, e estamos no grant_type=refresh_token,
		// isso pode indicar que o refresh token original não é rotacionado.
		// Ou, se a intenção é sempre rotacionar, então tokenPair.RefreshToken nunca deveria estar vazio aqui.
		// Se o refresh token original do cookie foi usado e é válido, e nenhum novo foi emitido,
		// o cookie original permanece. Se o refresh token original do JSON body foi usado,
		// e nenhum novo foi emitido, então o cliente não recebe um novo refresh token via cookie.
		// Esta lógica depende da estratégia de rotação de refresh token do oidcService.
		h.logger.Debug("No new refresh token returned by service, original refresh token (if from cookie) remains.")
	}

	// Construir a resposta JSON apenas com o access_token e outros campos relevantes.
	// A duração do access_token geralmente vem da configuração do JWTService.
	// O OIDCService deveria idealmente fornecer essa informação.
	// Por simplicidade, vamos assumir que o AccessToken é o único campo principal por agora,
	// além dos campos padrão OAuth2.
	// Em uma implementação completa, o OIDCService.ExchangeCode ou RefreshToken retornaria uma struct
	// mais rica contendo TokenType, ExpiresIn, IDToken, etc.
	// Para este exemplo, vamos mockar alguns valores.
	responsePayload := TokenEndpointResponse{
		AccessToken: tokenPair.AccessToken,
		TokenType:   "Bearer",
		// ExpiresIn: Deveria vir da duração do access token. Ex: int64(cfg.JWTAccessDuration.Seconds()),
		// IDToken: Se aplicável e retornado pelo serviço.
	}
	// Tentativa de obter a duração do access token do próprio token (se for JWT e tiver 'exp')
	// Isto é complexo e geralmente o serviço de token define explicitamente.
	// Por agora, vou omitir ExpiresIn e IDToken da resposta mockada para focar na mudança do refresh_token.
	// Em um cenário real, estes seriam populados corretamente.

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(responsePayload); err != nil {
		h.logger.Error("Failed to encode token endpoint response", zap.Error(err))
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
