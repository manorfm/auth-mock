package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/interfaces/http/errors"
	"go.uber.org/zap"
)

// LoginResponsePayload defines the structure for the login response JSON body
type LoginResponsePayload struct {
	AccessToken string `json:"access_token"`
}

type HandlerAuth struct {
	authService domain.AuthService
	logger      *zap.Logger
	// TODO: Idealmente, a configuração deveria ser injetada de forma mais estruturada.
	// Por agora, vamos assumir que podemos acessá-la ou definir um valor padrão.
	// Para este exemplo, vou adicionar um campo para a duração do refresh token.
	// Em uma aplicação real, isso viria do objeto de configuração.
	refreshTokenDuration time.Duration
}

func NewAuthHandler(authService domain.AuthService, logger *zap.Logger /* TODO: Adicionar config aqui */) *HandlerAuth {
	// TODO: Obter refreshTokenDuration da configuração
	// Exemplo: refreshTokenDuration := cfg.JWTRefreshDuration
	// Por agora, vou definir um valor fixo, mas isso DEVE ser da config.
	refreshTokenDuration := 24 * 7 * time.Hour // Exemplo: 7 dias

	return &HandlerAuth{
		authService:          authService,
		logger:               logger,
		refreshTokenDuration: refreshTokenDuration,
	}
}

type VerifyEmailRequest struct {
	Email string `json:"email" validate:"required,email"`
	Code  string `json:"code" validate:"required"`
}

type RequestPasswordResetRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type ResetPasswordRequest struct {
	Email       string `json:"email" validate:"required,email"`
	Code        string `json:"code" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8"`
}

type MFARequest struct {
	Ticket string `json:"ticket" validate:"required"`
	Code   string `json:"code" validate:"required"`
}

func (h *HandlerAuth) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req domain.CreateUserRequest

	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errors.RespondWithError(w, domain.ErrInvalidRequestBody)
		return
	}

	var validate = validator.New()
	if err := validate.Struct(req); err != nil {
		createErrorMessage(w, err)
		return
	}

	user, err := h.authService.Register(r.Context(), req.Name, req.Email, req.Password, req.Phone, nil)
	if err != nil {
		h.logger.Error("failed to register user", zap.Error(err))
		errors.RespondWithError(w, err.(domain.Error))
		return
	}

	response := NewUserResponse(user)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(response)
}

func (h *HandlerAuth) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req domain.LoginRequest

	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errors.RespondWithError(w, domain.ErrInvalidRequestBody)
		return
	}

	var validate = validator.New()
	if err := validate.Struct(req); err != nil {
		h.logger.Debug("validation error", zap.Error(err))
		createErrorMessage(w, err)
		return
	}

	result, err := h.authService.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		h.logger.Debug("failed to login user", zap.Error(err))
		errors.RespondWithError(w, err.(domain.Error))
		return
	}

	// Verificar o tipo de resultado. Poderia ser *domain.TokenPair ou *domain.MFATicket.
	switch tokenResult := result.(type) {
	case *domain.TokenPair:
		// Se for TokenPair, definir o refresh token como cookie e retornar apenas o access token.
		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    tokenResult.RefreshToken,
			Expires:  time.Now().Add(h.refreshTokenDuration),
			HttpOnly: true,
			Secure:   true, // Assumir true para produção; pode ser condicional baseado no ambiente.
			Path:     "/",  // Ajustar se necessário um path mais específico para refresh.
			SameSite: http.SameSiteStrictMode,
		})

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(LoginResponsePayload{AccessToken: tokenResult.AccessToken}); err != nil {
			h.logger.Error("failed to encode login response", zap.Error(err))
			errors.RespondWithError(w, domain.ErrInternal)
			return
		}
	case *domain.MFATicket:
		// Se for MFATicket, retornar o ticket como antes.
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(tokenResult); err != nil {
			h.logger.Error("failed to encode mfa ticket response", zap.Error(err))
			errors.RespondWithError(w, domain.ErrInternal)
			return
		}
	default:
		// Tipo de resultado inesperado do AuthService.Login
		h.logger.Error("unexpected result type from authService.Login", zap.Any("result", result))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}
}

func createErrorMessage(w http.ResponseWriter, err error) {
	var details []errors.ErrorDetail
	for _, fe := range err.(validator.ValidationErrors) {

		field := pascalToCamel(fe.Field())

		details = append(details, errors.ErrorDetail{
			Field:   field,
			Message: validationMessage(fe),
		})
	}
	errors.RespondErrorWithDetails(w, domain.ErrInvalidField, details)
}

func validationMessage(fe validator.FieldError) string {
	field := pascalToCamel(fe.Field())
	switch fe.Tag() {
	case "required":
		return field + " is required"
	case "email":
		return "Invalid email format"
	case "min":
		return field + " must be at least " + fe.Param() + " long"
	default:
		return field + " is invalid"
	}
}

// Função para converter PascalCase para camelCase
func pascalToCamel(str string) string {
	if len(str) == 0 {
		return str
	}
	// Converte a primeira letra para minúscula
	return strings.ToLower(string(str[0])) + str[1:]
}

func (h *HandlerAuth) VerifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	var req VerifyEmailRequest

	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errors.RespondWithError(w, domain.ErrInvalidRequestBody)
		return
	}

	var validate = validator.New()
	if err := validate.Struct(req); err != nil {
		createErrorMessage(w, err)
		return
	}

	if err := h.authService.VerifyEmail(r.Context(), req.Email, req.Code); err != nil {
		h.logger.Error("failed to verify email", zap.Error(err))
		errors.RespondWithError(w, err.(domain.Error))
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *HandlerAuth) RequestPasswordResetHandler(w http.ResponseWriter, r *http.Request) {
	var req RequestPasswordResetRequest

	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errors.RespondWithError(w, domain.ErrInvalidRequestBody)
		return
	}

	var validate = validator.New()
	if err := validate.Struct(req); err != nil {
		createErrorMessage(w, err)
		return
	}

	if err := h.authService.RequestPasswordReset(r.Context(), req.Email); err != nil {
		h.logger.Error("failed to request password reset", zap.Error(err))
		errors.RespondWithError(w, err.(domain.Error))
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *HandlerAuth) ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	var req ResetPasswordRequest

	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errors.RespondWithError(w, domain.ErrInvalidRequestBody)
		return
	}

	var validate = validator.New()
	if err := validate.Struct(req); err != nil {
		createErrorMessage(w, err)
		return
	}

	if err := h.authService.ResetPassword(r.Context(), req.Email, req.Code, req.NewPassword); err != nil {
		h.logger.Error("failed to reset password", zap.Error(err))
		errors.RespondWithError(w, err.(domain.Error))
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *HandlerAuth) VerifyMFAHandler(w http.ResponseWriter, r *http.Request) {
	var req MFARequest
	defer r.Body.Close()

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errors.RespondWithError(w, domain.ErrInvalidRequestBody)
		return
	}

	var validate = validator.New()
	if err := validate.Struct(req); err != nil {
		h.logger.Debug("validation error", zap.Error(err))
		createErrorMessage(w, err)
		return
	}

	tokenPair, err := h.authService.VerifyMFA(r.Context(), req.Ticket, req.Code)
	if err != nil {
		h.logger.Debug("failed to verify MFA", zap.Error(err))
		errors.RespondWithError(w, err.(domain.Error))
		return
	}

	// Definir o refresh token como cookie e retornar apenas o access token.
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    tokenPair.RefreshToken,
		Expires:  time.Now().Add(h.refreshTokenDuration), // Usar a mesma duração do login
		HttpOnly: true,
		Secure:   true, // Assumir true para produção
		Path:     "/",  // Ajustar se necessário
		SameSite: http.SameSiteStrictMode,
	})

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(LoginResponsePayload{AccessToken: tokenPair.AccessToken}); err != nil {
		h.logger.Error("failed to encode verify mfa response", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}
}
