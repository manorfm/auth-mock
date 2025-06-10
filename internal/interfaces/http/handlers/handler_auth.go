package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/interfaces/http/errors"
	"go.uber.org/zap"
)

type HandlerAuth struct {
	authService domain.AuthService
	logger      *zap.Logger
}

func NewAuthHandler(authService domain.AuthService, logger *zap.Logger) *HandlerAuth {
	return &HandlerAuth{
		authService: authService,
		logger:      logger,
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

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		h.logger.Error("failed to encode response", zap.Error(err))
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

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(tokenPair); err != nil {
		h.logger.Error("failed to encode response", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}
}
