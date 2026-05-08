package handlers

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/infrastructure/config"
	"github.com/manorfm/auth-mock/internal/interfaces/http/errors"
	"go.uber.org/zap"
)

type HandlerAuth struct {
	authService domain.AuthService
	cfg         *config.Config
	logger      *zap.Logger
}

func NewAuthHandler(authService domain.AuthService, cfg *config.Config, logger *zap.Logger) *HandlerAuth {
	return &HandlerAuth{
		authService: authService,
		cfg:         cfg,
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

type CreateStandaloneUserRequest struct {
	Name            string   `json:"name" validate:"required"`
	Email           string   `json:"email" validate:"required,email"`
	Password        string   `json:"password" validate:"required,min=8"`
	Phone           string   `json:"phone" validate:"required"`
	AllowedChannels []string `json:"allowed_channels"`
	Roles           []string `json:"roles"`
}

type UpdateUserRoleRequest struct {
	Role string `json:"role" validate:"required"`
}

// RegisterUserResponse matches the public registration contract (email-first onboarding).
type RegisterUserResponse struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Email           string   `json:"email"`
	Phone           string   `json:"phone,omitempty"`
	UserType        string   `json:"user_type"`
	AllowedChannels []string `json:"allowed_channels"`
	Roles           []string `json:"roles"`
	Status          string   `json:"status"`
}

func NewRegisterUserResponse(user *domain.User) *RegisterUserResponse {
	status := "active"
	if !user.EmailVerified {
		status = "email_verify"
	}
	return &RegisterUserResponse{
		ID:              user.ID.String(),
		Name:            user.Name,
		Email:           user.Email,
		Phone:           user.Phone,
		UserType:        user.UserType,
		AllowedChannels: user.Channels,
		Roles:           user.Roles,
		Status:          status,
	}
}

type loginAccessResponse struct {
	AccessToken string `json:"access_token"`
}

type renameRoleRequest struct {
	Name string `json:"name" validate:"required"`
}

// RegisterHandler is a legacy alias for client self-registration (same contract as RegisterClientHandler).
func (h *HandlerAuth) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	h.RegisterClientHandler(w, r)
}

func (h *HandlerAuth) RegisterClientHandler(w http.ResponseWriter, r *http.Request) {
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

	user, err := h.authService.RegisterClient(r.Context(), req.Name, req.Email, req.Password, req.Phone)
	if err != nil {
		h.logger.Error("failed to register client user", zap.Error(err))
		errors.RespondWithError(w, err.(domain.Error))
		return
	}
	response := NewRegisterUserResponse(user)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(response)
}

func (h *HandlerAuth) RegisterManagementHandler(w http.ResponseWriter, r *http.Request) {
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

	user, err := h.authService.RegisterManagementOwner(r.Context(), req.Name, req.Email, req.Password, req.Phone)
	if err != nil {
		h.logger.Error("failed to register user", zap.Error(err))
		errors.RespondWithError(w, err.(domain.Error))
		return
	}

	response := NewRegisterUserResponse(user)

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

	result, err := h.authService.Login(r.Context(), req.Email, req.Password, req.Channel)
	if err != nil {
		h.logger.Debug("failed to login user", zap.Error(err))
		errors.RespondWithError(w, err.(domain.Error))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	switch v := result.(type) {
	case *domain.TokenPair:
		setRefreshTokenCookie(w, h.cfg, v.RefreshToken)
		if err := json.NewEncoder(w).Encode(loginAccessResponse{AccessToken: v.AccessToken}); err != nil {
			h.logger.Error("failed to encode response", zap.Error(err))
			errors.RespondWithError(w, domain.ErrInternal)
		}
	default:
		if err := json.NewEncoder(w).Encode(result); err != nil {
			h.logger.Error("failed to encode response", zap.Error(err))
			errors.RespondWithError(w, domain.ErrInternal)
		}
	}
}

func (h *HandlerAuth) CreateStandaloneUserHandler(w http.ResponseWriter, r *http.Request) {
	var req CreateStandaloneUserRequest
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errors.RespondWithError(w, domain.ErrInvalidRequestBody)
		return
	}
	validate := validator.New()
	if err := validate.Struct(req); err != nil {
		createErrorMessage(w, err)
		return
	}
	user, err := h.authService.CreateStandaloneUserByAdmin(r.Context(), req.Name, req.Email, req.Password, req.Phone, req.AllowedChannels, req.Roles)
	if err != nil {
		errors.RespondWithError(w, err.(domain.Error))
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(NewRegisterUserResponse(user))
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

type refreshTokenBody struct {
	RefreshToken string `json:"refresh_token"`
}

func readRefreshTokenFromRequest(r *http.Request) (string, error) {
	var refresh string
	if c, err := r.Cookie(refreshTokenCookieName); err == nil && c.Value != "" {
		refresh = c.Value
	}
	if refresh == "" {
		var body refreshTokenBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err != io.EOF {
			return "", err
		}
		refresh = body.RefreshToken
	}
	return refresh, nil
}

// RefreshTokenHandler exchanges a refresh token (cookie or JSON body) for a new access token; refresh is re-set as HttpOnly cookie.
func (h *HandlerAuth) RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	refresh, err := readRefreshTokenFromRequest(r)
	if err != nil {
		errors.RespondWithError(w, domain.ErrInvalidRequestBody)
		return
	}
	if refresh == "" {
		errors.RespondWithError(w, domain.ErrInvalidRequestBody)
		return
	}

	pair, err := h.authService.RefreshWithRefreshToken(r.Context(), refresh)
	if err != nil {
		if de, ok := err.(domain.Error); ok {
			errors.RespondWithError(w, de)
			return
		}
		errors.RespondWithError(w, domain.ErrAuthInvalidCredentials)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	setRefreshTokenCookie(w, h.cfg, pair.RefreshToken)
	if err := json.NewEncoder(w).Encode(loginAccessResponse{AccessToken: pair.AccessToken}); err != nil {
		h.logger.Error("failed to encode refresh response", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
	}
}

func (h *HandlerAuth) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	refresh, err := readRefreshTokenFromRequest(r)
	if err != nil {
		errors.RespondWithError(w, domain.ErrInvalidRequestBody)
		return
	}
	if refresh == "" {
		errors.RespondWithError(w, domain.ErrInvalidRequestBody)
		return
	}
	if err := h.authService.LogoutWithRefreshToken(r.Context(), refresh); err != nil {
		if de, ok := err.(domain.Error); ok {
			errors.RespondWithError(w, de)
			return
		}
		errors.RespondWithError(w, domain.ErrAuthInvalidCredentials)
		return
	}
	clearRefreshTokenCookie(w, h.cfg)
	w.WriteHeader(http.StatusNoContent)
}

type resendVerificationRequest struct {
	Email string `json:"email" validate:"required,email"`
}

func (h *HandlerAuth) ResendVerificationHandler(w http.ResponseWriter, r *http.Request) {
	var req resendVerificationRequest
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errors.RespondWithError(w, domain.ErrInvalidRequestBody)
		return
	}
	v := validator.New()
	if err := v.Struct(req); err != nil {
		createErrorMessage(w, err)
		return
	}
	if err := h.authService.ResendVerificationEmail(r.Context(), req.Email); err != nil {
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
	setRefreshTokenCookie(w, h.cfg, tokenPair.RefreshToken)
	if err := json.NewEncoder(w).Encode(loginAccessResponse{AccessToken: tokenPair.AccessToken}); err != nil {
		h.logger.Error("failed to encode response", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}
}

func (h *HandlerAuth) AddStandaloneRoleHandler(w http.ResponseWriter, r *http.Request) {
	var req UpdateUserRoleRequest
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errors.RespondWithError(w, domain.ErrInvalidRequestBody)
		return
	}
	v := validator.New()
	if err := v.Struct(req); err != nil {
		createErrorMessage(w, err)
		return
	}
	roles, err := h.authService.AssignRoleToStandalone(r.Context(), chi.URLParam(r, "id"), req.Role)
	if err != nil {
		errors.RespondWithError(w, err.(domain.Error))
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"user_id": chi.URLParam(r, "id"), "roles": roles})
}

func (h *HandlerAuth) RemoveStandaloneRoleHandler(w http.ResponseWriter, r *http.Request) {
	roles, err := h.authService.RemoveRoleFromStandalone(r.Context(), chi.URLParam(r, "id"), chi.URLParam(r, "role"))
	if err != nil {
		errors.RespondWithError(w, err.(domain.Error))
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"user_id": chi.URLParam(r, "id"), "roles": roles})
}

func (h *HandlerAuth) ListStandaloneRolesHandler(w http.ResponseWriter, r *http.Request) {
	roles, err := h.authService.ListRolesByUser(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		errors.RespondWithError(w, err.(domain.Error))
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"user_id": chi.URLParam(r, "id"), "roles": roles})
}

func (h *HandlerAuth) ListRolesHandler(w http.ResponseWriter, r *http.Request) {
	roles, err := h.authService.ListRoles(r.Context())
	if err != nil {
		errors.RespondWithError(w, err.(domain.Error))
		return
	}
	_ = json.NewEncoder(w).Encode(roles)
}

func (h *HandlerAuth) CreateRoleHandler(w http.ResponseWriter, r *http.Request) {
	var req UpdateUserRoleRequest
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errors.RespondWithError(w, domain.ErrInvalidRequestBody)
		return
	}
	if err := h.authService.CreateCustomRole(r.Context(), req.Role); err != nil {
		errors.RespondWithError(w, err.(domain.Error))
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *HandlerAuth) DeleteRoleHandler(w http.ResponseWriter, r *http.Request) {
	if err := h.authService.DeleteCustomRole(r.Context(), chi.URLParam(r, "name")); err != nil {
		errors.RespondWithError(w, err.(domain.Error))
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *HandlerAuth) UpdateRoleHandler(w http.ResponseWriter, r *http.Request) {
	var req renameRoleRequest
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errors.RespondWithError(w, domain.ErrInvalidRequestBody)
		return
	}
	v := validator.New()
	if err := v.Struct(req); err != nil {
		createErrorMessage(w, err)
		return
	}
	if err := h.authService.RenameCustomRole(r.Context(), chi.URLParam(r, "name"), req.Name); err != nil {
		errors.RespondWithError(w, err.(domain.Error))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}
