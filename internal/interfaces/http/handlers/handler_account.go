package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/interfaces/http/errors"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
)

type HandlerAccount struct {
	accountService domain.AccountService
	userService    domain.UserService
	totpService    domain.TOTPService
	logger         *zap.Logger
}

func NewAccountHandler(accountService domain.AccountService, userService domain.UserService, totpService domain.TOTPService, logger *zap.Logger) *HandlerAccount {
	return &HandlerAccount{
		accountService: accountService,
		userService:    userService,
		totpService:    totpService,
		logger:         logger,
	}
}

// Request structures
type UpdateAccountRequest struct {
	Status domain.AccountStatus `json:"status" validate:"required"`
}

// AccountResponse represents the response structure for account endpoints
type AccountResponse struct {
	ID        string               `json:"id"`
	UserID    string               `json:"user_id"`
	Status    domain.AccountStatus `json:"status"`
	CreatedAt string               `json:"created_at"`
}

// AccountMeResponse represents the response structure for /accounts/me endpoint
type AccountMeResponse struct {
	ID   string `json:"id"`
	User struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
		Phone string `json:"phone"`
	} `json:"user"`
	MFA       string `json:"mfa"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

// NewAccountResponse creates a new AccountResponse from a domain Account
func NewAccountResponse(account *domain.Account) *AccountResponse {
	return &AccountResponse{
		ID:        account.ID.String(),
		UserID:    account.UserID.String(),
		Status:    account.Status,
		CreatedAt: account.CreatedAt.Format("2006-01-02"),
	}
}

// NewAccountMeResponse creates a new AccountMeResponse from account and user data
func NewAccountMeResponse(account *domain.Account, user *domain.User, mfaEnabled bool) *AccountMeResponse {
	response := &AccountMeResponse{
		ID:        account.ID.String(),
		Status:    string(account.Status),
		CreatedAt: account.CreatedAt.Format("2006-01-02"),
	}

	response.User.ID = user.ID.String()
	response.User.Name = user.Name
	response.User.Email = user.Email
	response.User.Phone = user.Phone

	if mfaEnabled {
		response.MFA = "active"
	} else {
		response.MFA = "inactive"
	}

	return response
}

// GetAccountsHandler returns all accounts (moved from /accounts/me)
func (h *HandlerAccount) GetAccountsHandler(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context (set by auth middleware)
	userIDStr, ok := domain.GetSubject(r.Context())
	if !ok {
		h.logger.Error("user ID not found in context")
		errors.RespondWithError(w, domain.ErrUnauthorized)
		return
	}

	// Parse user ID
	userID, err := ulid.Parse(userIDStr)
	if err != nil {
		h.logger.Error("invalid user ID format in token", zap.Error(err))
		errors.RespondWithError(w, domain.ErrUnauthorized)
		return
	}

	// Get account data
	account, err := h.accountService.GetAccountByUserID(r.Context(), userID)
	if err != nil {
		h.logger.Error("failed to get current user account", zap.Error(err))
		if err == domain.ErrAccountNotFound {
			errors.RespondWithError(w, domain.ErrAccountNotFound)
			return
		}
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(NewAccountResponse(account)); err != nil {
		h.logger.Error("failed to encode response", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}
}

// GetMeHandler returns the current user's account with user data and MFA status
func (h *HandlerAccount) GetMeHandler(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context (set by auth middleware)
	userIDStr, ok := domain.GetSubject(r.Context())
	if !ok {
		h.logger.Error("user ID not found in context")
		errors.RespondWithError(w, domain.ErrUnauthorized)
		return
	}

	// Parse user ID
	userID, err := ulid.Parse(userIDStr)
	if err != nil {
		h.logger.Error("invalid user ID format in token", zap.Error(err))
		errors.RespondWithError(w, domain.ErrUnauthorized)
		return
	}

	// Get account data
	account, err := h.accountService.GetAccountByUserID(r.Context(), userID)
	if err != nil {
		h.logger.Error("failed to get current user account", zap.Error(err))
		if err == domain.ErrAccountNotFound {
			errors.RespondWithError(w, domain.ErrAccountNotFound)
			return
		}
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}

	// Get user data
	user, err := h.userService.GetUser(r.Context(), userID)
	if err != nil {
		h.logger.Error("failed to get current user", zap.Error(err))
		if err == domain.ErrUserNotFound {
			errors.RespondWithError(w, domain.ErrUserNotFound)
			return
		}
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}

	// Check if TOTP is enabled
	_, err = h.totpService.GetTOTPSecret(r.Context(), userID.String())
	mfaEnabled := err == nil

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(NewAccountMeResponse(account, user, mfaEnabled)); err != nil {
		h.logger.Error("failed to encode response", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}
}

// UpdateAccountHandler handles PUT /accounts
func (h *HandlerAccount) UpdateAccountHandler(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context (set by auth middleware)
	userIDStr, ok := domain.GetSubject(r.Context())
	if !ok {
		h.logger.Error("user ID not found in context")
		errors.RespondWithError(w, domain.ErrUnauthorized)
		return
	}

	// Parse user ID
	userID, err := ulid.Parse(userIDStr)
	if err != nil {
		h.logger.Error("invalid user ID format in token", zap.Error(err))
		errors.RespondWithError(w, domain.ErrUnauthorized)
		return
	}

	var req UpdateAccountRequest
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

	// Get account by user ID
	account, err := h.accountService.GetAccountByUserID(r.Context(), userID)
	if err != nil {
		h.logger.Error("failed to get account for update", zap.Error(err))
		errors.RespondWithError(w, err.(domain.Error))
		return
	}

	account.Status = req.Status
	account.UpdatedAt = time.Now()

	if err := h.accountService.UpdateAccount(r.Context(), account); err != nil {
		h.logger.Error("failed to update account", zap.Error(err))
		errors.RespondWithError(w, err.(domain.Error))
		return
	}

	w.WriteHeader(http.StatusOK)
}

// DeleteAccountHandler handles DELETE /accounts
func (h *HandlerAccount) DeleteAccountHandler(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context (set by auth middleware)
	userIDStr, ok := domain.GetSubject(r.Context())
	if !ok {
		h.logger.Error("user ID not found in context")
		errors.RespondWithError(w, domain.ErrUnauthorized)
		return
	}

	// Parse user ID
	userID, err := ulid.Parse(userIDStr)
	if err != nil {
		h.logger.Error("invalid user ID format in token", zap.Error(err))
		errors.RespondWithError(w, domain.ErrUnauthorized)
		return
	}

	// Get account by user ID
	account, err := h.accountService.GetAccountByUserID(r.Context(), userID)
	if err != nil {
		h.logger.Error("failed to get account for deletion", zap.Error(err))
		errors.RespondWithError(w, err.(domain.Error))
		return
	}

	if err := h.accountService.DeleteAccount(r.Context(), account.ID); err != nil {
		h.logger.Error("failed to delete account", zap.Error(err))
		errors.RespondWithError(w, err.(domain.Error))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

 