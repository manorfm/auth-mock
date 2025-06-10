package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/interfaces/http/errors"
	"go.uber.org/zap"
)

// TOTPHandler handles TOTP-related HTTP requests
type TOTPHandler struct {
	service domain.TOTPService
	logger  *zap.Logger
}

// NewTOTPHandler creates a new TOTP handler
func NewTOTPHandler(service domain.TOTPService, logger *zap.Logger) *TOTPHandler {
	return &TOTPHandler{
		service: service,
		logger:  logger,
	}
}

// EnableTOTP handles the request to enable TOTP for a user
func (h *TOTPHandler) EnableTOTP(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("sub").(string)
	if !ok || userID == "" {
		h.logger.Error("User not authenticated")
		errors.RespondWithError(w, domain.ErrUnauthorized)
		return
	}

	totp, err := h.service.EnableTOTP(userID)
	if err != nil {
		h.logger.Error("Failed to enable TOTP",
			zap.String("user_id", userID),
			zap.Error(err))
		errors.RespondWithError(w, err.(domain.Error))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(totp); err != nil {
		h.logger.Error("Failed to encode response", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}
}

// VerifyTOTP handles the request to verify a TOTP code
func (h *TOTPHandler) VerifyTOTP(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("sub").(string)
	if !ok || userID == "" {
		h.logger.Error("User not authenticated")
		errors.RespondWithError(w, domain.ErrUnauthorized)
		return
	}

	var req struct {
		Code string `json:"code" binding:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error("Failed to decode request body", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInvalidRequestBody)
		return
	}

	if req.Code == "" {
		h.logger.Error("Missing TOTP code")
		errors.RespondWithError(w, domain.ErrInvalidField)
		return
	}

	err := h.service.VerifyTOTP(userID, req.Code)
	if err != nil {
		h.logger.Error("Failed to verify TOTP code",
			zap.String("user_id", userID),
			zap.Error(err))
		errors.RespondWithError(w, err.(domain.Error))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"message": "TOTP code verified successfully",
	}); err != nil {
		h.logger.Error("Failed to encode response", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}
}

// VerifyBackupCode handles the request to verify a backup code
func (h *TOTPHandler) VerifyBackupCode(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("sub").(string)
	if !ok || userID == "" {
		h.logger.Error("User not authenticated")
		errors.RespondWithError(w, domain.ErrUnauthorized)
		return
	}

	var req struct {
		Code string `json:"code" binding:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error("Failed to decode request body", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInvalidRequestBody)
		return
	}

	if req.Code == "" {
		h.logger.Error("Missing backup code")
		errors.RespondWithError(w, domain.ErrInvalidField)
		return
	}

	err := h.service.VerifyBackupCode(userID, req.Code)
	if err != nil {
		h.logger.Error("Failed to verify backup code",
			zap.String("user_id", userID),
			zap.Error(err))
		errors.RespondWithError(w, err.(domain.Error))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"message": "Backup code verified successfully",
	}); err != nil {
		h.logger.Error("Failed to encode response", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}
}

// DisableTOTP handles the request to disable TOTP for a user
func (h *TOTPHandler) DisableTOTP(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("sub").(string)
	if !ok || userID == "" {
		h.logger.Error("User not authenticated")
		errors.RespondWithError(w, domain.ErrUnauthorized)
		return
	}

	err := h.service.DisableTOTP(userID)
	if err != nil {
		h.logger.Error("Failed to disable TOTP",
			zap.String("user_id", userID),
			zap.Error(err))
		errors.RespondWithError(w, err.(domain.Error))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"message": "TOTP disabled successfully",
	}); err != nil {
		h.logger.Error("Failed to encode response", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}
}
