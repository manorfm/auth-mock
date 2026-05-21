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

func (h *TOTPHandler) SetupTOTP(w http.ResponseWriter, r *http.Request) {
	userID, ok := domain.GetSubject(r.Context())
	if !ok || userID == "" {
		errors.RespondWithError(w, domain.ErrUnauthorized)
		return
	}
	totp, err := h.service.SetupTOTP(userID)
	if err != nil {
		errors.RespondWithError(w, err.(domain.Error))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(totp)
}

func (h *TOTPHandler) ConfirmTOTP(w http.ResponseWriter, r *http.Request) {
	userID, ok := domain.GetSubject(r.Context())
	if !ok || userID == "" {
		errors.RespondWithError(w, domain.ErrUnauthorized)
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errors.RespondWithError(w, domain.ErrInvalidRequestBody)
		return
	}
	if req.Code == "" {
		errors.RespondWithError(w, domain.ErrInvalidField)
		return
	}
	codes, err := h.service.ConfirmTOTP(userID, req.Code)
	if err != nil {
		errors.RespondWithError(w, err.(domain.Error))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string][]string{"backup_codes": codes})
}

// EnableTOTP handles the request to enable TOTP for a user
func (h *TOTPHandler) EnableTOTP(w http.ResponseWriter, r *http.Request) {
	userID, ok := domain.GetSubject(r.Context())
	if !ok || userID == "" {
		h.logger.Error("User not authenticated")
		errors.RespondWithError(w, domain.ErrUnauthorized)
		return
	}

	w.Header().Set("Deprecation", "true")
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
	userID, ok := domain.GetSubject(r.Context())
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
	userID, ok := domain.GetSubject(r.Context())
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
	userID, ok := domain.GetSubject(r.Context())
	if !ok || userID == "" {
		h.logger.Error("User not authenticated")
		errors.RespondWithError(w, domain.ErrUnauthorized)
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errors.RespondWithError(w, domain.ErrInvalidRequestBody)
		return
	}
	if req.Code == "" {
		errors.RespondWithError(w, domain.ErrInvalidField)
		return
	}
	if err := h.service.VerifyTOTPOrBackup(userID, req.Code); err != nil {
		errors.RespondWithError(w, err.(domain.Error))
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

func (h *TOTPHandler) RegenerateBackupCodes(w http.ResponseWriter, r *http.Request) {
	userID, ok := domain.GetSubject(r.Context())
	if !ok || userID == "" {
		errors.RespondWithError(w, domain.ErrUnauthorized)
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errors.RespondWithError(w, domain.ErrInvalidRequestBody)
		return
	}
	if req.Code == "" {
		errors.RespondWithError(w, domain.ErrInvalidField)
		return
	}
	codes, err := h.service.RegenerateBackupCodes(userID, req.Code)
	if err != nil {
		errors.RespondWithError(w, err.(domain.Error))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"backup_codes": codes,
		"message":      "Backup codes regenerated successfully",
	})
}
