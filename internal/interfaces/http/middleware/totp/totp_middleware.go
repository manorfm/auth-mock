package totp

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/interfaces/http/errors"
	"go.uber.org/zap"
)

// Middleware handles TOTP verification after password authentication
type Middleware struct {
	totpService domain.TOTPService
	logger      *zap.Logger
}

// NewMiddleware creates a new TOTP middleware
func NewMiddleware(totpService domain.TOTPService, logger *zap.Logger) *Middleware {
	return &Middleware{
		totpService: totpService,
		logger:      logger,
	}
}

// Verifier is the middleware function that verifies TOTP codes
func (m *Middleware) Verifier(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get user ID from context (set by auth middleware)
		userID, ok := r.Context().Value("sub").(string)
		if !ok || userID == "" {
			m.logger.Error("User not authenticated")
			errors.RespondWithError(w, domain.ErrUnauthorized)
			return
		}

		// Check if TOTP is enabled for the user
		secret, err := m.totpService.GetTOTPSecret(r.Context(), userID)
		if err != nil {
			if err == domain.ErrTOTPNotEnabled {
				// TOTP not enabled, proceed to next handler
				next.ServeHTTP(w, r)
				return
			}
			m.logger.Error("Failed to check TOTP status",
				zap.String("user_id", userID),
				zap.Error(err))
			errors.RespondWithError(w, domain.ErrInternal)
			return
		}

		// If we got here and have a secret, TOTP is enabled
		if secret == "" {
			// TOTP not enabled, proceed to next handler
			next.ServeHTTP(w, r)
			return
		}

		// TOTP is enabled, check if already verified in this session
		if _, ok := r.Context().Value("totp_verified").(bool); ok {
			// TOTP already verified in this session, proceed
			next.ServeHTTP(w, r)
			return
		}

		// Check if this is a TOTP verification request
		if r.URL.Path == "/api/totp/verify" || r.URL.Path == "/api/totp/verify-backup" {
			// Allow TOTP verification endpoints to proceed
			next.ServeHTTP(w, r)
			return
		}

		// TOTP verification required
		errors.RespondWithError(w, domain.ErrTOTPVerificationRequired)
	})
}

// VerificationHandler handles the TOTP verification process
func (m *Middleware) VerificationHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("sub").(string)
	if !ok || userID == "" {
		m.logger.Error("User not authenticated")
		errors.RespondWithError(w, domain.ErrUnauthorized)
		return
	}

	var req struct {
		Code string `json:"code" binding:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		m.logger.Error("Failed to decode request body", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInvalidRequestBody)
		return
	}

	if req.Code == "" {
		m.logger.Error("Missing verification code")
		errors.RespondWithError(w, domain.ErrInvalidField)
		return
	}

	// Try TOTP code first
	err := m.totpService.VerifyTOTP(userID, req.Code)
	if err != nil {
		// If TOTP verification fails, try backup code
		if err == domain.ErrInvalidTOTPCode {
			err = m.totpService.VerifyBackupCode(userID, req.Code)
			if err != nil {
				m.logger.Error("Failed to verify code",
					zap.String("user_id", userID),
					zap.Error(err))
				errors.RespondWithError(w, err.(domain.Error))
				return
			}
		} else {
			m.logger.Error("Failed to verify TOTP code",
				zap.String("user_id", userID),
				zap.Error(err))
			errors.RespondWithError(w, err.(domain.Error))
			return
		}
	}

	// Create new context with TOTP verification flag
	ctx := context.WithValue(r.Context(), "totp_verified", true)
	*r = *r.WithContext(ctx)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"message": "TOTP verification successful",
	}); err != nil {
		m.logger.Error("Failed to encode response", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}
}
