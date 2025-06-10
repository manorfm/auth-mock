package errors

import (
	"encoding/json"
	"net/http"

	"github.com/manorfm/auth-mock/internal/domain"
)

// ErrorResponse represents the standard error response structure
type ErrorResponse struct {
	Code    string        `json:"code"`
	Message string        `json:"message"`
	Details []ErrorDetail `json:"details,omitempty"`
}

// ErrorDetail represents a validation error detail
type ErrorDetail struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func getStatus(err domain.Error) int {
	switch err.GetCode() {
	case domain.ErrUserNotFound.GetCode():
		return http.StatusNotFound
	case domain.ErrClientNotFound.GetCode():
		return http.StatusNotFound
	case domain.ErrInternal.GetCode():
		return http.StatusInternalServerError
	case domain.ErrUnauthorized.GetCode():
		return http.StatusUnauthorized
	case domain.ErrForbidden.GetCode():
		return http.StatusForbidden
	case domain.ErrInvalidToken.GetCode():
		return http.StatusForbidden
	case domain.ErrTOTPVerificationRequired.GetCode():
		return http.StatusForbidden
	}

	return http.StatusBadRequest
}

// RespondWithError sends a standardized error response
func RespondWithError(w http.ResponseWriter, err domain.Error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(getStatus(err))
	json.NewEncoder(w).Encode(ErrorResponse{
		Code:    err.GetCode(),
		Message: err.GetMessage(),
	})
}

// RespondErrorWithDetails sends a standardized error response with details
func RespondErrorWithDetails(w http.ResponseWriter, err domain.Error, details []ErrorDetail) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(getStatus(err))
	json.NewEncoder(w).Encode(ErrorResponse{
		Code:    err.GetCode(),
		Message: err.GetMessage(),
		Details: details,
	})
}
