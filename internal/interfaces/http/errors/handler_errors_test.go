package errors

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/stretchr/testify/assert"
)

func TestRespondWithError(t *testing.T) {
	tests := []struct {
		name           string
		err            domain.Error
		details        []ErrorDetail
		status         int
		expectedBody   ErrorResponse
		expectedStatus int
	}{
		{
			name: "validation error",
			err:  domain.ErrInvalidField,
			details: []ErrorDetail{
				{
					Field:   "Email",
					Message: "Email is required",
				},
			},
			status: http.StatusBadRequest,
			expectedBody: ErrorResponse{
				Code:    "U0011",
				Message: "Invalid field",
				Details: []ErrorDetail{
					{
						Field:   "Email",
						Message: "Email is required",
					},
				},
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "authentication error",
			err:    domain.ErrUnauthorized,
			status: http.StatusBadRequest,
			expectedBody: ErrorResponse{
				Code:    "U0014",
				Message: "Unauthorized",
			},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			if tt.details != nil {
				RespondErrorWithDetails(w, tt.err, tt.details)
			} else {
				RespondWithError(w, tt.err)
			}

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

			var response ErrorResponse
			err := json.NewDecoder(w.Body).Decode(&response)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedBody, response)
		})
	}
}
