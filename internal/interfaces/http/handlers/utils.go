package handlers

import (
	"net/http"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/interfaces/http/errors"
)

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