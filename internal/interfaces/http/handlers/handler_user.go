package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/interfaces/http/errors"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
)

type HandlerUser struct {
	userService domain.UserService
	logger      *zap.Logger
}

func NewUserHandler(userService domain.UserService, logger *zap.Logger) *HandlerUser {
	return &HandlerUser{
		userService: userService,
		logger:      logger,
	}
}

type UserResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Phone string `json:"phone"`
}

func NewUserResponse(user *domain.User) *UserResponse {
	return &UserResponse{
		ID:    user.ID.String(),
		Email: user.Email,
		Name:  user.Name,
		Phone: user.Phone,
	}
}

func (h *HandlerUser) GetUserHandler(w http.ResponseWriter, r *http.Request) {
	userID := getID(r, h)
	if userID == nil {
		errors.RespondWithError(w, domain.ErrInvalidUserID)
		return
	}

	user, err := h.userService.GetUser(r.Context(), *userID)
	if err != nil {
		h.logger.Error("failed to get user", zap.Error(err))
		if err == domain.ErrUserNotFound {
			errors.RespondWithError(w, domain.ErrUserNotFound)
			return
		}
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(NewUserResponse(user)); err != nil {
		h.logger.Error("failed to encode response", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}
}

func getQueryParam(r *http.Request, key string, defaultValue int) (int, error) {
	value := r.URL.Query().Get(key)
	if value == "" {
		return defaultValue, nil
	}
	return strconv.Atoi(value)
}

func (h *HandlerUser) ListUsersHandler(w http.ResponseWriter, r *http.Request) {
	limit, err := getQueryParam(r, "limit", 10)
	if err != nil {
		h.logger.Error("invalid limit parameter", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInvalidField)
		return
	}

	offset, err := getQueryParam(r, "offset", 0)
	if err != nil {
		h.logger.Error("invalid offset parameter", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInvalidField)
		return
	}

	users, err := h.userService.ListUsers(r.Context(), limit, offset)
	if err != nil {
		h.logger.Error("failed to list users", zap.Error(err))
		errors.RespondWithError(w, err.(domain.Error))
		return
	}

	response := make([]*UserResponse, len(users))
	for i, user := range users {
		response[i] = NewUserResponse(user)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("failed to encode response", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}
}

func getID(r *http.Request, h *HandlerUser) *ulid.ULID {
	userID := chi.URLParam(r, "id")
	if userID == "" {
		h.logger.Error("empty user ID")
		return nil
	}

	id, err := ulid.Parse(userID)
	if err != nil {
		h.logger.Error("invalid user ID format", zap.Error(err))
		return nil
	}

	return &id
}

func (h *HandlerUser) UpdateUserHandler(w http.ResponseWriter, r *http.Request) {
	var req domain.UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error("failed to decode request body", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInvalidRequestBody)
		return
	}

	userID := getID(r, h)
	if userID == nil {
		errors.RespondWithError(w, domain.ErrInvalidUserID)
		return
	}

	if err := h.userService.UpdateUser(r.Context(), *userID, req.Name, req.Phone); err != nil {
		h.logger.Error("failed to update user", zap.Error(err))
		if err == domain.ErrUserNotFound {
			errors.RespondWithError(w, domain.ErrUserNotFound)
			return
		}
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{"message": "User updated successfully"}); err != nil {
		h.logger.Error("failed to encode response", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}
}
