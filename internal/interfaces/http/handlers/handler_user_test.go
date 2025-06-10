package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

type mockUserService struct {
	mock.Mock
}

func (m *mockUserService) GetUser(ctx context.Context, id ulid.ULID) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *mockUserService) UpdateUser(ctx context.Context, id ulid.ULID, name, phone string) error {
	args := m.Called(ctx, id, name, phone)
	return args.Error(0)
}

func (m *mockUserService) ListUsers(ctx context.Context, limit, offset int) ([]*domain.User, error) {
	args := m.Called(ctx, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.User), args.Error(1)
}

func TestUserHandler_GetUser(t *testing.T) {
	tests := []struct {
		name           string
		userID         string
		mockSetup      func(*mockUserService)
		expectedStatus int
		expectedBody   interface{}
	}{
		{
			name:   "Success",
			userID: "01JX40J5TVMSAM48DQRX1TE6PM",
			mockSetup: func(m *mockUserService) {
				id, _ := ulid.Parse("01JX40J5TVMSAM48DQRX1TE6PM")
				m.On("GetUser", mock.Anything, id).Return(&domain.User{
					ID:            id,
					Name:          "Test User",
					Email:         "test@example.com",
					Phone:         "1234567890",
					Roles:         []string{"user"},
					EmailVerified: true,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}, nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"id":    "01JX40J5TVMSAM48DQRX1TE6PM",
				"name":  "Test User",
				"email": "test@example.com",
				"phone": "1234567890",
			},
		},
		{
			name:   "User Not Found",
			userID: "01JX40J5TVMSAM48DQRX1TE6PM",
			mockSetup: func(m *mockUserService) {
				id, _ := ulid.Parse("01JX40J5TVMSAM48DQRX1TE6PM")
				m.On("GetUser", mock.Anything, id).Return(nil, domain.ErrUserNotFound)
			},
			expectedStatus: http.StatusNotFound,
			expectedBody: map[string]interface{}{
				"code":    "U0007",
				"message": "User not found",
			},
		},
		{
			name:   "Invalid User ID",
			userID: "invalid-id",
			mockSetup: func(m *mockUserService) {
				// No mock setup needed
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"code":    "U0057",
				"message": "Invalid user ID",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockService := new(mockUserService)
			tt.mockSetup(mockService)
			handler := NewUserHandler(mockService, zap.NewNop())

			// Create chi router and mount handler to simulate real routing
			r := chi.NewRouter()
			r.Get("/users/{id}", handler.GetUserHandler)
			req := httptest.NewRequest(http.MethodGet, "/users/"+tt.userID, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedBody, response)

			mockService.AssertExpectations(t)
		})
	}
}

func TestUserHandler_UpdateUser(t *testing.T) {
	tests := []struct {
		name           string
		userID         string
		requestBody    map[string]interface{}
		mockSetup      func(*mockUserService)
		expectedStatus int
		expectedBody   interface{}
	}{
		{
			name:   "Success",
			userID: "01JX40J5TVMSAM48DQRX1TE6PM",
			requestBody: map[string]interface{}{
				"name":  "Updated Name",
				"phone": "9876543210",
			},
			mockSetup: func(m *mockUserService) {
				id, _ := ulid.Parse("01JX40J5TVMSAM48DQRX1TE6PM")
				m.On("UpdateUser", mock.Anything, id, "Updated Name", "9876543210").Return(nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"message": "User updated successfully",
			},
		},
		{
			name:   "User Not Found",
			userID: "01JX40J5TVMSAM48DQRX1TE6PM",
			requestBody: map[string]interface{}{
				"name":  "Updated Name",
				"phone": "9876543210",
			},
			mockSetup: func(m *mockUserService) {
				id, _ := ulid.Parse("01JX40J5TVMSAM48DQRX1TE6PM")
				m.On("UpdateUser", mock.Anything, id, "Updated Name", "9876543210").Return(domain.ErrUserNotFound)
			},
			expectedStatus: http.StatusNotFound,
			expectedBody: map[string]interface{}{
				"code":    "U0007",
				"message": "User not found",
			},
		},
		{
			name:   "Invalid User ID",
			userID: "invalid-id",
			requestBody: map[string]interface{}{
				"name":  "Updated Name",
				"phone": "9876543210",
			},
			mockSetup: func(m *mockUserService) {
				// No mock setup needed
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"code":    "U0057",
				"message": "Invalid user ID",
			},
		},
		{
			name:   "Invalid Request Body",
			userID: "01JX40J5TVMSAM48DQRX1TE6PM",
			requestBody: map[string]interface{}{
				"invalid": "field",
			},
			mockSetup: func(m *mockUserService) {
				id, _ := ulid.Parse("01JX40J5TVMSAM48DQRX1TE6PM")
				m.On("UpdateUser", mock.Anything, id, "", "").Return(nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"message": "User updated successfully",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockService := new(mockUserService)
			tt.mockSetup(mockService)
			handler := NewUserHandler(mockService, zap.NewNop())

			body, err := json.Marshal(tt.requestBody)
			assert.NoError(t, err)

			// Create chi router and mount handler to simulate real routing
			r := chi.NewRouter()
			r.Put("/users/{id}", handler.UpdateUserHandler)
			req := httptest.NewRequest(http.MethodPut, "/users/"+tt.userID, bytes.NewBuffer(body))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedBody, response)

			mockService.AssertExpectations(t)
		})
	}
}

func TestUserHandler_ListUsers(t *testing.T) {
	tests := []struct {
		name           string
		queryParams    string
		mockSetup      func(*mockUserService)
		expectedStatus int
		expectedBody   interface{}
	}{
		{
			name:        "Success",
			queryParams: "?limit=10&offset=0",
			mockSetup: func(m *mockUserService) {
				users := []*domain.User{
					{
						ID:            ulid.MustParse("01JX40J5TVMSAM48DQRX1TE6PM"),
						Name:          "Test User 1",
						Email:         "test1@example.com",
						Phone:         "1234567890",
						Roles:         []string{"user"},
						EmailVerified: true,
						CreatedAt:     time.Now(),
						UpdatedAt:     time.Now(),
					},
					{
						ID:    ulid.MustParse("01JX40J5TVMSAM48DQRX1TE6PM"),
						Name:  "Test User 2",
						Email: "test2@example.com",
						Phone: "9876543210",
					},
				}
				m.On("ListUsers", mock.Anything, 10, 0).Return(users, nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody: []interface{}{
				map[string]interface{}{
					"id":    "01JX40J5TVMSAM48DQRX1TE6PM",
					"name":  "Test User 1",
					"email": "test1@example.com",
					"phone": "1234567890",
				},
				map[string]interface{}{
					"id":    "01JX40J5TVMSAM48DQRX1TE6PM",
					"name":  "Test User 2",
					"email": "test2@example.com",
					"phone": "9876543210",
				},
			},
		},
		{
			name:        "Invalid Limit",
			queryParams: "?limit=invalid&offset=0",
			mockSetup: func(m *mockUserService) {
				// No mock setup needed
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"code":    "U0011",
				"message": "Invalid field",
			},
		},
		{
			name:        "Invalid Offset",
			queryParams: "?limit=10&offset=invalid",
			mockSetup: func(m *mockUserService) {
				// No mock setup needed
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"code":    "U0011",
				"message": "Invalid field",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockService := new(mockUserService)
			tt.mockSetup(mockService)
			handler := NewUserHandler(mockService, zap.NewNop())

			// Create request
			req := httptest.NewRequest(http.MethodGet, "/users"+tt.queryParams, nil)
			w := httptest.NewRecorder()

			// Execute
			handler.ListUsersHandler(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)

			var response interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			// For Success case, compare as []interface{}
			if tt.name == "Success" {
				assert.Equal(t, tt.expectedBody, response)
			} else {
				assert.Equal(t, tt.expectedBody, response)
			}

			mockService.AssertExpectations(t)
		})
	}
}
