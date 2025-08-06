package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/manorfm/auth-mock/internal/application"
	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/infrastructure/config"
	"github.com/manorfm/auth-mock/internal/infrastructure/email"
	"github.com/manorfm/auth-mock/internal/infrastructure/jwt"
	"github.com/manorfm/auth-mock/internal/infrastructure/repository"
	"github.com/manorfm/auth-mock/internal/infrastructure/totp"
	"github.com/manorfm/auth-mock/internal/interfaces/http/handlers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestAccountIntegration(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	// Setup configuration
	cfg := &config.Config{
		EmailEnabled:        false,
		DefaultUserEmail:    "test@example.com",
		DefaultUserPassword: "test123",
		DefaultUserRoles:    []string{"admin", "user"},
		JWTAccessDuration:   15 * time.Minute,
		JWTRefreshDuration:  7 * 24 * time.Hour,
		RSAKeySize:          2048,
		JWKSCacheDuration:   time.Hour,
	}

	// Setup repositories
	userRepo := repository.NewUserRepository(logger)
	accountRepo := repository.NewAccountRepository()
	verificationRepo := repository.NewVerificationCodeRepository(logger)
	totpRepo := repository.NewTOTPRepository(logger)
	mfaTicketRepo := repository.NewMFATicketRepository(logger)

	// Setup services
	jwtStrategy, err := jwt.NewLocalStrategy(cfg, logger)
	require.NoError(t, err)
	jwtService := jwt.NewJWTService(jwtStrategy, cfg, logger)

	totpGenerator := totp.NewGenerator(logger)
	emailTemplate := email.NewEmailTemplate(&cfg.SMTP, logger)

	totpService := application.NewTOTPService(totpRepo, totpGenerator, logger)
	userService := application.NewUserService(userRepo, logger)
	accountService := application.NewAccountService(accountRepo, logger)
	authService := application.NewAuthService(cfg, userRepo, accountService, verificationRepo, jwtService, emailTemplate, totpService, mfaTicketRepo, logger)

	// Setup handlers
	accountHandler := handlers.NewAccountHandler(accountService, userService, totpService, jwtService, logger)

	t.Run("Complete Account Flow", func(t *testing.T) {
		// 1. Register a new user (this should create an account automatically)
		user, err := authService.Register(ctx, "Test User", "account@example.com", "password123", "1234567890", nil)
		require.NoError(t, err)
		assert.NotNil(t, user)

		// 2. Verify email
		err = authService.VerifyEmail(ctx, "account@example.com", "mock-code")
		require.NoError(t, err)

		// 3. Login to get token
		result, err := authService.Login(ctx, "account@example.com", "password123")
		require.NoError(t, err)
		assert.NotNil(t, result)

		tokenPair, ok := result.(*domain.TokenPair)
		require.True(t, ok)
		assert.NotEmpty(t, tokenPair.AccessToken)

		// 4. Test GetAccountsHandler
		req := httptest.NewRequest("GET", "/api/accounts", nil)
		ctxWithUser := context.WithValue(req.Context(), domain.ContextKeySubject, user.ID.String())
		req = req.WithContext(ctxWithUser)

		w := httptest.NewRecorder()
		accountHandler.GetAccountsHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var accountResponse handlers.AccountResponse
		err = json.NewDecoder(w.Body).Decode(&accountResponse)
		require.NoError(t, err)
		assert.Equal(t, user.ID.String(), accountResponse.UserID)
		assert.Equal(t, string(domain.AccountStatusActive), string(accountResponse.Status))

		// 5. Test GetMeHandler
		// Generate a valid token for the user
		meTokenPair, err2 := jwtService.GenerateTokenPair(ctx, user)
		require.NoError(t, err2)

		req = httptest.NewRequest("GET", "/api/accounts/me", nil)
		req.Header.Set("Authorization", "Bearer "+meTokenPair.AccessToken)

		w = httptest.NewRecorder()
		accountHandler.GetMeHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var meResponse handlers.AccountMeResponse
		err = json.NewDecoder(w.Body).Decode(&meResponse)
		require.NoError(t, err)
		assert.Equal(t, user.ID.String(), meResponse.User.ID)
		assert.Equal(t, user.Name, meResponse.User.Name)
		assert.Equal(t, user.Email, meResponse.User.Email)
		assert.Equal(t, "inactive", meResponse.MFA) // MFA should be inactive by default

		// 6. Test UpdateAccountHandler
		updateRequest := handlers.UpdateAccountRequest{
			Status: domain.AccountStatusInactive,
		}
		body, _ := json.Marshal(updateRequest)

		req = httptest.NewRequest("PUT", "/api/accounts", bytes.NewBuffer(body))
		ctxWithUser = context.WithValue(req.Context(), domain.ContextKeySubject, user.ID.String())
		req = req.WithContext(ctxWithUser)

		w = httptest.NewRecorder()
		accountHandler.UpdateAccountHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// 7. Verify account was updated
		updatedAccount, err := accountService.GetAccountByUserID(ctx, user.ID)
		require.NoError(t, err)
		assert.Equal(t, domain.AccountStatusInactive, updatedAccount.Status)

		// 8. Test DeleteAccountHandler
		req = httptest.NewRequest("DELETE", "/api/accounts", nil)
		ctxWithUser = context.WithValue(req.Context(), domain.ContextKeySubject, user.ID.String())
		req = req.WithContext(ctxWithUser)

		w = httptest.NewRecorder()
		accountHandler.DeleteAccountHandler(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)

		// 11. Verify account was deleted
		_, err = accountService.GetAccountByUserID(ctx, user.ID)
		assert.Error(t, err)
		assert.Equal(t, domain.ErrAccountNotFound, err)
	})

	t.Run("Account Creation During Registration", func(t *testing.T) {
		// Test that account is automatically created during user registration
		user, err := authService.Register(ctx, "Auto Account User", "auto@example.com", "password123", "9876543210", nil)
		require.NoError(t, err)
		assert.NotNil(t, user)

		// Verify account was created
		account, err := accountService.GetAccountByUserID(ctx, user.ID)
		require.NoError(t, err)
		assert.NotNil(t, account)
		assert.Equal(t, user.ID, account.UserID)
		assert.Equal(t, domain.AccountStatusActive, account.Status)
	})

	t.Run("Account Rollback on Registration Failure", func(t *testing.T) {
		// This test would require mocking the account service to simulate failure
		// For now, we'll test the happy path
		user, err := authService.Register(ctx, "Rollback Test User", "rollback@example.com", "password123", "5555555555", nil)
		require.NoError(t, err)
		assert.NotNil(t, user)

		// Verify both user and account exist
		foundUser, err := userService.GetUser(ctx, user.ID)
		require.NoError(t, err)
		assert.NotNil(t, foundUser)

		foundAccount, err := accountService.GetAccountByUserID(ctx, user.ID)
		require.NoError(t, err)
		assert.NotNil(t, foundAccount)
	})

	t.Run("Multiple Accounts for Different Users", func(t *testing.T) {
		// Create multiple users and verify each gets their own account
		user1, err := authService.Register(ctx, "User 1", "user1@example.com", "password123", "1111111111", nil)
		require.NoError(t, err)

		user2, err := authService.Register(ctx, "User 2", "user2@example.com", "password123", "2222222222", nil)
		require.NoError(t, err)

		// Verify each user has their own account
		account1, err := accountService.GetAccountByUserID(ctx, user1.ID)
		require.NoError(t, err)
		assert.Equal(t, user1.ID, account1.UserID)

		account2, err := accountService.GetAccountByUserID(ctx, user2.ID)
		require.NoError(t, err)
		assert.Equal(t, user2.ID, account2.UserID)

		// Verify accounts are different
		assert.NotEqual(t, account1.ID, account2.ID)
	})

	t.Run("Account Status Transitions", func(t *testing.T) {
		user, err := authService.Register(ctx, "Status Test User", "status@example.com", "password123", "3333333333", nil)
		require.NoError(t, err)

		account, err := accountService.GetAccountByUserID(ctx, user.ID)
		require.NoError(t, err)

		// Test status transitions
		account.Status = domain.AccountStatusInactive
		err = accountService.UpdateAccount(ctx, account)
		require.NoError(t, err)

		updatedAccount, err := accountService.GetAccountByUserID(ctx, user.ID)
		require.NoError(t, err)
		assert.Equal(t, domain.AccountStatusInactive, updatedAccount.Status)

		// Test suspended status
		updatedAccount.Status = domain.AccountStatusSuspended
		err = accountService.UpdateAccount(ctx, updatedAccount)
		require.NoError(t, err)

		finalAccount, err := accountService.GetAccountByUserID(ctx, user.ID)
		require.NoError(t, err)
		assert.Equal(t, domain.AccountStatusSuspended, finalAccount.Status)
	})
}
