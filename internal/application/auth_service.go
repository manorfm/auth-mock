package application

import (
	"context"
	"time"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/infrastructure/config"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	config           *config.Config
	userRepo         domain.UserRepository
	verificationRepo domain.VerificationCodeRepository
	jwtService       domain.JWTService
	emailService     domain.EmailService
	totpService      domain.TOTPService
	mfaTicketRepo    domain.MFATicketRepository
	logger           *zap.Logger
}

func NewAuthService(
	config *config.Config,
	userRepo domain.UserRepository,
	verificationRepo domain.VerificationCodeRepository,
	jwtService domain.JWTService,
	emailService domain.EmailService,
	totpService domain.TOTPService,
	mfaTicketRepo domain.MFATicketRepository,
	logger *zap.Logger,
) *AuthService {
	return &AuthService{
		config:           config,
		userRepo:         userRepo,
		verificationRepo: verificationRepo,
		jwtService:       jwtService,
		emailService:     emailService,
		totpService:      totpService,
		mfaTicketRepo:    mfaTicketRepo,
		logger:           logger,
	}
}

// Register creates a new user
func (s *AuthService) Register(ctx context.Context, name, email, password, phone string, roles []string) (*domain.User, error) {
	// Check if user already exists
	exists, err := s.userRepo.ExistsByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, domain.ErrUserAlreadyExists
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	emailVerified := true
	if s.config.EmailEnabled {
		emailVerified = false
	}

	if roles == nil {
		roles = []string{"ADMIN", "USER"}
	}

	// Create user
	user := &domain.User{
		ID:            ulid.Make(),
		Name:          name,
		Email:         email,
		Password:      string(hashedPassword),
		Phone:         phone,
		Roles:         roles,
		EmailVerified: emailVerified,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	// Generate verification code
	code := generateRandomCode()
	verificationCode := domain.NewVerificationCode(user.ID, code, domain.EmailVerification, 24*time.Hour)

	// Store verification code
	if err := s.verificationRepo.Create(ctx, verificationCode); err != nil {
		s.logger.Error("Failed to store verification code", zap.Error(err))
		return nil, domain.ErrInternal
	}

	// Send verification email if email is enabled
	if s.config.EmailEnabled {
		// Send verification email
		if err := s.emailService.SendVerificationEmail(ctx, email, code); err != nil {
			s.logger.Error("Failed to send verification email", zap.Error(err))
			return nil, domain.ErrEmailSendFailed
		}
	}

	return user, nil
}

func (s *AuthService) Login(ctx context.Context, email, password string) (interface{}, error) {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	if !user.EmailVerified {
		return nil, domain.ErrEmailNotVerified
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	// Check if TOTP is enabled for the user
	secret, err := s.totpService.GetTOTPSecret(ctx, user.ID.String())
	if err != nil {
		// If TOTP is not enabled, proceed with normal login
		if err == domain.ErrTOTPNotEnabled || secret == "" {
			tokenPair, err := s.jwtService.GenerateTokenPair(user.ID, user.Roles)
			if err != nil {
				return nil, err
			}
			return tokenPair, nil
		}

		s.logger.Error("Failed to check TOTP status",
			zap.String("user_id", user.ID.String()),
			zap.Error(err))
		return nil, domain.ErrInternal
	}

	// Generate MFA ticket
	ticketID := ulid.Make()
	ticket := &domain.MFATicket{
		Ticket:    ticketID,
		User:      user.ID.String(),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	if err := s.mfaTicketRepo.Create(ctx, ticket); err != nil {
		s.logger.Error("Failed to create MFA ticket",
			zap.String("user_id", user.ID.String()),
			zap.Error(err))
		return nil, domain.ErrInternal
	}

	return ticket, nil
}

func (s *AuthService) VerifyEmail(ctx context.Context, email, code string) error {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return domain.ErrUserNotFound
	}

	if user.EmailVerified {
		return nil // Already verified
	}

	// Find verification code using user ID and type
	verificationCode, err := s.verificationRepo.FindByUserIDAndType(ctx, user.ID, domain.EmailVerification)
	if err != nil {
		return domain.ErrInvalidVerificationCode
	}

	// Verify the code matches
	if verificationCode.Code != code {
		return domain.ErrInvalidVerificationCode
	}

	// Check if code is expired
	if verificationCode.IsExpired() {
		// Delete old code first
		if err := s.verificationRepo.DeleteByUserIDAndType(ctx, user.ID, domain.EmailVerification); err != nil {
			s.logger.Error("Failed to delete old verification code", zap.Error(err))
		}

		// Generate new code
		newCode := generateRandomCode()
		newVerificationCode := domain.NewVerificationCode(user.ID, newCode, domain.EmailVerification, 24*time.Hour)

		// Store new code
		if err := s.verificationRepo.Create(ctx, newVerificationCode); err != nil {
			s.logger.Error("Failed to store new verification code", zap.Error(err))
			return domain.ErrInternal
		}

		// Send new verification email
		if err := s.emailService.SendVerificationEmail(ctx, email, newCode); err != nil {
			s.logger.Error("Failed to send new verification email", zap.Error(err))
			return domain.ErrEmailSendFailed
		}

		return domain.ErrVerificationCodeExpired
	}

	// Delete the used code
	if err := s.verificationRepo.DeleteByUserIDAndType(ctx, user.ID, domain.EmailVerification); err != nil {
		s.logger.Error("Failed to delete verification code", zap.Error(err))
		return domain.ErrInternal
	}

	// Update user
	user.EmailVerified = true
	user.UpdatedAt = time.Now()

	return s.userRepo.Update(ctx, user)
}

func (s *AuthService) RequestPasswordReset(ctx context.Context, email string) error {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return domain.ErrUserNotFound
	}

	// Delete any existing reset codes first
	if err := s.verificationRepo.DeleteByUserIDAndType(ctx, user.ID, domain.PasswordReset); err != nil {
		s.logger.Error("Failed to delete existing reset codes", zap.Error(err))
		return domain.ErrInternal
	}

	// Generate reset code
	code := generateRandomCode()
	resetCode := domain.NewVerificationCode(user.ID, code, domain.PasswordReset, 1*time.Hour)

	// Store reset code
	if err := s.verificationRepo.Create(ctx, resetCode); err != nil {
		s.logger.Error("Failed to store password reset code", zap.Error(err))
		return domain.ErrInternal
	}

	// Send reset email
	if err := s.emailService.SendPasswordResetEmail(ctx, email, code); err != nil {
		s.logger.Error("Failed to send password reset email", zap.Error(err))
		return domain.ErrEmailSendFailed
	}

	return nil
}

func (s *AuthService) ResetPassword(ctx context.Context, email, code, newPassword string) error {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return domain.ErrUserNotFound
	}

	// Find reset code using user ID and type
	resetCode, err := s.verificationRepo.FindByUserIDAndType(ctx, user.ID, domain.PasswordReset)
	if err != nil {
		return domain.ErrInvalidPasswordChangeCode
	}

	// Verify the code matches
	if resetCode.Code != code {
		return domain.ErrInvalidPasswordChangeCode
	}

	var deleteCode = func() {
		if err := s.verificationRepo.DeleteByUserIDAndType(ctx, user.ID, domain.PasswordReset); err != nil {
			s.logger.Error("Failed to delete reset code", zap.Error(err))
		}
	}

	// Check if code is expired
	if resetCode.IsExpired() {
		deleteCode()
		return domain.ErrPasswordChangeCodeExpired
	}

	// Delete the used code
	deleteCode()

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Update password using dedicated method
	return s.userRepo.UpdatePassword(ctx, user.ID, string(hashedPassword))
}

func (s *AuthService) VerifyMFA(ctx context.Context, ticketID, code string) (*domain.TokenPair, error) {
	// Get and validate ticket
	ticket, err := s.mfaTicketRepo.Get(ctx, ticketID)
	if err != nil {
		return nil, err
	}

	if time.Now().After(ticket.ExpiresAt) {
		s.logger.Error("MFA ticket expired", zap.String("ticket_id", ticketID))
		s.mfaTicketRepo.Delete(ctx, ticketID)
		return nil, domain.ErrMFATicketExpired
	}

	// Get user
	userID, err := ulid.Parse(ticket.User)
	if err != nil {
		s.logger.Error("Invalid user ID", zap.String("ticket_id", ticketID), zap.Error(err))
		return nil, domain.ErrInvalidUserID
	}

	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		s.logger.Error("User not found", zap.String("ticket_id", ticketID), zap.Error(err))
		return nil, domain.ErrUserNotFound
	}

	// Verify TOTP code
	err = s.totpService.VerifyTOTP(user.ID.String(), code)
	if err != nil {
		s.logger.Error("Invalid TOTP code", zap.String("ticket_id", ticketID), zap.Error(err))
		return nil, err
	}

	// Delete ticket
	if err := s.mfaTicketRepo.Delete(ctx, ticketID); err != nil {
		s.logger.Error("Failed to delete MFA ticket",
			zap.String("ticket_id", ticketID),
			zap.Error(err))
		return nil, domain.ErrInternal
	}

	// Generate token pair with MFA AMR
	tokenPair, err := s.jwtService.GenerateTokenPair(user.ID, user.Roles)
	if err != nil {
		return nil, err
	}

	return tokenPair, nil
}

func generateRandomCode() string {
	// Generate a ULID which provides good entropy and is time-ordered
	id := ulid.Make()
	return id.String()
}
