package application

import (
	"context"
	"strings"
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
	accountService   domain.AccountService
	verificationRepo domain.VerificationCodeRepository
	jwtService       domain.JWTService
	emailService     domain.EmailService
	totpService      domain.TOTPService
	mfaTicketRepo    domain.MFATicketRepository
	logger           *zap.Logger
	roleCatalog      map[string]bool
}

func NewAuthService(
	config *config.Config,
	userRepo domain.UserRepository,
	accountService domain.AccountService,
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
		accountService:   accountService,
		verificationRepo: verificationRepo,
		jwtService:       jwtService,
		emailService:     emailService,
		totpService:      totpService,
		mfaTicketRepo:    mfaTicketRepo,
		logger:           logger,
		roleCatalog: map[string]bool{
			domain.RoleRoot:  true,
			domain.RoleAdmin: true,
			domain.RoleUser:  true,
		},
	}
}

// Register creates a new user
func (s *AuthService) Register(ctx context.Context, name, email, password, phone string, roles []string) (*domain.User, error) {
	return s.registerWithProfile(ctx, name, email, password, phone, domain.UserTypeManagement, []string{domain.ChannelManagementPanel}, roles, false, true)
}

func (s *AuthService) RegisterClient(ctx context.Context, name, email, password, phone string) (*domain.User, error) {
	return s.registerWithProfile(ctx, name, email, password, phone, domain.UserTypeClient, []string{domain.ChannelClientApp}, []string{domain.RoleUser}, false, false)
}

func (s *AuthService) RegisterManagementOwner(ctx context.Context, name, email, password, phone string) (*domain.User, error) {
	return s.registerWithProfile(ctx, name, email, password, phone, domain.UserTypeManagement, []string{domain.ChannelManagementPanel}, []string{domain.RoleUser}, false, false)
}

func (s *AuthService) CreateStandaloneUserByAdmin(ctx context.Context, name, email, password, phone string, channels, roles []string) (*domain.User, error) {
	if len(channels) == 0 {
		channels = []string{domain.ChannelManagementPanel}
	}
	if len(roles) == 0 {
		roles = []string{domain.RoleUser}
	}
	channels = normalizeChannels(channels)
	if err := validateChannels(channels); err != nil {
		return nil, err
	}
	for _, role := range roles {
		nr := strings.TrimSpace(strings.ToLower(role))
		if nr == domain.RoleRoot || nr == domain.RoleAdmin {
			return nil, domain.ErrAuthRoleProtected
		}
	}
	u, err := s.registerWithProfile(ctx, name, email, password, phone, domain.UserTypeStandalone, channels, roles, true, false)
	if err == nil {
		s.auditAuth(ctx, "admin_create_standalone_user", zap.String("target_user_id", u.ID.String()), zap.String("email", u.Email))
	}
	return u, err
}

func (s *AuthService) registerWithProfile(ctx context.Context, name, email, password, phone, userType string, channels, roles []string, forceEmailVerified bool, allowElevatedRoles bool) (*domain.User, error) {
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

	if len(roles) == 0 {
		roles = []string{domain.RoleUser}
	}
	if forceEmailVerified {
		emailVerified = true
	}
	channels = normalizeChannels(channels)
	if len(channels) == 0 {
		return nil, domain.ErrAuthForbiddenChannel
	}
	if err := validateChannels(channels); err != nil {
		return nil, err
	}
	roles = normalizeRoles(roles)
	if !allowElevatedRoles {
		for _, role := range roles {
			if role == domain.RoleAdmin || role == domain.RoleRoot {
				return nil, domain.ErrAuthRoleProtected
			}
		}
	}
	if !s.rolesExist(roles) {
		return nil, domain.ErrAuthRoleNotFound
	}

	// Create user
	user := &domain.User{
		ID:            ulid.Make(),
		Name:          name,
		Email:         email,
		Password:      string(hashedPassword),
		Phone:         phone,
		Roles:         roles,
		UserType:      userType,
		Channels:      channels,
		EmailVerified: emailVerified,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	// Create account for the user
	_, err = s.accountService.CreateAccount(ctx, user.ID)
	if err != nil {
		// If account creation fails, delete the user and return error
		s.logger.Error("Failed to create account, rolling back user creation", zap.Error(err))
		if deleteErr := s.userRepo.Delete(ctx, user.ID); deleteErr != nil {
			s.logger.Error("Failed to delete user after account creation failure", zap.Error(deleteErr))
		}
		return nil, domain.ErrAccountCreationFailed
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

func (s *AuthService) Login(ctx context.Context, email, password, channel string) (interface{}, error) {
	channel = strings.TrimSpace(strings.ToLower(channel))
	if err := validateChannels([]string{channel}); err != nil {
		return nil, err
	}
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil, domain.ErrAuthInvalidCredentials
	}

	if !user.EmailVerified {
		return nil, domain.ErrEmailNotVerified
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, domain.ErrAuthInvalidCredentials
	}
	if !contains(user.Channels, channel) {
		return nil, domain.ErrAuthForbiddenChannel
	}

	// Check if TOTP is enabled for the user
	secret, err := s.totpService.GetTOTPSecret(ctx, user.ID.String())
	if err != nil {
		// If TOTP is not enabled, proceed with normal login
		if err == domain.ErrTOTPNotEnabled || secret == "" {
			tokenPair, err := s.jwtService.GenerateTokenPair(ctx, user)
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

func (s *AuthService) AssignRoleToStandalone(ctx context.Context, userID, role string) ([]string, error) {
	role = strings.TrimSpace(strings.ToLower(role))
	id, err := ulid.Parse(userID)
	if err != nil {
		return nil, domain.ErrInvalidUserID
	}
	user, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if user.UserType != domain.UserTypeStandalone {
		return nil, domain.ErrAuthUserNotStandalone
	}
	if !s.rolesExist([]string{role}) {
		return nil, domain.ErrAuthRoleNotFound
	}
	if user.HasRole(role) {
		return user.Roles, nil
	}
	user.AddRole(role)
	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, err
	}
	s.auditAuth(ctx, "standalone_role_assign", zap.String("target_user_id", userID), zap.String("role", role))
	return user.Roles, nil
}

func (s *AuthService) RemoveRoleFromStandalone(ctx context.Context, userID, role string) ([]string, error) {
	role = strings.TrimSpace(strings.ToLower(role))
	id, err := ulid.Parse(userID)
	if err != nil {
		return nil, domain.ErrInvalidUserID
	}
	user, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if user.UserType != domain.UserTypeStandalone {
		return nil, domain.ErrAuthUserNotStandalone
	}
	if role == domain.RoleUser {
		return nil, domain.ErrAuthRoleRequiredMinimum
	}
	user.RemoveRole(role)
	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, err
	}
	s.auditAuth(ctx, "standalone_role_remove", zap.String("target_user_id", userID), zap.String("role", role))
	return user.Roles, nil
}

func (s *AuthService) ListRolesByUser(ctx context.Context, userID string) ([]domain.RoleDefinition, error) {
	id, err := ulid.Parse(userID)
	if err != nil {
		return nil, domain.ErrInvalidUserID
	}
	user, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	roles := make([]domain.RoleDefinition, 0, len(user.Roles))
	for _, role := range user.Roles {
		isSys, ok := s.roleCatalog[role]
		roles = append(roles, domain.RoleDefinition{Name: role, IsSystem: ok && isSys})
	}
	return roles, nil
}

func (s *AuthService) CreateCustomRole(ctx context.Context, role string) error {
	role = strings.TrimSpace(strings.ToLower(role))
	if role == "" {
		return domain.ErrInvalidField
	}
	isSys, exists := s.roleCatalog[role]
	if exists && isSys {
		return domain.ErrAuthRoleProtected
	}
	if exists && !isSys {
		return domain.ErrAuthRoleAlreadyAssigned
	}
	s.roleCatalog[role] = false
	s.auditAuth(ctx, "admin_role_create", zap.String("role", role))
	return nil
}

func (s *AuthService) RenameCustomRole(ctx context.Context, fromName, toName string) error {
	fromName = strings.TrimSpace(strings.ToLower(fromName))
	toName = strings.TrimSpace(strings.ToLower(toName))
	if fromName == "" || toName == "" {
		return domain.ErrInvalidField
	}
	if fromName == toName {
		return nil
	}
	fromSys, fromOK := s.roleCatalog[fromName]
	if !fromOK {
		return domain.ErrAuthRoleNotFound
	}
	if fromSys {
		return domain.ErrAuthRoleProtected
	}
	if toName != fromName {
		if toSys, toOK := s.roleCatalog[toName]; toOK {
			if toSys {
				return domain.ErrAuthRoleProtected
			}
			return domain.ErrAuthRoleAlreadyAssigned
		}
	}
	delete(s.roleCatalog, fromName)
	s.roleCatalog[toName] = false

	users, err := s.userRepo.List(ctx, 10000, 0)
	if err != nil {
		return err
	}
	for _, u := range users {
		changed := false
		for i, r := range u.Roles {
			if r == fromName {
				u.Roles[i] = toName
				changed = true
			}
		}
		if changed {
			if err := s.userRepo.Update(ctx, u); err != nil {
				return err
			}
		}
	}
	s.auditAuth(ctx, "admin_role_rename", zap.String("from", fromName), zap.String("to", toName))
	return nil
}

func (s *AuthService) DeleteCustomRole(ctx context.Context, role string) error {
	role = strings.TrimSpace(strings.ToLower(role))
	if role == "" {
		return domain.ErrInvalidField
	}
	isSys, ok := s.roleCatalog[role]
	if !ok {
		return domain.ErrAuthRoleNotFound
	}
	if isSys {
		return domain.ErrAuthRoleProtected
	}
	delete(s.roleCatalog, role)
	s.auditAuth(ctx, "admin_role_delete", zap.String("role", role))
	return nil
}

func (s *AuthService) ListRoles(ctx context.Context) ([]domain.RoleDefinition, error) {
	roles := make([]domain.RoleDefinition, 0, len(s.roleCatalog))
	for role, isSystem := range s.roleCatalog {
		roles = append(roles, domain.RoleDefinition{Name: role, IsSystem: isSystem})
	}
	return roles, nil
}

func normalizeRoles(roles []string) []string {
	normalized := make([]string, 0, len(roles))
	seen := map[string]struct{}{}
	for _, role := range roles {
		normalizedRole := strings.TrimSpace(strings.ToLower(role))
		if normalizedRole == "" {
			continue
		}
		if _, ok := seen[normalizedRole]; ok {
			continue
		}
		seen[normalizedRole] = struct{}{}
		normalized = append(normalized, normalizedRole)
	}
	return normalized
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func (s *AuthService) rolesExist(roles []string) bool {
	for _, role := range roles {
		if _, ok := s.roleCatalog[role]; !ok {
			return false
		}
	}
	return true
}

func normalizeChannels(channels []string) []string {
	out := make([]string, 0, len(channels))
	seen := map[string]struct{}{}
	for _, ch := range channels {
		c := strings.TrimSpace(strings.ToLower(ch))
		if c == "" {
			continue
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

func validateChannels(channels []string) error {
	for _, ch := range channels {
		if ch != domain.ChannelClientApp && ch != domain.ChannelManagementPanel {
			return domain.ErrAuthForbiddenChannel
		}
	}
	return nil
}

func (s *AuthService) auditAuth(ctx context.Context, action string, fields ...zap.Field) {
	actor, _ := domain.GetSubject(ctx)
	f := append([]zap.Field{
		zap.String("action", action),
		zap.String("actor_sub", actor),
	}, fields...)
	s.logger.Info("auth_audit_event", f...)
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
	tokenPair, err := s.jwtService.GenerateTokenPair(ctx, user)
	if err != nil {
		return nil, err
	}

	return tokenPair, nil
}

func (s *AuthService) RefreshWithRefreshToken(ctx context.Context, refreshToken string) (*domain.TokenPair, error) {
	claims, err := s.jwtService.ValidateToken(refreshToken)
	if err != nil {
		return nil, domain.ErrAuthInvalidCredentials
	}
	userID, err := ulid.Parse(claims.Subject)
	if err != nil {
		return nil, domain.ErrInvalidUserID
	}
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, domain.ErrAuthInvalidCredentials
	}
	return s.jwtService.GenerateTokenPair(ctx, user)
}

func (s *AuthService) ResendVerificationEmail(ctx context.Context, email string) error {
	if !s.config.EmailEnabled {
		return nil
	}
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return domain.ErrUserNotFound
	}
	if user.EmailVerified {
		return nil
	}
	if err := s.verificationRepo.DeleteByUserIDAndType(ctx, user.ID, domain.EmailVerification); err != nil {
		s.logger.Error("Failed to delete verification code", zap.Error(err))
		return domain.ErrInternal
	}
	code := generateRandomCode()
	vc := domain.NewVerificationCode(user.ID, code, domain.EmailVerification, 24*time.Hour)
	if err := s.verificationRepo.Create(ctx, vc); err != nil {
		s.logger.Error("Failed to store verification code", zap.Error(err))
		return domain.ErrInternal
	}
	if err := s.emailService.SendVerificationEmail(ctx, email, code); err != nil {
		s.logger.Error("Failed to send verification email", zap.Error(err))
		return domain.ErrEmailSendFailed
	}
	return nil
}

func generateRandomCode() string {
	// Generate a ULID which provides good entropy and is time-ordered
	id := ulid.Make()
	return id.String()
}
