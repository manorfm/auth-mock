package domain

import (
	"context"
	"time"

	"github.com/oklog/ulid/v2"
)

// MFATicket represents a temporary ticket for MFA verification
type MFATicket struct {
	Ticket    ulid.ULID `json:"ticket"`
	User      string    `json:"user"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// MFATicketRepository defines the interface for MFA ticket operations
type MFATicketRepository interface {
	// Create creates a new MFA ticket
	Create(ctx context.Context, ticket *MFATicket) error
	// Get retrieves an MFA ticket by ID
	Get(ctx context.Context, id string) (*MFATicket, error)
	// Delete deletes an MFA ticket
	Delete(ctx context.Context, id string) error
}

// UserService defines the interface for user operations
type AuthService interface {
	// Register creates a new user
	Register(ctx context.Context, name, email, password, phone string, roles []string) (*User, error)
	RegisterClient(ctx context.Context, name, email, password, phone string) (*User, error)
	RegisterClientWithCPF(ctx context.Context, name, email, password, phone, cpf string) (*User, error)
	RegisterManagementOwner(ctx context.Context, name, email, password, phone string) (*User, error)
	RegisterManagementOwnerWithCPF(ctx context.Context, name, email, password, phone, cpf string) (*User, error)
	CreateStandaloneUserByAdmin(ctx context.Context, name, email, password, phone string, channels, roles []string) (*User, error)
	CreateStandaloneUserByAdminWithCPF(ctx context.Context, name, email, password, phone, cpf string, channels, roles []string) (*User, error)
	AssignRoleToStandalone(ctx context.Context, userID, role string) ([]string, error)
	RemoveRoleFromStandalone(ctx context.Context, userID, role string) ([]string, error)
	ListRolesByUser(ctx context.Context, userID string) ([]RoleDefinition, error)
	CreateCustomRole(ctx context.Context, role string) error
	RenameCustomRole(ctx context.Context, fromName, toName string) error
	DeleteCustomRole(ctx context.Context, role string) error
	ListRoles(ctx context.Context) ([]RoleDefinition, error)
	// Login authenticates a user and returns a token pair or MFA ticket
	Login(ctx context.Context, email, password, channel string) (interface{}, error)
	// VerifyMFA verifies the MFA code and returns a token pair
	VerifyMFA(ctx context.Context, ticketID, code string) (*TokenPair, error)
	// VerifyEmail verifies the email code and returns a token pair
	VerifyEmail(ctx context.Context, email, code string) error
	// RequestPasswordReset requests a password reset
	RequestPasswordReset(ctx context.Context, email string) error
	// ResetPassword resets the password
	ResetPassword(ctx context.Context, email, code, newPassword string) error
	// RefreshWithRefreshToken issues a new access/refresh pair from a valid refresh JWT.
	RefreshWithRefreshToken(ctx context.Context, refreshToken string) (*TokenPair, error)
	// LogoutWithRefreshToken invalidates the provided refresh JWT.
	LogoutWithRefreshToken(ctx context.Context, refreshToken string) error
	// ResendVerificationEmail generates a new email verification code when verification is enabled.
	ResendVerificationEmail(ctx context.Context, email string) error
}

type RoleDefinition struct {
	Name     string `json:"name"`
	IsSystem bool   `json:"is_system"`
}
