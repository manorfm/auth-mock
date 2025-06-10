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
	// Login authenticates a user and returns a token pair or MFA ticket
	Login(ctx context.Context, email, password string) (interface{}, error)
	// VerifyMFA verifies the MFA code and returns a token pair
	VerifyMFA(ctx context.Context, ticketID, code string) (*TokenPair, error)
	// VerifyEmail verifies the email code and returns a token pair
	VerifyEmail(ctx context.Context, email, code string) error
	// RequestPasswordReset requests a password reset
	RequestPasswordReset(ctx context.Context, email string) error
	// ResetPassword resets the password
	ResetPassword(ctx context.Context, email, code, newPassword string) error
}
