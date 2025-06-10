package domain

import "context"

// EmailService defines the interface for email operations
type EmailService interface {
	// SendVerificationEmail sends a verification email to the user
	SendVerificationEmail(ctx context.Context, email, code string) error

	// SendPasswordResetEmail sends a password reset email to the user
	SendPasswordResetEmail(ctx context.Context, email, code string) error
}
