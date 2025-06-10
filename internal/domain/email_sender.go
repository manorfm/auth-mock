package domain

import "context"

// EmailSender defines the interface for email service operations
type EmailSender interface {
	Send(ctx context.Context, email, subject, template, code string) error
}
