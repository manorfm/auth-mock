package email

import (
	"context"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/infrastructure/config"
	"go.uber.org/zap"
)

type EmailTemplate struct {
	config      *config.SMTPConfig
	logger      *zap.Logger
	emailSender domain.EmailSender
}

func NewEmailTemplate(cfg *config.SMTPConfig, logger *zap.Logger) *EmailTemplate {
	emailCommand := NewEmailService(cfg, logger)
	return &EmailTemplate{
		config:      cfg,
		logger:      logger,
		emailSender: emailCommand,
	}
}

func (s *EmailTemplate) SendVerificationEmail(ctx context.Context, email, code string) error {
	subject := "Welcome! Please verify your email"
	template := `
Hi there! 👋

Welcome to our platform! We're excited to have you on board.

To get started, please verify your email address by entering this code:
%s

This code will expire in 24 hours.

If you didn't request this verification, you can safely ignore this email.

Best regards,
The Team
`
	return s.emailSender.Send(ctx, email, subject, template, code)
}

func (s *EmailTemplate) SendPasswordResetEmail(ctx context.Context, email, code string) error {
	subject := "Reset your password"
	template := `
Hi there! 👋

We received a request to reset your password. To proceed, please use this code:
%s

This code will expire in 1 hour.

If you didn't request a password reset, please ignore this email or contact support if you have concerns.

Stay secure,
The Team
`
	return s.emailSender.Send(ctx, email, subject, template, code)
}
