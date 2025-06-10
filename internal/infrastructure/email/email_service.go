package email

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/mail"
	"net/smtp"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/infrastructure/config"
	"go.uber.org/zap"
)

// SMTPClient defines the interface for SMTP operations
type SMTPClient interface {
	SendMail(addr string, a smtp.Auth, from string, to []string, msg []byte) error
}

// EmailMessage represents an email message
type EmailMessage struct {
	From    string
	To      string
	Subject string
	Body    string
}

func (e *EmailMessage) Build() string {
	return fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		e.From, e.To, e.Subject, e.Body)
}

// EmailService implements the EmailServiceInterface
type EmailService struct {
	config     *config.SMTPConfig
	logger     *zap.Logger
	smtpClient SMTPClient
}

// NewEmailService creates a new instance of EmailService
func NewEmailService(cfg *config.SMTPConfig, logger *zap.Logger) domain.EmailSender {
	return &EmailService{
		config:     cfg,
		logger:     logger,
		smtpClient: &realSMTPClient{},
	}
}

// realSMTPClient implements the SMTPClient interface
type realSMTPClient struct{}

func (c *realSMTPClient) SendMail(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	return smtp.SendMail(addr, a, from, to, msg)
}

func (s *EmailService) isValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func (s *EmailService) validateConfig() error {
	var missing []string

	if s.config.Host == "" {
		missing = append(missing, "SMTP_HOST")
	}
	if s.config.Username == "" {
		missing = append(missing, "SMTP_USERNAME")
	}
	if s.config.Password == "" {
		missing = append(missing, "SMTP_PASSWORD")
	}
	if s.config.From == "" {
		missing = append(missing, "SMTP_FROM")
	}
	if s.config.AuthValidation && len(missing) > 0 {
		s.logger.Error("Missing SMTP configuration", zap.Strings("missing_fields", missing))
		return domain.ErrMissingSMTPConfiguration
	}
	return nil
}

func (s *EmailService) Send(ctx context.Context, email, subject, template, code string) error {
	if !s.isValidEmail(email) {
		s.logger.Error("Invalid email address", zap.String("email", email))
		return domain.ErrInvalidEmail
	}

	body := fmt.Sprintf(template, code)

	if err := s.validateConfig(); err != nil {
		s.logger.Error("Invalid SMTP configuration", zap.Error(err))
		return err
	}

	msg := &EmailMessage{
		From:    s.config.From,
		To:      email,
		Subject: subject,
		Body:    body,
	}

	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	var auth smtp.Auth

	// Only set up authentication if username and password are provided
	if s.config.Username != "" && s.config.Password != "" {
		auth = smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)
	}

	// For testing purposes, if we're using a mock SMTP client, skip TLS
	if s.config.UseTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: s.config.SkipVerify,
			ServerName:         s.config.Host,
		}

		// Create a custom SMTP client with TLS
		client, err := smtp.Dial(addr)
		if err != nil {
			return fmt.Errorf("failed to connect to SMTP server: %w", err)
		}
		defer client.Close()

		if err = client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("failed to start TLS: %w", err)
		}

		if auth != nil {
			if err = client.Auth(auth); err != nil {
				return fmt.Errorf("failed to authenticate: %w", err)
			}
		}

		if err = client.Mail(s.config.From); err != nil {
			return fmt.Errorf("failed to set sender: %w", err)
		}

		if err = client.Rcpt(email); err != nil {
			return fmt.Errorf("failed to set recipient: %w", err)
		}

		w, err := client.Data()
		if err != nil {
			return fmt.Errorf("failed to create message writer: %w", err)
		}
		defer w.Close()

		_, err = w.Write([]byte(msg.Build()))
		if err != nil {
			return fmt.Errorf("failed to write message: %w", err)
		}

		return nil
	}

	// Use standard SMTP client for non-TLS connections
	err := s.smtpClient.SendMail(addr, auth, s.config.From, []string{email}, []byte(msg.Build()))
	if err != nil {
		s.logger.Error("Failed to send email",
			zap.String("to", email),
			zap.String("subject", subject),
			zap.String("smtp_host", s.config.Host),
			zap.Int("smtp_port", s.config.Port),
			zap.Error(err),
			zap.String("request_id", getRequestID(ctx)),
		)
		return err
	}

	s.logger.Info("Email sent successfully",
		zap.String("to", email),
		zap.String("subject", subject),
		zap.String("request_id", getRequestID(ctx)),
	)
	return nil
}

// getRequestID retrieves the request ID from context if present
func getRequestID(ctx context.Context) string {
	if v := ctx.Value("request_id"); v != nil {
		if id, ok := v.(string); ok {
			return id
		}
	}
	return ""
}
