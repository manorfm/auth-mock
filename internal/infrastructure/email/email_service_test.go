package email

import (
	"context"
	"errors"
	"net/smtp"
	"testing"

	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/infrastructure/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

// MockSMTPClient is a mock implementation of SMTPClient
type MockSMTPClient struct {
	mock.Mock
}

func (m *MockSMTPClient) SendMail(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	args := m.Called(addr, a, from, to, msg)
	return args.Error(0)
}

func TestEmailService_SendEmail(t *testing.T) {
	tests := []struct {
		name          string
		email         string
		subject       string
		template      string
		code          string
		config        *config.SMTPConfig
		mockSetup     func(*MockSMTPClient)
		expectedError error
	}{
		{
			name:     "successful email send",
			email:    "test@example.com",
			subject:  "Test Subject",
			template: "Test template with code: %s",
			code:     "123456",
			config: &config.SMTPConfig{
				Host:           "smtp.example.com",
				Port:           587,
				Username:       "user",
				Password:       "pass",
				From:           "noreply@example.com",
				AuthValidation: true,
				UseTLS:         false,
			},
			mockSetup: func(m *MockSMTPClient) {
				m.On("SendMail",
					"smtp.example.com:587",
					mock.Anything,
					"noreply@example.com",
					[]string{"test@example.com"},
					mock.Anything,
				).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:     "invalid email address",
			email:    "invalid-email",
			subject:  "Test Subject",
			template: "Test template with code: %s",
			code:     "123456",
			config: &config.SMTPConfig{
				Host:           "smtp.example.com",
				Port:           587,
				Username:       "user",
				Password:       "pass",
				From:           "noreply@example.com",
				AuthValidation: true,
				UseTLS:         false,
			},
			mockSetup:     func(m *MockSMTPClient) {},
			expectedError: domain.ErrInvalidEmail,
		},
		{
			name:     "smtp error",
			email:    "test@example.com",
			subject:  "Test Subject",
			template: "Test template with code: %s",
			code:     "123456",
			config: &config.SMTPConfig{
				Host:           "smtp.example.com",
				Port:           587,
				Username:       "user",
				Password:       "pass",
				From:           "noreply@example.com",
				AuthValidation: true,
				UseTLS:         false,
			},
			mockSetup: func(m *MockSMTPClient) {
				m.On("SendMail",
					"smtp.example.com:587",
					mock.Anything,
					"noreply@example.com",
					[]string{"test@example.com"},
					mock.Anything,
				).Return(errors.New("smtp error"))
			},
			expectedError: errors.New("smtp error"),
		},
		{
			name:     "missing configuration",
			email:    "test@example.com",
			subject:  "Test Subject",
			template: "Test template with code: %s",
			code:     "123456",
			config: &config.SMTPConfig{
				Host:           "",
				Port:           587,
				Username:       "",
				Password:       "",
				From:           "",
				AuthValidation: true,
				UseTLS:         false,
			},
			mockSetup:     func(m *MockSMTPClient) {},
			expectedError: domain.ErrMissingSMTPConfiguration,
		},
		{
			name:     "email with request ID",
			email:    "test@example.com",
			subject:  "Test Subject",
			template: "Test template with code: %s",
			code:     "123456",
			config: &config.SMTPConfig{
				Host:           "smtp.example.com",
				Port:           587,
				Username:       "user",
				Password:       "pass",
				From:           "noreply@example.com",
				AuthValidation: true,
				UseTLS:         false,
			},
			mockSetup: func(m *MockSMTPClient) {
				m.On("SendMail",
					"smtp.example.com:587",
					mock.Anything,
					"noreply@example.com",
					[]string{"test@example.com"},
					mock.Anything,
				).Return(nil)
			},
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock SMTP client
			mockSMTP := new(MockSMTPClient)
			tt.mockSetup(mockSMTP)

			// Create logger
			logger, _ := zap.NewDevelopment()

			// Create email service with mock
			service := &EmailService{
				config:     tt.config,
				logger:     logger,
				smtpClient: mockSMTP,
			}

			// Create context with request ID for specific test
			ctx := context.Background()
			if tt.name == "email with request ID" {
				ctx = context.WithValue(ctx, "request_id", "test-request-id")
			}

			// Send email
			err := service.Send(ctx, tt.email, tt.subject, tt.template, tt.code)

			// Assert results
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}

			// Verify mock expectations
			mockSMTP.AssertExpectations(t)
		})
	}
}

func TestEmailService_validateConfig(t *testing.T) {
	tests := []struct {
		name          string
		config        *config.SMTPConfig
		expectedError error
	}{
		{
			name: "valid configuration",
			config: &config.SMTPConfig{
				Host:           "smtp.example.com",
				Port:           587,
				Username:       "user",
				Password:       "pass",
				From:           "noreply@example.com",
				AuthValidation: true,
			},
			expectedError: nil,
		},
		{
			name: "missing host",
			config: &config.SMTPConfig{
				Port:           587,
				Username:       "user",
				Password:       "pass",
				From:           "noreply@example.com",
				AuthValidation: true,
			},
			expectedError: domain.ErrMissingSMTPConfiguration,
		},
		{
			name: "missing username",
			config: &config.SMTPConfig{
				Host:           "smtp.example.com",
				Port:           587,
				Password:       "pass",
				From:           "noreply@example.com",
				AuthValidation: true,
			},
			expectedError: domain.ErrMissingSMTPConfiguration,
		},
		{
			name: "missing password",
			config: &config.SMTPConfig{
				Host:           "smtp.example.com",
				Port:           587,
				Username:       "user",
				From:           "noreply@example.com",
				AuthValidation: true,
			},
			expectedError: domain.ErrMissingSMTPConfiguration,
		},
		{
			name: "missing from",
			config: &config.SMTPConfig{
				Host:           "smtp.example.com",
				Port:           587,
				Username:       "user",
				Password:       "pass",
				AuthValidation: true,
			},
			expectedError: domain.ErrMissingSMTPConfiguration,
		},
		{
			name: "auth validation disabled",
			config: &config.SMTPConfig{
				Host:           "smtp.example.com",
				Port:           587,
				Username:       "",
				Password:       "",
				From:           "noreply@example.com",
				AuthValidation: false,
			},
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create logger
			logger, _ := zap.NewDevelopment()

			// Create email service
			service := &EmailService{
				config: tt.config,
				logger: logger,
			}

			// Validate config
			err := service.validateConfig()

			// Assert results
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEmailMessage_Build(t *testing.T) {
	msg := &EmailMessage{
		From:    "from@example.com",
		To:      "to@example.com",
		Subject: "Test Subject",
		Body:    "Test Body",
	}

	expected := "From: from@example.com\r\nTo: to@example.com\r\nSubject: Test Subject\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nTest Body"
	assert.Equal(t, expected, msg.Build())
}
