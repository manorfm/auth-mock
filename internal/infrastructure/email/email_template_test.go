package email

import (
	"context"
	"errors"
	"testing"

	"github.com/manorfm/auth-mock/internal/infrastructure/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

// MockEmailService is a mock implementation of EmailServiceInterface
type MockEmailSender struct {
	mock.Mock
}

func (m *MockEmailSender) Send(ctx context.Context, email, subject, template, code string) error {
	args := m.Called(ctx, email, subject, template, code)
	return args.Error(0)
}

func TestEmailTemplate_SendVerificationEmail(t *testing.T) {
	tests := []struct {
		name          string
		email         string
		code          string
		mockSetup     func(*MockEmailSender)
		expectedError error
	}{
		{
			name:  "successful verification email",
			email: "test@example.com",
			code:  "123456",
			mockSetup: func(m *MockEmailSender) {
				m.On("Send",
					mock.Anything,
					"test@example.com",
					"Welcome! Please verify your email",
					mock.Anything,
					"123456",
				).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:  "smtp error during verification",
			email: "test@example.com",
			code:  "123456",
			mockSetup: func(m *MockEmailSender) {
				m.On("Send",
					mock.Anything,
					"test@example.com",
					"Welcome! Please verify your email",
					mock.Anything,
					"123456",
				).Return(errors.New("smtp error"))
			},
			expectedError: errors.New("smtp error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock email service
			mockEmailService := new(MockEmailSender)
			tt.mockSetup(mockEmailService)

			// Create logger
			logger, _ := zap.NewDevelopment()

			// Create email template with mock service
			template := &EmailTemplate{
				config:      &config.SMTPConfig{},
				logger:      logger,
				emailSender: mockEmailService,
			}

			// Send verification email
			err := template.SendVerificationEmail(context.Background(), tt.email, tt.code)

			// Assert results
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}

			// Verify mock expectations
			mockEmailService.AssertExpectations(t)
		})
	}
}

func TestEmailTemplate_SendPasswordResetEmail(t *testing.T) {
	tests := []struct {
		name          string
		email         string
		code          string
		mockSetup     func(*MockEmailSender)
		expectedError error
	}{
		{
			name:  "successful password reset email",
			email: "test@example.com",
			code:  "123456",
			mockSetup: func(m *MockEmailSender) {
				m.On("Send",
					mock.Anything,
					"test@example.com",
					"Reset your password",
					mock.Anything,
					"123456",
				).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:  "smtp error during password reset",
			email: "test@example.com",
			code:  "123456",
			mockSetup: func(m *MockEmailSender) {
				m.On("Send",
					mock.Anything,
					"test@example.com",
					"Reset your password",
					mock.Anything,
					"123456",
				).Return(errors.New("smtp error"))
			},
			expectedError: errors.New("smtp error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock email service
			mockEmailService := new(MockEmailSender)
			tt.mockSetup(mockEmailService)

			// Create logger
			logger, _ := zap.NewDevelopment()

			// Create email template with mock service
			template := &EmailTemplate{
				config:      &config.SMTPConfig{},
				logger:      logger,
				emailSender: mockEmailService,
			}

			// Send password reset email
			err := template.SendPasswordResetEmail(context.Background(), tt.email, tt.code)

			// Assert results
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}

			// Verify mock expectations
			mockEmailService.AssertExpectations(t)
		})
	}
}
