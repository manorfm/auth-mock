package config

import (
	"os"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestLoadConfig(t *testing.T) {
	// Set up test environment variables
	os.Setenv("JWT_ACCESS_TOKEN_DURATION", "15m")
	os.Setenv("JWT_REFRESH_TOKEN_DURATION", "24h")
	os.Setenv("PORT", "8080")
	os.Setenv("ENVIRONMENT", "test")

	tests := []struct {
		name    string
		setup   func()
		wantErr bool
	}{
		{
			name: "valid config",
			setup: func() {
				// Environment variables already set
			},
			wantErr: false,
		},
		{
			name: "invalid jwt durations",
			setup: func() {
				os.Setenv("JWT_ACCESS_TOKEN_DURATION", "invalid")
				os.Setenv("JWT_REFRESH_TOKEN_DURATION", "invalid")
			},
			wantErr: true,
		},
		{
			name: "invalid server port",
			setup: func() {
				os.Setenv("PORT", "invalid")
			},
			wantErr: true,
		},
		{
			name: "invalid rsa key size",
			setup: func() {
				os.Setenv("RSA_KEY_SIZE", "invalid")
			},
			wantErr: true,
		},
		{
			name: "invalid smtp port",
			setup: func() {
				os.Setenv("SMTP_PORT", "invalid")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset environment variables to default values
			os.Setenv("JWT_ACCESS_TOKEN_DURATION", "15m")
			os.Setenv("JWT_REFRESH_TOKEN_DURATION", "24h")
			os.Setenv("PORT", "8080")
			os.Setenv("RSA_KEY_SIZE", "2048")
			os.Setenv("SMTP_PORT", "1025")

			// Run test-specific setup
			tt.setup()

			cfg, err := LoadConfig(zap.NewNop())
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Validate config values
				if cfg.JWTAccessDuration != 15*time.Minute {
					t.Errorf("LoadConfig() JWTAccessDuration = %v, want %v", cfg.JWTAccessDuration, 15*time.Minute)
				}
				if cfg.JWTRefreshDuration != 24*time.Hour {
					t.Errorf("LoadConfig() JWTRefreshDuration = %v, want %v", cfg.JWTRefreshDuration, 24*time.Hour)
				}
				if cfg.ServerPort != 8080 {
					t.Errorf("LoadConfig() ServerPort = %v, want %v", cfg.ServerPort, 8080)
				}
			}
		})
	}
}
