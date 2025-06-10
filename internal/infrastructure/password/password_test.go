package password

import (
	"testing"
)

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "valid password",
			password: "securePassword123!",
			wantErr:  false,
		},
		{
			name:     "empty password",
			password: "",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashPassword(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("HashPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if hash == "" {
				t.Error("HashPassword() returned empty hash")
			}
		})
	}
}

func TestCheckPassword(t *testing.T) {
	password := "securePassword123!"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() failed: %v", err)
	}

	tests := []struct {
		name     string
		password string
		hash     string
		wantErr  bool
	}{
		{
			name:     "correct password",
			password: password,
			hash:     hash,
			wantErr:  false,
		},
		{
			name:     "incorrect password",
			password: "wrongPassword123!",
			hash:     hash,
			wantErr:  true,
		},
		{
			name:     "empty password",
			password: "",
			hash:     hash,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckPassword(tt.password, tt.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckPassword() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
