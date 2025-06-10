package domain

import (
	"context"
	"time"

	"github.com/oklog/ulid/v2"
)

// ULID represents a Universally Unique Lexicographically Sortable Identifier
// @Description A string representation of ULID
// @type string
// @format ulid
type ULID = ulid.ULID

// User represents a user in the system
type User struct {
	ID            ulid.ULID  `json:"id"`
	Name          string     `json:"name"`
	Email         string     `json:"email"`
	Password      string     `json:"-"` // Password is not serialized to JSON
	Phone         string     `json:"phone"`
	Roles         []string   `json:"roles"`
	EmailVerified bool       `json:"email_verified"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	DeletedAt     *time.Time `json:"deleted_at,omitempty"`
}

// CreateUserRequest represents the request to create a new user
type CreateUserRequest struct {
	Name     string `json:"name" validate:"required"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
	Phone    string `json:"phone" validate:"required"`
}

// UpdateUserRequest represents the request to update a user
type UpdateUserRequest struct {
	Name  string `json:"name" validate:"required"`
	Phone string `json:"phone" validate:"required"`
}

// LoginRequest represents the request to login a user
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// NewUser creates a new user instance
func NewUser(name, email, password, phone string) (*User, error) {
	id := ulid.Make()

	user := &User{
		ID:        id,
		Name:      name,
		Email:     email,
		Password:  password,
		Phone:     phone,
		Roles:     []string{"user"}, // Default role
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	return user, nil
}

// AddRole adds a role to the user
func (u *User) AddRole(role string) {
	for _, r := range u.Roles {
		if r == role {
			return
		}
	}
	u.Roles = append(u.Roles, role)
}

// RemoveRole removes a role from the user
func (u *User) RemoveRole(role string) {
	for i, r := range u.Roles {
		if r == role {
			u.Roles = append(u.Roles[:i], u.Roles[i+1:]...)
			return
		}
	}
}

// HasRole checks if the user has a specific role
func (u *User) HasRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

type UserService interface {
	GetUser(ctx context.Context, id ulid.ULID) (*User, error)
	UpdateUser(ctx context.Context, id ulid.ULID, name, phone string) error
	ListUsers(ctx context.Context, limit, offset int) ([]*User, error)
}

// UserRepository defines the interface for user data access
type UserRepository interface {
	// Create creates a new user in the memory
	Create(ctx context.Context, user *User) error

	// FindByID finds a user by ID
	FindByID(ctx context.Context, id ulid.ULID) (*User, error)

	// FindByEmail finds a user by email
	FindByEmail(ctx context.Context, email string) (*User, error)

	// ExistsByEmail checks if a user exists with the given email
	ExistsByEmail(ctx context.Context, email string) (bool, error)

	// Update updates a user
	Update(ctx context.Context, user *User) error

	// UpdatePassword updates a user's password
	UpdatePassword(ctx context.Context, userID ulid.ULID, hashedPassword string) error

	// Delete deletes a user
	Delete(ctx context.Context, id ulid.ULID) error

	// List lists all users with pagination
	List(ctx context.Context, limit, offset int) ([]*User, error)

	// AddRole adds a role to a user
	AddRole(ctx context.Context, userID ulid.ULID, role string) error

	// RemoveRole removes a role from a user
	RemoveRole(ctx context.Context, userID ulid.ULID, role string) error
}
