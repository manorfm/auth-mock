package domain

import "context"

// ContextKey is a type for context keys to avoid magic strings
type ContextKey string

const (
	// ContextKeySubject is the key for the subject (user ID) in the context
	ContextKeySubject ContextKey = "sub"
	// ContextKeyCodeChallenge is the key for the PKCE code challenge in the context
	ContextKeyCodeChallenge ContextKey = "code_challenge"
	// ContextKeyCodeChallengeMethod is the key for the PKCE code challenge method in the context
	ContextKeyCodeChallengeMethod ContextKey = "code_challenge_method"
)

// WithSubject adds the subject (user ID) to the context
func WithSubject(ctx context.Context, subject string) context.Context {
	return context.WithValue(ctx, ContextKeySubject, subject)
}

// WithCodeChallenge adds the PKCE code challenge to the context
func WithCodeChallenge(ctx context.Context, challenge string) context.Context {
	return context.WithValue(ctx, ContextKeyCodeChallenge, challenge)
}

// WithCodeChallengeMethod adds the PKCE code challenge method to the context
func WithCodeChallengeMethod(ctx context.Context, method string) context.Context {
	return context.WithValue(ctx, ContextKeyCodeChallengeMethod, method)
}

// GetSubject retrieves the subject (user ID) from the context
func GetSubject(ctx context.Context) (string, bool) {
	subject, ok := ctx.Value(ContextKeySubject).(string)
	return subject, ok
}

// GetCodeChallenge retrieves the PKCE code challenge from the context
func GetCodeChallenge(ctx context.Context) (string, bool) {
	challenge, ok := ctx.Value(ContextKeyCodeChallenge).(string)
	return challenge, ok
}

// GetCodeChallengeMethod retrieves the PKCE code challenge method from the context
func GetCodeChallengeMethod(ctx context.Context) (string, bool) {
	method, ok := ctx.Value(ContextKeyCodeChallengeMethod).(string)
	return method, ok
}
