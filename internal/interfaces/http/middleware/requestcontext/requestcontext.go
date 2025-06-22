package requestcontext

import (
	"context"
	"net/http"

	"github.com/manorfm/auth-mock/internal/domain"
)

// RequestContextMiddleware injects the *http.Request into the context using domain.RequestKey.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), domain.RequestKey, r)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
