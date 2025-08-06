package router

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/manorfm/auth-mock/internal/application"
	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/infrastructure/config"
	"github.com/manorfm/auth-mock/internal/infrastructure/email"
	"github.com/manorfm/auth-mock/internal/infrastructure/jwt"
	"github.com/manorfm/auth-mock/internal/infrastructure/repository"
	"github.com/manorfm/auth-mock/internal/infrastructure/totp"
	"github.com/manorfm/auth-mock/internal/interfaces/http/handlers"
	"github.com/manorfm/auth-mock/internal/interfaces/http/middleware/auth"
	"github.com/manorfm/auth-mock/internal/interfaces/http/middleware/ratelimit"
	"github.com/manorfm/auth-mock/internal/interfaces/http/middleware/requestcontext" // Added import
	httptotp "github.com/manorfm/auth-mock/internal/interfaces/http/middleware/totp"
	"github.com/oklog/ulid/v2"
	swagger "github.com/swaggo/http-swagger"
	"go.uber.org/zap"
)

type Router struct {
	router *chi.Mux
}

func NewRouter(
	cfg *config.Config,
	logger *zap.Logger,
) *Router {
	strategy, err := jwt.NewLocalStrategy(cfg, logger)
	if err != nil {
		logger.Error("Failed to create JWT strategy", zap.Error(err))
		panic(err)
	}
	jwtService := jwt.NewJWTService(strategy, cfg, logger)
	authMiddleware := auth.NewAuthMiddleware(jwtService, logger)
	rateLimiter := ratelimit.NewRateLimiter(100, 200, 3*time.Minute)

	userRepo := repository.NewUserRepository(logger)
	oauthRepo := repository.NewOAuth2Repository(logger)
	verificationRepo := repository.NewVerificationCodeRepository(logger)
	totpRepo := repository.NewTOTPRepository(logger)
	mfaTicketRepo := repository.NewMFATicketRepository(logger)
	accountRepo := repository.NewAccountRepository()

	totpGenerator := totp.NewGenerator(logger)
	emailTemplate := email.NewEmailTemplate(&cfg.SMTP, logger)

	totpService := application.NewTOTPService(totpRepo, totpGenerator, logger)
	userService := application.NewUserService(userRepo, logger)
	oauth2Service := application.NewOAuth2Service(oauthRepo, logger)
	accountService := application.NewAccountService(accountRepo, logger)
	authService := application.NewAuthService(cfg, userRepo, accountService, verificationRepo, jwtService, emailTemplate, totpService, mfaTicketRepo, logger)
	oidcService := application.NewOIDCService(oauth2Service, jwtService, userRepo, totpService, cfg, logger)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authService, logger)
	userHandler := handlers.NewUserHandler(userService, logger)
	accountHandler := handlers.NewAccountHandler(accountService, userService, totpService, logger)
	oidcHandler := handlers.NewOIDCHandler(oidcService, jwtService, logger)
	oauth2Handler := handlers.NewOAuth2Handler(oauthRepo, logger)
	totpHandler := handlers.NewTOTPHandler(totpService, logger)

	createDefaultUser(authService, cfg, logger)

	// Create router with middleware
	router := createRouter() // RequestContextMiddleware is now applied inside createRouter

	// Apply other global middlewares
	router.Use(rateLimiter.Middleware)

	// Initialize TOTP middleware
	totpMiddleware := httptotp.NewMiddleware(totpService, logger)

	// Health check endpoints
	router.Group(func(r chi.Router) {
		r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		})

		r.Get("/health/ready", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Ready"))
		})

		r.Get("/health/live", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Alive"))
		})
	})

	// Swagger UI configuration
	router.Get("/swagger/*", swagger.Handler(
		swagger.URL("/swagger/doc.json"),
		swagger.DocExpansion("list"),
		swagger.DomID("swagger-ui"),
		swagger.DeepLinking(true),
		swagger.PersistAuthorization(true),
	))

	// Serve Swagger JSON with CORS headers
	router.Get("/swagger/doc.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")
		w.Header().Set("Content-Type", "application/json")
		http.ServeFile(w, r, "docs/swagger.json")
	})

	// OIDC routes
	router.Group(func(r chi.Router) {
		r.Get("/.well-known/openid-configuration", oidcHandler.GetOpenIDConfigurationHandler)
		r.Get("/.well-known/jwks.json", oidcHandler.GetJWKSHandler)
	})

	// API routes without version in URL
	router.Route("/api", func(r chi.Router) {
		// Public routes
		r.Group(func(r chi.Router) {
			r.Post("/register", authHandler.RegisterHandler)
			r.Post("/auth/login", authHandler.LoginHandler)
			r.Post("/auth/verify-mfa", authHandler.VerifyMFAHandler)
			r.Post("/auth/verify-email", authHandler.VerifyEmailHandler)
			r.Post("/auth/request-password-reset", authHandler.RequestPasswordResetHandler)
			r.Post("/auth/reset-password", authHandler.ResetPasswordHandler)
		})

		// Admin routes
		r.Group(func(r chi.Router) {
			r.Use(authMiddleware.Authenticator, authMiddleware.RequireRole("admin"))
			r.Get("/users", userHandler.ListUsersHandler)
			r.Get("/oauth2/clients", oauth2Handler.ListClientsHandler)
		})

		// Protected routes
		r.Group(func(r chi.Router) {
			r.Use(authMiddleware.Authenticator)
			//r.Use(totpMiddleware.Verifier)

			// TOTP verification endpoint
			r.Post("/totp/verify", totpMiddleware.VerificationHandler)

			r.Get("/users/{id}", userHandler.GetUserHandler)
			r.Put("/users/{id}", userHandler.UpdateUserHandler)
			r.Get("/oauth2/authorize", oidcHandler.AuthorizeHandler)
			r.Post("/oauth2/token", oidcHandler.TokenHandler)
			r.Get("/oauth2/userinfo", oidcHandler.GetUserInfoHandler)

			// OAuth2 client management routes
			r.Post("/oauth2/clients", oauth2Handler.CreateClientHandler)
			r.Get("/oauth2/clients/{id}", oauth2Handler.GetClientHandler)
			r.Put("/oauth2/clients/{id}", oauth2Handler.UpdateClientHandler)
			r.Delete("/oauth2/clients/{id}", oauth2Handler.DeleteClientHandler)

			// TOTP routes
			r.Post("/totp/enable", totpHandler.EnableTOTP)
			r.Post("/totp/verify", totpHandler.VerifyTOTP)
			r.Post("/totp/verify-backup", totpHandler.VerifyBackupCode)
			r.Post("/totp/disable", totpHandler.DisableTOTP)

			// Account routes
			r.Get("/accounts", accountHandler.GetAccountsHandler)
			r.Get("/accounts/me", accountHandler.GetMeHandler)
			r.Put("/accounts", accountHandler.UpdateAccountHandler)
			r.Delete("/accounts", accountHandler.DeleteAccountHandler)
		})
	})

	return &Router{router: router}
}

func createDefaultUser(authService domain.AuthService, cfg *config.Config, logger *zap.Logger) {
	if cfg.DefaultUserEmail == "" || cfg.DefaultUserPassword == "" {
		logger.Info("Default user not configured, skipping creation")
	} else {
		user := &domain.User{
			ID:            ulid.Make(),
			Email:         cfg.DefaultUserEmail,
			Password:      cfg.DefaultUserPassword,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
			EmailVerified: true,
			Roles:         cfg.DefaultUserRoles,
		}
		authService.Register(nil, user.Name, user.Email, user.Password, user.Phone, user.Roles)
		logger.Info("Default user created", zap.String("email", cfg.DefaultUserEmail), zap.Strings("roles", cfg.DefaultUserRoles))
	}
}

func createRouter() *chi.Mux {
	router := chi.NewRouter()

	// Apply RequestContextMiddleware first to ensure request is in context
	router.Use(requestcontext.Middleware)

	// Add other standard chi middleware
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Timeout(60 * time.Second))

	return router
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.router.ServeHTTP(w, req)
}
