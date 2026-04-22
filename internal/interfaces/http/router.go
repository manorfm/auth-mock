package router

import (
	"context"
	"net/http"
	"strings"
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
	"github.com/manorfm/auth-mock/internal/interfaces/http/middleware/requestcontext"
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
	strictRateLimiter := ratelimit.NewRateLimiter(20, 40, 3*time.Minute)

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

	authHandler := handlers.NewAuthHandler(authService, cfg, logger)
	userHandler := handlers.NewUserHandler(userService, logger)
	accountHandler := handlers.NewAccountHandler(accountService, userService, totpService, jwtService, logger)
	oidcHandler := handlers.NewOIDCHandler(oidcService, jwtService, logger)
	oauth2Handler := handlers.NewOAuth2Handler(oauthRepo, logger)
	totpHandler := handlers.NewTOTPHandler(totpService, logger)

	createDefaultUser(authService, cfg, logger)

	router := createRouter()

	router.Use(rateLimiter.Middleware)

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

	router.Get("/swagger/*", swagger.Handler(
		swagger.URL("/swagger/doc.json"),
		swagger.DocExpansion("list"),
		swagger.DomID("swagger-ui"),
		swagger.DeepLinking(true),
		swagger.PersistAuthorization(true),
	))

	router.Get("/swagger/doc.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")
		w.Header().Set("Content-Type", "application/json")
		http.ServeFile(w, r, "docs/swagger.json")
	})

	apiBase := cfg.EffectiveAPIBasePath()
	router.Route(apiBase, func(r chi.Router) {
		r.Get("/.well-known/openid-configuration", oidcHandler.GetOpenIDConfigurationHandler)
		r.Get("/.well-known/jwks.json", oidcHandler.GetJWKSHandler)
		r.Post("/oauth2/token", oidcHandler.TokenHandler)

		r.Group(func(r chi.Router) {
			r.Post("/register", authHandler.RegisterHandler)
			r.Post("/auth/register/client", authHandler.RegisterClientHandler)
			r.Post("/auth/verify-email", authHandler.VerifyEmailHandler)
			r.Post("/auth/request-password-reset", authHandler.RequestPasswordResetHandler)
			r.Post("/auth/reset-password", authHandler.ResetPasswordHandler)
		})

		r.Group(func(r chi.Router) {
			r.Use(strictRateLimiter.Middleware)
			r.Post("/auth/register/management", authHandler.RegisterManagementHandler)
			r.Post("/auth/login", authHandler.LoginHandler)
			r.Post("/auth/refresh", authHandler.RefreshTokenHandler)
			r.Post("/auth/verify-mfa", authHandler.VerifyMFAHandler)
			r.Post("/auth/resend-verification", authHandler.ResendVerificationHandler)
		})

		r.Group(func(r chi.Router) {
			r.Use(authMiddleware.Authenticator, authMiddleware.RequireAnyRole(domain.RoleAdmin, domain.RoleRoot), authMiddleware.RequireChannel(domain.ChannelManagementPanel), strictRateLimiter.Middleware)
			r.Get("/users", userHandler.ListUsersHandler)
			r.Get("/oauth2/clients", oauth2Handler.ListClientsHandler)
			r.Post("/oauth2/clients", oauth2Handler.CreateClientHandler)
			r.Get("/oauth2/clients/{id}", oauth2Handler.GetClientHandler)
			r.Put("/oauth2/clients/{id}", oauth2Handler.UpdateClientHandler)
			r.Delete("/oauth2/clients/{id}", oauth2Handler.DeleteClientHandler)
			r.Post("/admin/users/standalone", authHandler.CreateStandaloneUserHandler)
			r.Post("/admin/users/{id}/roles", authHandler.AddStandaloneRoleHandler)
			r.Delete("/admin/users/{id}/roles/{role}", authHandler.RemoveStandaloneRoleHandler)
			r.Get("/admin/users/{id}/roles", authHandler.ListStandaloneRolesHandler)
			r.Get("/admin/roles", authHandler.ListRolesHandler)
			r.Post("/admin/roles", authHandler.CreateRoleHandler)
			r.Put("/admin/roles/{name}", authHandler.UpdateRoleHandler)
			r.Delete("/admin/roles/{name}", authHandler.DeleteRoleHandler)
		})

		r.Group(func(r chi.Router) {
			r.Use(authMiddleware.Authenticator)
			r.With(authMiddleware.RequireChannel(domain.ChannelManagementPanel)).Get("/accounts", accountHandler.GetAccountsHandler)
			r.Get("/accounts/me", accountHandler.GetMeHandler)
			r.Put("/accounts", accountHandler.UpdateAccountHandler)
			r.Delete("/accounts", accountHandler.DeleteAccountHandler)
			r.Get("/users/me", userHandler.GetMeHandler)
			r.Get("/users/{id}", userHandler.GetUserHandler)
			r.Put("/users/{id}", userHandler.UpdateUserHandler)
			r.Get("/oauth2/authorize", oidcHandler.AuthorizeHandler)
			r.Get("/oauth2/userinfo", oidcHandler.GetUserInfoHandler)
			r.Post("/totp/enable", totpHandler.EnableTOTP)
			r.Post("/totp/verify", totpHandler.VerifyTOTP)
			r.Post("/totp/verify-backup", totpHandler.VerifyBackupCode)
			r.Post("/totp/disable", totpHandler.DisableTOTP)
		})
	})

	return &Router{router: router}
}

func createDefaultUser(authService domain.AuthService, cfg *config.Config, logger *zap.Logger) {
	if cfg.DefaultUserEmail == "" || cfg.DefaultUserPassword == "" {
		logger.Info("Default user not configured, skipping creation")
	} else {
		roles := make([]string, 0, len(cfg.DefaultUserRoles))
		for _, r := range cfg.DefaultUserRoles {
			r = strings.TrimSpace(strings.ToLower(r))
			if r != "" {
				roles = append(roles, r)
			}
		}
		if len(roles) == 0 {
			roles = []string{domain.RoleAdmin}
		}
		_, err := authService.Register(context.Background(), "Default Admin", cfg.DefaultUserEmail, cfg.DefaultUserPassword, "0000000000", roles)
		if err != nil {
			logger.Warn("Default user not created", zap.Error(err))
			return
		}
		logger.Info("Default user created", zap.String("email", cfg.DefaultUserEmail), zap.Strings("roles", roles))
	}
}

func createRouter() *chi.Mux {
	router := chi.NewRouter()
	router.Use(requestcontext.Middleware)
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
