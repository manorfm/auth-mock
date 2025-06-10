package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/manorfm/auth-mock/internal/infrastructure/config"
	httprouter "github.com/manorfm/auth-mock/internal/interfaces/http"
	"go.uber.org/zap"
)

// @title User Manager Service API
// @version 1.0
// @description This is a user management service with JWT authentication
// @host localhost:8080
// @BasePath /api/v1
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	cfg, err := config.LoadConfig(logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	router := httprouter.NewRouter(cfg, logger)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.ServerPort),
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		logger.Info("Server is starting", zap.Int("port", cfg.ServerPort))
		if err := srv.ListenAndServe(); err != nil {
			if err == http.ErrServerClosed {
				logger.Info("Server closed gracefully")
			} else {
				logger.Fatal("Server failed to start", zap.Error(err))
			}
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal("Forced server shutdown", zap.Error(err))
	}

	logger.Info("Server exited cleanly")
}
