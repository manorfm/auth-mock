package handlers

import (
	"net/http"

	"github.com/manorfm/auth-mock/internal/infrastructure/config"
)

const refreshTokenCookieName = "refresh_token"

func setRefreshTokenCookie(w http.ResponseWriter, cfg *config.Config, refreshToken string) {
	maxAge := 0
	if cfg != nil {
		maxAge = int(cfg.JWTRefreshDuration.Seconds())
	}
	if maxAge < 0 {
		maxAge = 0
	}
	path := "/"
	if cfg != nil {
		path = cfg.EffectiveAPIBasePath()
		if path == "" {
			path = "/"
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenCookieName,
		Value:    refreshToken,
		Path:     path,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   cfg != nil && cfg.RefreshCookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearRefreshTokenCookie(w http.ResponseWriter, cfg *config.Config) {
	path := "/"
	if cfg != nil {
		path = cfg.EffectiveAPIBasePath()
		if path == "" {
			path = "/"
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenCookieName,
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   cfg != nil && cfg.RefreshCookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}
