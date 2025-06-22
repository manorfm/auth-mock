package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/manorfm/auth-mock/internal/application"
	"github.com/manorfm/auth-mock/internal/infrastructure/config"
	"github.com/manorfm/auth-mock/internal/infrastructure/jwt"
	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/infrastructure/repository"
	"github.com/manorfm/auth-mock/internal/infrastructure/totp"
	httprouter "github.com/manorfm/auth-mock/internal/interfaces/http"
	"github.com/manorfm/auth-mock/internal/interfaces/http/handlers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestOIDC_GetOpenIDConfiguration_E2E(t *testing.T) {
	logger := zap.NewNop()
	// logger, _ := zap.NewDevelopment() // Temporary change for better logging
	// defer logger.Sync()

	routerRealConfig := &config.Config{
		ServerURL:          "http://router-default-config.com:7000",
		JWTAccessDuration:  15 * time.Minute,
		JWTRefreshDuration: 24 * time.Hour,
		RSAKeySize:         2048,
	}

	router := httprouter.NewRouter(routerRealConfig, logger)

	ts := httptest.NewServer(router)
	defer ts.Close()

	tests := []struct {
		name              string
		headers           map[string]string
		expectedIssuer    string
		useTestServerHost bool
	}{
		{
			name: "No X-Forwarded headers, derive from request Host",
			headers: map[string]string{},
			useTestServerHost: true,
		},
		{
			name: "With X-Forwarded-Proto and X-Forwarded-Host",
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "proxy.example.com",
			},
			expectedIssuer: "https://proxy.example.com",
		},
		{
			name: "With X-Forwarded-Proto and X-Forwarded-Host with port",
			headers: map[string]string{
				"X-Forwarded-Proto": "http",
				"X-Forwarded-Host":  "proxy.internal:8888",
			},
			expectedIssuer: "http://proxy.internal:8888",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", ts.URL+"/.well-known/openid-configuration", nil)
			require.NoError(t, err)

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			client := &http.Client{}
			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var openIDConfig map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&openIDConfig)
			require.NoError(t, err)

			expectedIssuerURL := tt.expectedIssuer
			if tt.useTestServerHost {
				expectedIssuerURL = ts.URL
			}

			assert.Equal(t, expectedIssuerURL, openIDConfig["issuer"])
			assert.Equal(t, expectedIssuerURL+"/oauth2/authorize", openIDConfig["authorization_endpoint"])
			assert.Equal(t, expectedIssuerURL+"/oauth2/token", openIDConfig["token_endpoint"])
			assert.Equal(t, expectedIssuerURL+"/oauth2/userinfo", openIDConfig["userinfo_endpoint"])
			assert.Equal(t, expectedIssuerURL+"/.well-known/jwks.json", openIDConfig["jwks_uri"])

			assert.Contains(t, openIDConfig, "response_types_supported")
			assert.Contains(t, openIDConfig, "subject_types_supported")
		})
	}

	t.Run("OIDC Service configured with nil config - should error as per current OIDCService.GetOpenIDConfiguration guard", func(t *testing.T) {
		userRepo := repository.NewUserRepository(logger)
		oauthRepo := repository.NewOAuth2Repository(logger)
		totpRepo := repository.NewTOTPRepository(logger)

		totpGenerator := totp.NewGenerator(logger)
		localTotpService := application.NewTOTPService(totpRepo, totpGenerator, logger)

		minimalRouterCfg := &config.Config{RSAKeySize: 2048}
		strategyForNilTest, err := jwt.NewLocalStrategy(minimalRouterCfg, logger)
		require.NoError(t, err)
		jwtServiceForNilTest := jwt.NewJWTService(strategyForNilTest, minimalRouterCfg, logger)
		oauth2ServiceForNilTest := application.NewOAuth2Service(oauthRepo, logger)

		nilConfigOIDCService := application.NewOIDCService(oauth2ServiceForNilTest, jwtServiceForNilTest, userRepo, localTotpService, nil, logger)

		minimalTestCfg := &config.Config{RSAKeySize: 2048}
		strategy, err := jwt.NewLocalStrategy(minimalTestCfg, logger)
		require.NoError(t, err)
		testJwtService := jwt.NewJWTService(strategy, minimalTestCfg, logger)

		handler := handlers.NewOIDCHandler(nilConfigOIDCService, testJwtService, logger)

		req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
		ctxWithReq := context.WithValue(context.Background(), domain.RequestKey, req)

		rr := httptest.NewRecorder()
		handler.GetOpenIDConfigurationHandler(rr, req.WithContext(ctxWithReq))

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
		fmt.Println("Response for nil config OIDC service:", rr.Body.String())
	})
}
