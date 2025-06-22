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
	"github.com/manorfm/auth-mock/internal/domain" // Required for domain.RequestKey
	"github.com/manorfm/auth-mock/internal/infrastructure/repository" // Added back
	"github.com/manorfm/auth-mock/internal/infrastructure/totp"       // Added back
	httprouter "github.com/manorfm/auth-mock/internal/interfaces/http"
	"github.com/manorfm/auth-mock/internal/interfaces/http/handlers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestOIDC_GetOpenIDConfiguration_E2E(t *testing.T) {
	logger := zap.NewNop()

	// Router's config for the E2E test.
	// The ServerURL here will be used by the oidcService instantiated within NewRouter,
	// if no context/headers override it.
	routerRealConfig := &config.Config{
		ServerURL:          "http://router-default-config.com:7000",
		JWTAccessDuration:  15 * time.Minute,
		JWTRefreshDuration: 24 * time.Hour,
		RSAKeySize:         2048,
		// Ensure other necessary fields for NewRouter are set if any.
	}

	// Setup router with the actual OIDC service and middleware.
	// NewRouter will create its own oidcService instance using routerRealConfig.
	// This is what we want for an E2E test.
	// but the oidcService inside it has defaultTestConfig.
	// The router's config ServerURL might differ or be "" if we want to test pure dynamic resolution.
	// routerConfig := &config.Config{
	// 	ServerURL: "http://router-config:8000", // This will be overridden by request if middleware works
	// 	// ... other necessary router config fields
	// }
	// Use routerRealConfig for the router instance for the E2E test.
	router := httprouter.NewRouter(routerRealConfig, logger) // NewRouter now includes RequestContextMiddleware

	// Create a test server
	ts := httptest.NewServer(router)
	defer ts.Close()

	tests := []struct {
		name              string
		headers           map[string]string
		expectedIssuer    string // Expected issuer URL based on how serverURL should be derived
		useTestServerHost bool   // If true, expectedIssuer will use ts.URL
	}{
		{
			name: "No X-Forwarded headers, derive from request Host",
			headers: map[string]string{},
			useTestServerHost: true, // Expect ts.URL as the base
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
				expectedIssuerURL = ts.URL // httptest.Server provides the scheme and host
			}

			assert.Equal(t, expectedIssuerURL, openIDConfig["issuer"])
			assert.Equal(t, expectedIssuerURL+"/oauth2/authorize", openIDConfig["authorization_endpoint"])
			assert.Equal(t, expectedIssuerURL+"/oauth2/token", openIDConfig["token_endpoint"])
			assert.Equal(t, expectedIssuerURL+"/oauth2/userinfo", openIDConfig["userinfo_endpoint"])
			assert.Equal(t, expectedIssuerURL+"/.well-known/jwks.json", openIDConfig["jwks_uri"])

			// Verify a few other fields to ensure the map is populated
			assert.Contains(t, openIDConfig, "response_types_supported")
			assert.Contains(t, openIDConfig, "subject_types_supported")
		})
	}

	// Test case: OIDC service has nil config (should use router's config as ultimate fallback if request context also fails)
	// This specific scenario is a bit tricky because the oidcService is instantiated with defaultTestConfig.
	// To truly test oidcService.config == nil, we'd need to instantiate OIDCService with nil config.
	// The current setup of getServerURL will use oidcService.config.ServerURL if context is empty.
	// Let's test the scenario where the context is empty (no RequestContextMiddleware or request is not in context)
	// For this, we'd ideally bypass the middleware or ensure request is not put in context.
	// However, since RequestContextMiddleware is global, we'll rely on the unit tests for s.config.ServerURL fallback.
	// The E2E test primarily verifies the middleware's effect and X-Forwarded headers.

	// An additional test: if oidcService itself was initialized with a nil config.
	// This is more of a unit-test concern for oidcService, but let's simulate the router providing nil.
	t.Run("OIDC Service configured with nil config - should error as per current OIDCService.GetOpenIDConfiguration guard", func(t *testing.T) {
		// Setup minimal dependencies for this specific sub-test
		userRepo := repository.NewUserRepository(logger) // from "github.com/manorfm/auth-mock/internal/infrastructure/repository"
		oauthRepo := repository.NewOAuth2Repository(logger)
		totpRepo := repository.NewTOTPRepository(logger)   // from "github.com/manorfm/auth-mock/internal/infrastructure/repository"

		totpGenerator := totp.NewGenerator(logger) // from "github.com/manorfm/auth-mock/internal/infrastructure/totp"
		localTotpService := application.NewTOTPService(totpRepo, totpGenerator, logger)

		minimalRouterCfg := &config.Config{RSAKeySize: 2048}
		strategyForNilTest, err := jwt.NewLocalStrategy(minimalRouterCfg, logger)
		require.NoError(t, err)
		jwtServiceForNilTest := jwt.NewJWTService(strategyForNilTest, minimalRouterCfg, logger)
		oauth2ServiceForNilTest := application.NewOAuth2Service(oauthRepo, logger)

		// Create a new OIDC service instance with a nil config
		nilConfigOIDCService := application.NewOIDCService(oauth2ServiceForNilTest, jwtServiceForNilTest, userRepo, localTotpService, nil, logger)

		// Temporarily replace the handler in a new test router or directly test the handler
		// For simplicity, we'll call the handler method directly with a context that would be prepared by the middleware
		// This isn't a full E2E for the router part, but tests the oidcService's direct behavior with nil config.

		// Need JWTService for handler, can reuse one or make a simple one for this test scope if needed
		// For this sub-test, we are primarily testing the OIDCService's behavior when its own config is nil.
		// The jwtService passed to the handler is mostly for other OIDC endpoints, but NewOIDCHandler requires it.
		// Let's create a minimal jwtService for this specific sub-test to avoid dependency on the broader test setup's jwtService.
		minimalTestCfg := &config.Config{RSAKeySize: 2048} // Minimal config for JWT strategy
		strategy, err := jwt.NewLocalStrategy(minimalTestCfg, logger)
		require.NoError(t, err)
		testJwtService := jwt.NewJWTService(strategy, minimalTestCfg, logger)

		handler := handlers.NewOIDCHandler(nilConfigOIDCService, testJwtService, logger)

		req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
		// If RequestContextMiddleware were active, it would add 'req' to ctx.
		// Let's simulate a context that has gone through the middleware.
		// The critical part is that nilConfigOIDCService has s.config == nil
		ctxWithReq := context.WithValue(context.Background(), domain.RequestKey, req)

		rr := httptest.NewRecorder()
		handler.GetOpenIDConfigurationHandler(rr, req.WithContext(ctxWithReq)) // Pass context with request

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
		// The error message would be "Internal server error" due to how errors are handled by a wrapper or directly.
		// We expect the oidcService.GetOpenIDConfiguration to return domain.ErrInternal, which the handler should translate.
		// The exact JSON error structure depends on the error handling middleware not shown here.
		// For now, checking the status code is sufficient for this specific sub-test.
		fmt.Println("Response for nil config OIDC service:", rr.Body.String()) // keep for debugging if needed
		// Example of how an error might be structured, though this depends on actual error handling middleware
		// var errResp map[string]string
		// if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err == nil {
		// 	assert.Equal(t, "Internal server error", errResp["error"])
		// }
	})
}
