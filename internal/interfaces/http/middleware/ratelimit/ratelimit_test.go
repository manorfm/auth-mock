package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestNewRateLimiter(t *testing.T) {
	// Test cases
	tests := []struct {
		name     string
		rate     rate.Limit
		burst    int
		ttl      time.Duration
		expected *RateLimiter
	}{
		{
			name:  "Standard configuration",
			rate:  100,
			burst: 200,
			ttl:   3 * time.Minute,
			expected: &RateLimiter{
				visitors: make(map[string]*clientLimiter),
				rate:     100,
				burst:    200,
				ttl:      3 * time.Minute,
			},
		},
		{
			name:  "Strict configuration",
			rate:  1,
			burst: 1,
			ttl:   1 * time.Minute,
			expected: &RateLimiter{
				visitors: make(map[string]*clientLimiter),
				rate:     1,
				burst:    1,
				ttl:      1 * time.Minute,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rl := NewRateLimiter(tt.rate, tt.burst, tt.ttl)
			if rl.rate != tt.expected.rate {
				t.Errorf("expected rate %v, got %v", tt.expected.rate, rl.rate)
			}
			if rl.burst != tt.expected.burst {
				t.Errorf("expected burst %v, got %v", tt.expected.burst, rl.burst)
			}
			if rl.ttl != tt.expected.ttl {
				t.Errorf("expected ttl %v, got %v", tt.expected.ttl, rl.ttl)
			}
			if rl.visitors == nil {
				t.Error("expected visitors map to be initialized")
			}
		})
	}
}

func TestGetVisitor(t *testing.T) {
	rl := NewRateLimiter(100, 200, 3*time.Minute)
	ip := "192.168.1.1"

	// Test getting a new visitor
	limiter1 := rl.getVisitor(ip)
	if limiter1 == nil {
		t.Error("expected limiter to be created for new visitor")
	}

	// Test getting the same visitor again
	limiter2 := rl.getVisitor(ip)
	if limiter1 != limiter2 {
		t.Error("expected same limiter for same IP")
	}

	// Test getting a different visitor
	ip2 := "192.168.1.2"
	limiter3 := rl.getVisitor(ip2)
	if limiter3 == limiter1 {
		t.Error("expected different limiter for different IP")
	}
}

func TestRateLimiterMiddleware(t *testing.T) {
	// Create a rate limiter with strict limits for testing
	rl := NewRateLimiter(1, 1, 1*time.Minute)

	// Create a test handler that always returns 200 OK
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Create a test request
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	// Test cases
	tests := []struct {
		name           string
		requests       int
		expectedStatus int
	}{
		{
			name:           "First request should succeed",
			requests:       1,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Second request should be rate limited",
			requests:       2,
			expectedStatus: http.StatusTooManyRequests,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := 0; i < tt.requests; i++ {
				w := httptest.NewRecorder()
				rl.Middleware(handler).ServeHTTP(w, req)

				if i == tt.requests-1 {
					if w.Code != tt.expectedStatus {
						t.Errorf("expected status %v, got %v", tt.expectedStatus, w.Code)
					}
				}
			}
		})
	}
}

func TestRateLimiterMiddlewareInvalidIP(t *testing.T) {
	rl := NewRateLimiter(1, 1, 1*time.Minute)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Test with invalid IP address
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "invalid-ip"

	w := httptest.NewRecorder()
	rl.Middleware(handler).ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %v, got %v", http.StatusInternalServerError, w.Code)
	}
}

func TestCleanupVisitors(t *testing.T) {
	// Create a rate limiter with a short cleanup interval for testing
	cleanupInterval := 100 * time.Millisecond
	ttl := 200 * time.Millisecond

	// Create a custom rate limiter with a shorter cleanup interval
	rl := &RateLimiter{
		visitors: make(map[string]*clientLimiter),
		rate:     1,
		burst:    1,
		ttl:      ttl,
	}

	// Start cleanup goroutine with shorter interval
	go func() {
		for {
			time.Sleep(cleanupInterval)
			rl.mu.Lock()
			now := time.Now()
			for ip, v := range rl.visitors {
				if now.Sub(v.lastSeen) > rl.ttl {
					delete(rl.visitors, ip)
				}
			}
			rl.mu.Unlock()
		}
	}()

	// Add a visitor
	ip := "192.168.1.1"
	rl.getVisitor(ip)

	// Verify visitor was added
	rl.mu.Lock()
	_, exists := rl.visitors[ip]
	rl.mu.Unlock()
	if !exists {
		t.Fatal("visitor should exist after adding")
	}

	// Wait for cleanup
	time.Sleep(ttl + cleanupInterval)

	// Verify visitor was cleaned up
	rl.mu.Lock()
	_, exists = rl.visitors[ip]
	rl.mu.Unlock()
	if exists {
		t.Error("expected visitor to be cleaned up")
	}
}

func TestConcurrentAccess(t *testing.T) {
	rl := NewRateLimiter(100, 200, 1*time.Minute)
	done := make(chan bool)

	// Simulate concurrent access
	for i := 0; i < 10; i++ {
		go func() {
			ip := "192.168.1.1"
			rl.getVisitor(ip)
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify that we still have only one visitor
	rl.mu.Lock()
	count := len(rl.visitors)
	rl.mu.Unlock()

	if count != 1 {
		t.Errorf("expected 1 visitor, got %d", count)
	}
}
