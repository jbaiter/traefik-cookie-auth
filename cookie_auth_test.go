package traefik_cookie_auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestCreateConfig(t *testing.T) {
	config := CreateConfig()
	if config == nil {
		t.Fatal("Expected config to not be nil")
	}
	if config.CookieConf == nil {
		t.Fatal("Expected cookie config to not be nil")
	}
	if config.CookieConf.Name != "traefik_auth_token" {
		t.Errorf("Expected cookie name to be 'traefik_auth_token', got %s", config.CookieConf.Name)
	}
}

func TestParseUsers(t *testing.T) {
	tests := []struct {
		name    string
		users   string
		wantErr bool
	}{
		{
			name:    "Valid users",
			users:   "user1:pass1,user2:pass2",
			wantErr: false,
		},
		{
			name:    "Invalid format",
			users:   "invalid",
			wantErr: true,
		},
		{
			name:    "Empty string",
			users:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{Users: tt.users}
			users, err := config.ParseUsers()
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseUsers() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.users != "" {
				expectedUserCount := len(strings.Split(tt.users, ","))
				if len(users) != expectedUserCount {
					t.Errorf("Expected %d users, got %d", expectedUserCount, len(users))
				}
			}
		})
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "Valid config",
			config: &Config{
				Users:  "user1:pass1",
				Secret: "secret",
				CookieConf: &CookieConfig{
					Name: "test_cookie",
				},
			},
			wantErr: false,
		},
		{
			name: "Invalid users",
			config: &Config{
				Users:  "invalid",
				Secret: "secret",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

			middleware, err := New(ctx, handler, tt.config, "test")
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && middleware == nil {
				t.Error("Expected middleware to not be nil")
			}
		})
	}
}

func TestAuthMiddleware_ServeHTTP(t *testing.T) {
	config := &Config{
		Users:  "testuser:testpass",
		Secret: "testsecret",
		CookieConf: &CookieConfig{
			Name:     "test_auth_token",
			Path:     "/",
			TTL:      60,
			HttpOnly: true,
			Secure:   false,
			SameSite: http.SameSiteLaxMode,
		},
	}

	var called bool
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	middleware, err := New(context.Background(), nextHandler, config, "test")
	if err != nil {
		t.Fatalf("Failed to create middleware: %v", err)
	}

	tests := []struct {
		name           string
		method         string
		formData       map[string]string
		cookie         *http.Cookie
		expectedStatus int
		shouldCallNext bool
	}{
		{
			name:           "No cookie - GET request",
			method:         "GET",
			cookie:         nil,
			expectedStatus: http.StatusOK, // Shows login page
			shouldCallNext: false,
		},
		{
			name:   "Invalid credentials - POST request",
			method: "POST",
			formData: map[string]string{
				"username": "wrong",
				"password": "wrong",
			},
			expectedStatus: http.StatusUnauthorized,
			shouldCallNext: false,
		},
		{
			name:   "Valid credentials - POST request",
			method: "POST",
			formData: map[string]string{
				"username": "testuser",
				"password": "testpass",
			},
			expectedStatus: http.StatusFound, // Redirect after successful login
			shouldCallNext: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called = false
			var req *http.Request

			if tt.method == "POST" {
				form := url.Values{}
				for key, value := range tt.formData {
					form.Add(key, value)
				}
				req = httptest.NewRequest(tt.method, "http://example.com", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			} else {
				req = httptest.NewRequest(tt.method, "http://example.com", nil)
			}

			if tt.cookie != nil {
				req.AddCookie(tt.cookie)
			}

			w := httptest.NewRecorder()
			middleware.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status code %d, got %d", tt.expectedStatus, w.Code)
			}

			if called != tt.shouldCallNext {
				t.Errorf("Next handler called = %v, want %v", called, tt.shouldCallNext)
			}
		})
	}
}

func TestHashPassword(t *testing.T) {
	password := "testpassword"
	hash, err := hashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	if !comparePasswords(hash, password) {
		t.Error("Password comparison failed")
	}
}
