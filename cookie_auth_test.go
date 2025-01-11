package traefik_cookie_auth

import (
	"context"
	"golang.org/x/crypto/bcrypt"
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
		name          string
		users         string
		wantErr       bool
		expectedUsers map[string]string
	}{
		{
			name:    "Valid users",
			users:   "user1:pass1,user2:pass2",
			wantErr: false,
			expectedUsers: map[string]string{
				"user1": "pass1",
				"user2": "pass2",
			},
		},
		{
			name:          "Invalid format",
			users:         "invalid",
			wantErr:       false,
			expectedUsers: map[string]string{},
		},
		{
			name:          "Empty string",
			users:         "",
			wantErr:       false,
			expectedUsers: map[string]string{},
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
			if len(users) != len(tt.expectedUsers) {
				t.Errorf("Expected %d users, got %d", len(tt.expectedUsers), len(users))
				return
			}
			for k, v := range tt.expectedUsers {
				if users[k] != v {
					t.Errorf("Expected user %s to have password %s, got %s", k, v, users[k])
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
				Secret: "test-secret",
				CookieConf: &CookieConfig{
					Name:     "test_cookie",
					Path:     "/",
					Domain:   "",
					TTL:      60,
					HttpOnly: true,
					Secure:   false,
					SameSite: http.SameSiteLaxMode,
				},
			},
			wantErr: false,
		},
		{
			name: "Empty config",
			config: &Config{
				Users:  "",
				Secret: "test-secret",
			},
			wantErr: false,
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
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("testpass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	config := &Config{
		Users:  "testuser:" + string(hashedPassword),
		Secret: "test-secret",
		CookieConf: &CookieConfig{
			Name:     "test_cookie",
			Path:     "/",
			Domain:   "",
			TTL:      60,
			HttpOnly: true,
			Secure:   false,
			SameSite: http.SameSiteLaxMode,
		},
	}

	tests := []struct {
		name           string
		method         string
		username       string
		password       string
		withCookie     bool
		expectedStatus int
	}{
		{
			name:           "GET request without cookie shows login page",
			method:         "GET",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "POST request with invalid credentials",
			method:         "POST",
			username:       "invalid",
			password:       "invalid",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "POST request with valid credentials",
			method:         "POST",
			username:       "testuser",
			password:       "testpass",
			expectedStatus: http.StatusFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			middleware, err := New(ctx, nextHandler, config, "test")
			if err != nil {
				t.Fatalf("Failed to create middleware: %v", err)
			}

			var req *http.Request
			if tt.method == "POST" {
				form := url.Values{}
				form.Add("username", tt.username)
				form.Add("password", tt.password)
				req = httptest.NewRequest("POST", "http://example.com", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			} else {
				req = httptest.NewRequest("GET", "http://example.com", nil)
			}

			rr := httptest.NewRecorder()
			middleware.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, tt.expectedStatus)
			}
		})
	}
}

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "Valid password",
			password: "testpass",
			wantErr:  false,
		},
		{
			name:     "Empty password",
			password: "",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hashedPwd, err := bcrypt.GenerateFromPassword([]byte(tt.password), bcrypt.DefaultCost)
			if err != nil {
				t.Fatalf("Failed to hash password: %v", err)
			}
			if !comparePasswords(string(hashedPwd), tt.password) != tt.wantErr {
				t.Errorf("Password comparison failed for %s", tt.name)
			}
		})
	}
}
