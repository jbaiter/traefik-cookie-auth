package traefik_cookie_auth

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
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
	if len(config.Users) != 0 {
		t.Errorf("Expected Users map to be empty, got size %d", len(config.Users))
	}
	if config.LoginTemplateFile != "" {
		t.Errorf("Expected LoginTemplateFile to be empty, got %s", config.LoginTemplateFile)
	}
	if config.LoginTemplateInline != "" {
		t.Errorf("Expected LoginTemplateInline to be empty, got %s", config.LoginTemplateInline)
	}
}

func TestNew(t *testing.T) {
	ctx := context.Background()
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	// Valid template file setup
	tmpFile, err := os.CreateTemp("", "template-*.html")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	_, err = tmpFile.WriteString("Hello From File {{.TestVar}}")
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	tests := []struct {
		name        string
		config      *Config
		wantErr     bool
		expectedErr string
	}{
		{
			name: "Valid config with default template",
			config: &Config{
				Users:  map[string]string{"user1": "hash1"},
				Secret: "test-secret",
				CookieConf: &CookieConfig{
					Name: "test_cookie", Path: "/", TTL: 60, HttpOnly: true,
				},
			},
			wantErr: false,
		},
		{
			name: "Empty secret",
			config: &Config{
				Users: map[string]string{"user1": "hash1"},
				CookieConf: &CookieConfig{
					Name: "test_cookie", Path: "/", TTL: 60, HttpOnly: true,
				},
			},
			wantErr:     true,
			expectedErr: "secret cannot be empty",
		},
		{
			name: "Valid config with template file",
			config: &Config{
				Users:             map[string]string{"user1": "hash1"},
				Secret:            "test-secret",
				CookieConf:        &CookieConfig{Name: "test_cookie"},
				LoginTemplateFile: tmpFile.Name(),
			},
			wantErr: false,
		},
		{
			name: "Invalid template file path",
			config: &Config{
				Users:             map[string]string{"user1": "hash1"},
				Secret:            "test-secret",
				CookieConf:        &CookieConfig{Name: "test_cookie"},
				LoginTemplateFile: "nonexistent.html",
			},
			wantErr:     true,
			expectedErr: "failed to read login template file nonexistent.html",
		},
		{
			name: "Valid config with inline template",
			config: &Config{
				Users:               map[string]string{"user1": "hash1"},
				Secret:              "test-secret",
				CookieConf:          &CookieConfig{Name: "test_cookie"},
				LoginTemplateInline: "Hello Inline",
			},
			wantErr: false,
		},
		{
			name: "Invalid inline template syntax",
			config: &Config{
				Users:               map[string]string{"user1": "hash1"},
				Secret:              "test-secret",
				CookieConf:          &CookieConfig{Name: "test_cookie"},
				LoginTemplateInline: "Hello {{ .Unclosed",
			},
			wantErr:     true,
			expectedErr: "failed to parse login template",
		},
		{
			name: "Config with empty users (should not error on New, but might be problematic for auth)",
			config: &Config{
				Users:  map[string]string{},
				Secret: "test-secret",
				CookieConf: &CookieConfig{
					Name: "test_cookie", Path: "/", TTL: 60, HttpOnly: true,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Ensure CookieConf is not nil for tests that don't explicitly set it fully
			if tt.config.CookieConf == nil {
				tt.config.CookieConf = CreateConfig().CookieConf
			}

			middleware, err := New(ctx, nextHandler, tt.config, "test-middleware")
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if err != nil && tt.expectedErr != "" && !strings.Contains(err.Error(), tt.expectedErr) {
					t.Errorf("New() error = %q, want error containing %q", err.Error(), tt.expectedErr)
				}
				return
			}
			if middleware == nil {
				t.Error("Expected middleware to not be nil")
			}
			// Check if users map is correctly passed
			authMw, ok := middleware.(*AuthMiddleware)
			if !ok {
				t.Fatal("Middleware is not of type *AuthMiddleware")
			}
			if len(authMw.users) != len(tt.config.Users) {
				t.Errorf("Expected %d users, got %d", len(tt.config.Users), len(authMw.users))
			}
			for k, v := range tt.config.Users {
				if authMw.users[k] != v {
					t.Errorf("Expected user %s with hash %s, got %s", k, v, authMw.users[k])
				}
			}
		})
	}
}

func TestAuthMiddleware_ServeHTTP(t *testing.T) {
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("testpass"), bcrypt.DefaultCost)
	baseConfig := &Config{
		Users:  map[string]string{"testuser": string(hashedPassword)},
		Secret: "test-secret",
		CookieConf: &CookieConfig{
			Name:     "test_cookie",
			Path:     "/",
			Domain:   "",
			TTL:      1, // 1 minute for testing
			HttpOnly: true,
			Secure:   false,
			SameSite: http.SameSiteLaxMode,
		},
	}

	// Create a temporary custom template file
	customTmplFile, err := os.CreateTemp("", "custom-login-*.html")
	if err != nil {
		t.Fatalf("Failed to create temp template file: %v", err)
	}
	defer os.Remove(customTmplFile.Name())
	_, err = customTmplFile.WriteString("Custom Login Page Content. {{if .ErrorMessage}}Error: {{.ErrorMessage}}{{end}}")
	if err != nil {
		t.Fatalf("Failed to write to temp template file: %v", err)
	}
	customTmplFile.Close()

	configWithFileTmpl := *baseConfig // shallow copy
	configWithFileTmpl.LoginTemplateFile = customTmplFile.Name()

	configWithInlineTmpl := *baseConfig // shallow copy
	configWithInlineTmpl.LoginTemplateInline = "Inline Login Page. {{if .ErrorMessage}}Error: {{.ErrorMessage}}{{end}}"

	tests := []struct {
		name                 string
		config               *Config
		method               string
		path                 string
		username             string
		password             string
		existingCookie       *http.Cookie
		expectedStatus       int
		expectedBodyContains string
		expectRedirect       bool
		expectSetCookie      bool
	}{
		{
			name:                 "GET request without cookie shows default login page",
			config:               baseConfig,
			method:               "GET",
			path:                 "/login",
			expectedStatus:       http.StatusOK,
			expectedBodyContains: "<title>Login</title>",
		},
		{
			name:                 "GET request without cookie shows custom file login page",
			config:               &configWithFileTmpl,
			method:               "GET",
			path:                 "/login",
			expectedStatus:       http.StatusOK,
			expectedBodyContains: "Custom Login Page Content.",
		},
		{
			name:                 "GET request without cookie shows custom inline login page",
			config:               &configWithInlineTmpl,
			method:               "GET",
			path:                 "/login",
			expectedStatus:       http.StatusOK,
			expectedBodyContains: "Inline Login Page.",
		},
		{
			name:                 "POST request with invalid credentials",
			config:               baseConfig,
			method:               "POST",
			path:                 "/login",
			username:             "invaliduser",
			password:             "invalidpass",
			expectedStatus:       http.StatusUnauthorized,
			expectedBodyContains: "Invalid username or password",
		},
		{
			name:            "POST request with valid credentials sets cookie and redirects",
			config:          baseConfig,
			method:          "POST",
			path:            "/login",
			username:        "testuser",
			password:        "testpass",
			expectedStatus:  http.StatusFound,
			expectRedirect:  true,
			expectSetCookie: true,
		},
		{
			name:           "GET request with valid cookie passes through",
			config:         baseConfig,
			method:         "GET",
			path:           "/protected",
			existingCookie: generateValidCookie(t, "testuser", "test-secret", baseConfig.CookieConf),
			expectedStatus: http.StatusOK, // Assuming next handler returns OK
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Check if username header is set
				if r.Header.Get("Username") == "" && tt.existingCookie != nil {
					// This check is only relevant if a cookie was provided, implying successful auth
					// t.Errorf("Username header not set by middleware for authenticated request")
				}
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "OK from next handler")
			})

			middleware, err := New(ctx, nextHandler, tt.config, "test")
			if err != nil {
				t.Fatalf("Failed to create middleware: %v", err)
			}

			var req *http.Request
			if tt.method == "POST" {
				form := url.Values{}
				form.Add("username", tt.username)
				form.Add("password", tt.password)
				req = httptest.NewRequest(tt.method, "http://example.com"+tt.path, strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			} else {
				req = httptest.NewRequest(tt.method, "http://example.com"+tt.path, nil)
			}

			if tt.existingCookie != nil {
				req.AddCookie(tt.existingCookie)
			}

			rr := httptest.NewRecorder()
			middleware.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, tt.expectedStatus)
			}

			if tt.expectedBodyContains != "" {
				if !strings.Contains(rr.Body.String(), tt.expectedBodyContains) {
					t.Errorf("handler returned unexpected body: got %q want to contain %q", rr.Body.String(), tt.expectedBodyContains)
				}
			}
			if tt.expectRedirect {
				location := rr.Header().Get("Location")
				if location != tt.path { // Should redirect to the same path it was POSTed to
					t.Errorf("Expected redirect to %s, got %s", tt.path, location)
				}
			}
			if tt.expectSetCookie {
				cookies := rr.Result().Cookies()
				foundCookie := false
				for _, c := range cookies {
					if c.Name == tt.config.CookieConf.Name {
						foundCookie = true
						break
					}
				}
				if !foundCookie {
					t.Errorf("Expected cookie %s to be set", tt.config.CookieConf.Name)
				}
			}
		})
	}
}

// Helper to generate a valid JWT cookie for testing
func generateValidCookie(t *testing.T, username, secret string, cookieConf *CookieConfig) *http.Cookie {
	t.Helper()
	expirationTime := time.Now().Add(time.Duration(cookieConf.TTL) * time.Minute)
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}
	return &http.Cookie{
		Name:  cookieConf.Name,
		Value: tokenString,
		Path:  cookieConf.Path,
	}
}

func TestComparePasswords(t *testing.T) { // Renamed from TestHashPassword to be more accurate
	password := "testpass"
	hashedPwd, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	tests := []struct {
		name        string
		hashedPwd   string
		plainPwd    string
		expectMatch bool
	}{
		{
			name:        "Valid match",
			hashedPwd:   string(hashedPwd),
			plainPwd:    password,
			expectMatch: true,
		},
		{
			name:        "Invalid match",
			hashedPwd:   string(hashedPwd),
			plainPwd:    "wrongpassword",
			expectMatch: false,
		},
		{
			name: "Empty password with valid hash (bcrypt specific)",
			// This case depends on whether empty passwords were used to generate the hash.
			// For this test, we assume bcrypt can hash an empty string.
			hashedPwd:   func() string { h, _ := bcrypt.GenerateFromPassword([]byte(""), bcrypt.DefaultCost); return string(h) }(),
			plainPwd:    "",
			expectMatch: true,
		},
		{
			name:        "Mismatched empty password",
			hashedPwd:   string(hashedPwd), // hash of "testpass"
			plainPwd:    "",
			expectMatch: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := comparePasswords(tt.hashedPwd, tt.plainPwd)
			if match != tt.expectMatch {
				t.Errorf("comparePasswords() with plainPwd %q expected %v, got %v", tt.plainPwd, tt.expectMatch, match)
			}
		})
	}
}
