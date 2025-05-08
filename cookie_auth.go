package traefik_cookie_auth

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"net/http"
	"os"
	"time"
)

const defaultLoginTemplate = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC" crossorigin="anonymous"></head><body><div class="container d-flex align-items-center justify-content-center vh-100"><div class="row w-100"><div class="col-md-6 mx-auto"><div class="card"><div class="card-body"><h2 class="text-center mb-4">Login</h2>{{if .ErrorMessage}}<div class="alert alert-danger" role="alert">{{.ErrorMessage}}</div>{{end}}<form method="POST"><div class="mb-3"><label for="username" class="form-label">Username</label><input type="text" class="form-control" id="username" name="username" placeholder="Enter your username" required></div><div class="mb-3"><label for="password" class="form-label">Password</label><input type="password" class="form-control" id="password" name="password" placeholder="Enter your password" required></div><button type="submit" class="btn btn-primary w-100">Login</button></form></div></div></div></div></div></body></html>`

type Config struct {
	Users               map[string]string `json:"users"`
	Secret              string            `json:"secret"`
	CookieConf          *CookieConfig     `json:"cookieConf"`
	LoginTemplate       string            `json:"loginTemplate,omitempty"`
	LoginTemplatePath   string            `json:"loginTemplatePath,omitempty"`
}

type CookieConfig struct {
	Name     string        `json:"name"`
	Path     string        `json:"path"`
	Domain   string        `json:"domain"`
	TTL      int           `json:"ttl"` // TTL in minutes
	HttpOnly bool          `json:"httpOnly"`
	Secure   bool          `json:"secure"`
	SameSite http.SameSite `json:"sameSite"`
}

func CreateConfig() *Config {
	return &Config{
		Users: make(map[string]string),
		CookieConf: &CookieConfig{
			Name:     "traefik_auth_token",
			Path:     "/",
			Domain:   "",
			TTL:      60,
			HttpOnly: true,
			Secure:   false,
			SameSite: http.SameSiteLaxMode,
		},
		LoginTemplatePath:   "",
		LoginTemplate: "",
	}
}

type AuthMiddleware struct {
	next       http.Handler
	secret     string
	cookieConf *CookieConfig
	users      map[string]string
	name       string
	loginTmpl  *template.Template
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.Secret == "" {
		return nil, fmt.Errorf("secret cannot be empty")
	}
	if len(config.Users) == 0 {
		// Consider if this should be an error or just a warning.
		// For now, allow it but auth will effectively be disabled for new logins.
	}

	var loginTemplateContent string
	var err error

	if config.LoginTemplatePath != "" {
		tmplBytes, errFile := os.ReadFile(config.LoginTemplatePath)
		if errFile != nil {
			return nil, fmt.Errorf("failed to read login template file %s: %w", config.LoginTemplatePath, errFile)
		}
		loginTemplateContent = string(tmplBytes)
	} else if config.LoginTemplate != "" {
		loginTemplateContent = config.LoginTemplate
	} else {
		loginTemplateContent = defaultLoginTemplate
	}

	loginTmpl, err := template.New("login").Parse(loginTemplateContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse login template: %w", err)
	}

	return &AuthMiddleware{
		next:       next,
		secret:     config.Secret,
		cookieConf: config.CookieConf,
		users:      config.Users,
		name:       name,
		loginTmpl:  loginTmpl,
	}, nil
}

func (a *AuthMiddleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if cookie, err := req.Cookie(a.cookieConf.Name); err == nil {
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(cookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(a.secret), nil
		})
		if err == nil && token.Valid {
			req.Header.Set("Username", claims.Username) // Set username header for upstream
			a.next.ServeHTTP(rw, req)
			return
		}
	}

	// No valid cookie, proceed to login
	if req.Method == http.MethodPost {
		username := req.FormValue("username")
		password := req.FormValue("password")

		if storedHash, exists := a.users[username]; exists && comparePasswords(storedHash, password) {
			expirationTime := time.Now().Add(time.Duration(a.cookieConf.TTL) * time.Minute)
			claims := &Claims{
				Username: username,
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(expirationTime),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
				},
			}
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			tokenString, err := token.SignedString([]byte(a.secret))

			if err == nil {
				http.SetCookie(rw, &http.Cookie{
					Name:     a.cookieConf.Name,
					Value:    tokenString,
					Expires:  expirationTime,
					Path:     a.cookieConf.Path,
					Domain:   a.cookieConf.Domain,
					HttpOnly: a.cookieConf.HttpOnly,
					Secure:   a.cookieConf.Secure,
					SameSite: a.cookieConf.SameSite,
				})
				http.Redirect(rw, req, req.URL.Path, http.StatusFound)
				return
			}
			// Log internal error if token signing fails
			// For security, don't expose internal error details to client here
			http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		// Invalid credentials
		rw.WriteHeader(http.StatusUnauthorized)
		a.renderLoginPage(rw, map[string]interface{}{"ErrorMessage": "Invalid username or password"})
		return
	}

	// Show login page for GET or other methods
	a.renderLoginPage(rw, nil)
}

func (a *AuthMiddleware) renderLoginPage(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := a.loginTmpl.Execute(w, data)
	if err != nil {
		// Log internal error
		http.Error(w, "Failed to render login page: "+err.Error(), http.StatusInternalServerError)
	}
}

func comparePasswords(hashedPwd string, plainPwd string) bool {
	byteHash := []byte(hashedPwd)
	bytePlain := []byte(plainPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, bytePlain)
	return err == nil
}
