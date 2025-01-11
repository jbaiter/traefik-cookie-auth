package traefik_cookie_auth

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"net/http"
	"strings"
	"time"
)

type Config struct {
	Users      string        `json:"users"`
	Secret     string        `json:"secret"`
	CookieConf *CookieConfig `json:"cookieConf"`
}

type CookieConfig struct {
	Name     string        `json:"name"`
	Path     string        `json:"path"`
	Domain   string        `json:"domain"`
	TTL      int           `json:"ttl"`
	HttpOnly bool          `json:"httpOnly"`
	Secure   bool          `json:"secure"`
	SameSite http.SameSite `json:"sameSite"`
}

func CreateConfig() *Config {
	return &Config{
		CookieConf: &CookieConfig{
			Name:     "traefik_auth_token",
			Path:     "/",
			Domain:   "",
			TTL:      60,
			HttpOnly: true,
			Secure:   false,
			SameSite: http.SameSiteLaxMode,
		},
	}
}

type AuthMiddleware struct {
	next       http.Handler
	secret     string
	cookieConf *CookieConfig
	users      map[string]string
	name       string
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func (c *Config) ParseUsers() (map[string]string, error) {
	return parseUsers(c.Users), nil
}

func parseUsers(usersStr string) map[string]string {
	users := make(map[string]string)
	if usersStr == "" {
		return users
	}

	userList := strings.Split(usersStr, ",")
	for _, user := range userList {
		parts := strings.SplitN(user, ":", 2)
		if len(parts) != 2 {
			continue
		}
		users[parts[0]] = parts[1]
	}
	return users
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	userMap, err := config.ParseUsers()
	if err != nil {
		return nil, err
	}

	return &AuthMiddleware{
		next:       next,
		secret:     config.Secret,
		cookieConf: config.CookieConf,
		users:      userMap,
		name:       name,
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
			req.Header.Set("Username", claims.Username)
			a.next.ServeHTTP(rw, req)
			return
		}
	}

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
		}

		rw.WriteHeader(http.StatusUnauthorized)
		renderTemplate(rw, map[string]interface{}{"ErrorMessage": "Invalid username or password"})
		return
	}

	renderTemplate(rw, nil)
}

func comparePasswords(hashedPwd string, plainPwd string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPwd), []byte(plainPwd))
	return err == nil
}

func renderTemplate(w http.ResponseWriter, data interface{}) {
	const loginTemplate = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC" crossorigin="anonymous"></head><body><div class="container d-flex align-items-center justify-content-center vh-100"><div class="row w-100"><div class="col-md-6 mx-auto"><div class="card"><div class="card-body"><h2 class="text-center mb-4">Login</h2>{{if .ErrorMessage}}<div class="alert alert-danger" role="alert">{{.ErrorMessage}}</div>{{end}}<form method="POST"><div class="mb-3"><label for="username" class="form-label">Username</label><input type="text" class="form-control" id="username" name="username" placeholder="Enter your username" required></div><div class="mb-3"><label for="password" class="form-label">Password</label><input type="password" class="form-control" id="password" name="password" placeholder="Enter your password" required></div><button type="submit" class="btn btn-primary w-100">Login</button></form></div></div></div></div></div></body></html>`
	t, err := template.New("login").Parse(loginTemplate)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = t.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
