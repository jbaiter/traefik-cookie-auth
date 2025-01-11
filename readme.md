# Traefik Cookie Authentication Middleware

[![Build Status](https://github.com/inalbilal/traefik-cookie-auth/workflows/Main/badge.svg?branch=master)](https://github.com/inalbilal/traefik-cookie-auth/actions)

A Traefik middleware plugin that provides cookie-based authentication with JWT tokens. This middleware presents a login form for unauthenticated users and manages authentication state using secure cookies.

## Features

- Cookie-based authentication with JWT tokens
- Support for multiple users
- Support for bcrypt-generated passwords
- Configurable cookie settings
- Bootstrap-styled login page
- Secure password handling

## Installation

### Static Configuration

Add the plugin to your Traefik static configuration:

```yaml
experimental:
  plugins:
    cookie-auth:
      moduleName: github.com/inalbilal/traefik-cookie-auth
      version: v0.2.1
```

### Dynamic Configuration

Configure the middleware in your dynamic configuration:

```yaml
http:
  middlewares:
    my-cookie-auth:
      plugin:
        cookie-auth:
          users: "admin:$$2y$$05$$eWB3jfpm8U1sFPBAg5Zdg.PG2OhoCeGIWAuqDDToBcIQYYu2UlIFe,test2:$2y$10$..."
          secret: "your_secret_key"
          cookieConf:
            name: "traefik_auth_token"
            path: "/"
            ttl: 60
            httpOnly: true
            secure: false
            sameSite: 1
```

## Configuration

All configuration options with their default values:

```yaml
# User credentials in username:hash format, multiple users separated by comma
users: ""

# Secret key for JWT token generation
secret: ""

# Cookie configuration
cookieConf:
  name: "traefik_auth_token"  # Name of the cookie
  path: "/"                   # Cookie path
  ttl: 60                     # Time to live in minutes
  httpOnly: true             # HttpOnly flag
  secure: false              # Set to true if using HTTPS
  sameSite: 1               # SameSite policy (1: Default, 2: Lax, 3: Strict, 4: None)
```

You can generate bcrypt password hashes using htpasswd:
```bash
htpasswd -B -nb admin mypassword
```

## Example Docker Compose

```yaml
version: '3.9'
services:
  traefik:
    image: traefik:v2.11
    command:
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--entrypoints.web.address=:80"
      - "--experimental.plugins.cookie-auth.modulename=github.com/inalbilal/traefik-cookie-auth"
      - "--experimental.plugins.cookie-auth.version=v0.2.1"
    ports:
      - "80:80"
      - "8080:8080"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

  whoami:
    image: traefik/whoami
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.whoami.rule=Host(`whoami.local`)"
      - "traefik.http.routers.whoami.entrypoints=web"
      - "traefik.http.routers.whoami.middlewares=cookie-auth"
      - "traefik.http.middlewares.cookie-auth.plugin.cookie-auth.users=admin:$$2y$$05$$eWB3jfpm8U1sFPBAg5Zdg.PG2OhoCeGIWAuqDDToBcIQYYu2UlIFe"
      - "traefik.http.middlewares.cookie-auth.plugin.cookie-auth.secret=your_secret_key"
      - "traefik.http.middlewares.cookie-auth.plugin.cookie-auth.cookieConf.name=traefik_auth_token"
      - "traefik.http.middlewares.cookie-auth.plugin.cookie-auth.cookieConf.path=/"
      - "traefik.http.middlewares.cookie-auth.plugin.cookie-auth.cookieConf.ttl=60"
      - "traefik.http.middlewares.cookie-auth.plugin.cookie-auth.cookieConf.httpOnly=true"
      - "traefik.http.middlewares.cookie-auth.plugin.cookie-auth.cookieConf.secure=false"
      - "traefik.http.middlewares.cookie-auth.plugin.cookie-auth.cookieConf.sameSite=1"
```

## Development

To develop or test the plugin locally:

1. Clone the repository
2. Run tests: `go test ./...`
3. Use local plugin mode in Traefik (see Traefik documentation for details)

## Security Considerations

- Always use HTTPS in production
- Use strong passwords and a secure JWT secret
- Enable the `secure` cookie flag in production
- Consider enabling stricter SameSite policies based on your needs

## License

This project is licensed under the MIT License - see the LICENSE file for details.
