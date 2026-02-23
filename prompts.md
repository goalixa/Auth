# Goalixa Auth Repository

## Purpose
Standalone authentication service with dual-token JWT authentication, user registration, and password reset functionality.

## Architecture
- **Dual-token authentication**: Short-lived access tokens (15 min) + long-lived refresh tokens (7 days)
- **Database-backed refresh tokens**: Stored in PostgreSQL for revocation support
- **Token rotation**: New refresh token issued on refresh, old one revoked

## Tech Stack
- **Python 3.11** + Flask
- **PostgreSQL** (production) or SQLite (development)
- **Flask-SQLAlchemy** for ORM
- **Prometheus** for metrics (Counter, Gauge, Histogram)
- **Werkzeug** for password hashing

## Key Configuration
Environment variables (supports Docker secrets in `/run/secrets/`):
- `AUTH_SECRET_KEY`: Flask secret key
- `AUTH_JWT_SECRET`: JWT signing secret (or AUTH_SECRET_KEY for backward compatibility)
- `AUTH_DATABASE_URI`: Database connection string
- `AUTH_ACCESS_TOKEN_TTL_MINUTES`: Access token TTL (default: 15)
- `AUTH_REFRESH_TOKEN_TTL_DAYS`: Refresh token TTL (default: 7)
- `AUTH_ACCESS_COOKIE_NAME`: Access cookie name (default: goalixa_access)
- `AUTH_REFRESH_COOKIE_NAME`: Refresh cookie name (default: goalixa_refresh)
- `AUTH_COOKIE_DOMAIN`: Cookie domain (optional)
- `AUTH_COOKIE_SAMESITE`: SameSite policy (default: Lax, can be None for cross-site)
- `AUTH_COOKIE_SECURE`: Secure flag (default: 1)
- `REGISTERABLE`: Enable public registration (default: 1)
- `LOG_LEVEL`: Logging level (default: INFO)

## Code Conventions
- Use `get_config_value()` helper for env vars with Docker secrets fallback
- Use `get_jwt_secret()` for JWT secret resolution with backward compatibility
- Structured logging: `app.logger.info("message", extra={"key": "value"})`
- ProxyFix for proper proxy header handling
- Prometheus metrics on all endpoints (except /metrics)
- Auto-refresh access tokens via refresh token in `before_request`

## File Structure
```
goalixa-auth/
├── app.py                 # Application factory and all routes
├── requirements.txt
├── auth/
│   ├── __init__.py
│   ├── models.py          # User, RefreshToken, PasswordResetToken
│   └── jwt.py             # JWT creation/validation
└── README.md
```

## API Endpoints
- `GET /health`: Health check
- `GET /metrics`: Prometheus metrics
- `POST /api/login`: Email/password login
- `POST /api/register`: User registration
- `POST /api/logout`: Logout (revokes refresh token)
- `POST /api/refresh`: Refresh access token
- `POST /api/forgot`: Initiate password reset
- `POST /api/password-reset/request`: Alias for password reset request
- `POST /api/password-reset/confirm`: Confirm password reset
- `GET /api/me`: Get current user info

## Cookie Security
- HTTP-only to prevent XSS
- Secure flag in production
- SameSite=Lax (or None for cross-site with Secure=True)
- Domain-wide cookies (.goalixa.com)
- Both access and refresh cookies set on auth success
