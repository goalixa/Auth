# goalixa-auth

Standalone authentication service for Goalixa with dual-token authentication.

## Local run

```bash
python app.py
```

## Metrics

Prometheus metrics are exposed at `GET /metrics`.

## Environment variables

### Required
- `AUTH_JWT_SECRET`: Secret for signing auth tokens (must match Goalixa app).

### Optional
- `AUTH_SECRET_KEY`: Flask session secret (defaults to dev secret).
- `AUTH_DATABASE_URI`: SQLAlchemy database URI (defaults to `sqlite:///data.db`).
- `AUTH_ACCESS_TOKEN_TTL_MINUTES`: Access token lifetime in minutes (default: `15`).
- `AUTH_REFRESH_TOKEN_TTL_DAYS`: Refresh token lifetime in days (default: `7`).
- `AUTH_ACCESS_COOKIE_NAME`: Access token cookie name (default: `goalixa_access`).
- `AUTH_REFRESH_COOKIE_NAME`: Refresh token cookie name (default: `goalixa_refresh`).
- `AUTH_COOKIE_SECURE`: Set to `1` to require HTTPS cookies (auto-enabled with `SameSite=None`).
- `AUTH_COOKIE_SAMESITE`: Cookie SameSite attribute (default: `None` for cross-domain).
- `AUTH_COOKIE_DOMAIN`: Cookie domain (auto-detected from `GOALIXA_APP_URL` for goalixa.com).
- `GOALIXA_APP_URL`: Where to redirect after login/logout (default: `https://goalixa.com/app`).
- `REGISTERABLE`: Set to `0` to disable registration (default: `1`).
- `GOOGLE_CLIENT_ID`: Google OAuth client ID.
- `GOOGLE_CLIENT_SECRET`: Google OAuth client secret.
- `GOOGLE_REDIRECT_URI`: Google OAuth redirect URI.
- `ADMIN_EMAIL`: Bootstrap admin user email.
- `ADMIN_PASSWORD`: Bootstrap admin user password.
- `LOG_LEVEL`: Logging level (default: `INFO`).

## Dual-Token Authentication

This service implements a dual-token authentication system for enhanced security:

- **Access Token**: Short-lived (15 minutes) JWT used for API authentication
- **Refresh Token**: Long-lived (7 days) JWT stored in database for token renewal

### Token Flow

1. User logs in via `/api/login`, `/api/register`, or OAuth
2. Service issues both access and refresh tokens as HTTP-only cookies
3. Access token is used for authentication
4. When access token expires, frontend automatically calls `/api/refresh` to get a new access token
5. Refresh tokens are rotated on each refresh for security (old token revoked, new one issued)

### Security Features

- **Token Rotation**: Refresh tokens are rotated on each use to detect token theft
- **Database Validation**: Refresh tokens validated against database on each use
- **Auto-Revocation**: Tokens automatically revoked on logout and password change
- **HTTP-Only Cookies**: Both tokens stored in HTTP-only cookies to prevent XSS access

### API Endpoints

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/login` | GET | Serve login UI |
| `/login` | POST | Validate credentials, issue dual tokens, redirect |
| `/api/login` | POST | JSON login, issue dual tokens |
| `/register` | GET | Serve registration UI |
| `/register` | POST | Create user, issue dual tokens, redirect |
| `/api/register` | POST | JSON registration, issue dual tokens |
| `/api/refresh` | POST | Exchange refresh token for new access token (rotates refresh token) |
| `/logout` | GET | Revoke refresh token, clear cookies, redirect |
| `/api/logout` | POST | Revoke refresh token, clear cookies, return JSON |
| `/login/google` | GET | Start Google OAuth flow |
| `/login/google/callback` | GET | Finalize Google OAuth, issue dual tokens |
| `/api/me` | GET | Get current user info |

### Database Migration

The `refresh_token` table is created automatically via `db.create_all()`. For production, run:

```sql
CREATE TABLE refresh_token (
    id INTEGER PRIMARY KEY,
    token VARCHAR(255) UNIQUE NOT NULL,
    token_id VARCHAR(36) UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    revoked_at DATETIME,
    replaced_by INTEGER,
    FOREIGN KEY (user_id) REFERENCES user(id),
    FOREIGN KEY (replaced_by) REFERENCES refresh_token(id)
);
CREATE INDEX idx_refresh_token_user ON refresh_token(user_id);
CREATE INDEX idx_refresh_token_token ON refresh_token(token);
CREATE INDEX idx_refresh_token_expires ON refresh_token(expires_at);
```
