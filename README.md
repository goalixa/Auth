# Goalixa Auth

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-black?logo=flask)
![JWT](https://img.shields.io/badge/JWT-Auth-orange)
![License](https://img.shields.io/badge/License-MIT-green)

Authentication service for Goalixa with dual-token JWT system.

## Features

| Feature | Description |
|---------|-------------|
| **Dual-token JWT** | Access tokens (15min) + Refresh tokens (7 days) |
| **Token Rotation** | Automatic refresh token rotation |
| **HTTP-only Cookies** | Secure token storage |
| **Google OAuth** | Optional OAuth integration |
| **Password Reset** | Secure password reset flow |

## Architecture

```
┌──────────────────┐
│   Frontend/PWA   │
└────────┬─────────┘
         │ HTTPS
         ▼
┌──────────────────┐
│   BFF / Proxy    │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   goalixa-auth   │
│                  │
│  • Login/Register│
│  • Token Refresh │
│  • OAuth         │
└────────┬─────────┘
         │
         ▼
    ┌────────────┐
    │  Database  │
    └────────────┘
```

## Tech Stack

- **Python 3.11**
- **Flask** - Web framework
- **SQLAlchemy** - ORM
- **Authlib** - OAuth library
- **PyJWT** - Token handling

## Getting Started

### Installation

```bash
git clone https://github.com/goalixa/goalixa-auth.git
cd goalixa-auth

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Configuration

Create a `.env` file:

```bash
JWT_SECRET=your-jwt-secret
DATABASE_URI=sqlite:///data.db   # or PostgreSQL
```

| Variable | Description | Required |
|----------|-------------|----------|
| `JWT_SECRET` | Secret for signing tokens | Yes |
| `DATABASE_URI` | SQLAlchemy connection string | No |
| `ACCESS_TOKEN_TTL_MINUTES` | Access token lifetime | No (default: 15) |
| `REFRESH_TOKEN_TTL_DAYS` | Refresh token lifetime | No (default: 7) |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | No |
| `GOOGLE_CLIENT_SECRET` | Google OAuth secret | No |

### Run

```bash
python3 app.py
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/api/login` | User login |
| POST | `/api/register` | User registration |
| POST | `/api/refresh` | Refresh access token |
| POST | `/api/logout` | Logout (revoke tokens) |
| GET | `/api/me` | Current user info |
| POST | `/api/forgot` | Password reset request |
| POST | `/api/password-reset/confirm` | Confirm password reset |
| GET | `/api/oauth/google/start` | Start Google OAuth |
| GET | `/api/oauth/google/callback` | OAuth callback |

## Authentication Flow

```
1. User logs in → /api/login
2. Server issues access + refresh tokens (HTTP-only cookies)
3. Client makes requests with access token
4. Access token expires → Client calls /api/refresh
5. Server rotates refresh token, issues new access token
6. Logout → Both tokens revoked
```

### Token Security

- **Access Token**: Short-lived (15min), used for API calls
- **Refresh Token**: Long-lived (7 days), rotated on each use
- **HTTP-only**: Tokens stored in cookies, not accessible via JavaScript
- **Rotation**: Old refresh tokens are revoked when new ones are issued

## Database Schema

```sql
-- User table managed by your application

-- Refresh token tracking
CREATE TABLE refresh_token (
    id SERIAL PRIMARY KEY,
    token VARCHAR(255) UNIQUE NOT NULL,
    token_id VARCHAR(36) UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP,
    replaced_by INTEGER
);
```

## Deployment

### Docker

```bash
docker build -t goalixa-auth:latest .
docker run -p 8080:80 \
  -e JWT_SECRET="your-secret" \
  goalixa-auth:latest
```

### Kubernetes

```bash
helm upgrade --install goalixa-auth ./helm \
  --namespace goalixa \
  --create-namespace
```

## Security Checklist

When deploying to production:

- [ ] Use strong JWT secret (256-bit random)
- [ ] Enable HTTPS
- [ ] Set secure cookie flags
- [ ] Use PostgreSQL instead of SQLite
- [ ] Configure proper CORS origins

## License

MIT License - see [LICENSE](LICENSE) for details.

---

Built by [Amirreza Rezaie](https://github.com/amirrezarezaie)
