# goalixa-auth

Standalone authentication service for Goalixa.

## Local run

```bash
python app.py
```

## Metrics

Prometheus metrics are exposed at `GET /metrics`.

## Environment variables

- `AUTH_SECRET_KEY`: Flask session secret.
- `AUTH_DATABASE_URI`: SQLAlchemy database URI (defaults to `sqlite:///data.db`).
- `AUTH_JWT_SECRET`: Secret for signing auth tokens (must match Goalixa).
- `AUTH_JWT_TTL_MINUTES`: Token lifetime (default 120).
- `AUTH_COOKIE_NAME`: Cookie name (default `goalixa_auth`).
- `AUTH_COOKIE_SECURE`: Set to `1` to require HTTPS cookies.
- `GOALIXA_APP_URL`: Where to redirect after login/logout (default `http://localhost:5000`).
- `REGISTERABLE`: Set to `0` to disable registration.
- `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` / `GOOGLE_REDIRECT_URI`: Google OAuth config.
- `ADMIN_EMAIL` / `ADMIN_PASSWORD`: Optional bootstrap admin user.
