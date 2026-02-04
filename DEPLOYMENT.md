# Goalixa Auth Service - Deployment Guide

## Overview

The auth service is configured to run at **auth.goalixa.com** and handles authentication for the Goalixa application.

## Architecture

- **Domain**: auth.goalixa.com
- **Namespace**: goalixa-auth
- **Ingress Controller**: Traefik
- **Replicas**: 2
- **Container Port**: 5001
- **Service Port**: 80

## Prerequisites

1. Kubernetes cluster (k3s) with Traefik ingress controller
2. GitHub Container Registry access (ghcr.io)
3. PostgreSQL database (optional, can use SQLite)
4. Domain DNS configured: auth.goalixa.com → your cluster IP

## Quick Start - Local Development

### Option 1: SQLite (Recommended for Testing)

```bash
# Install dependencies
pip install -r requirements.txt

# Use default .env (already configured for local dev)
# The app will use SQLite by default if AUTH_DATABASE_URI is not set

# Run the service
python app.py
```

The service will start at `http://localhost:5001`

### Option 2: PostgreSQL (Production-like)

```bash
# Setup PostgreSQL
psql -U postgres
CREATE DATABASE authdb;
CREATE USER appuser WITH PASSWORD 'apppass';
GRANT ALL PRIVILEGES ON DATABASE authdb TO appuser;
\q

# Update .env
# Uncomment this line:
# AUTH_DATABASE_URI=postgresql://appuser:apppass@localhost:5432/authdb

# Run the service
python app.py
```

## Kubernetes Deployment

### 1. Configure Secrets

First, generate secure secrets:

```bash
# Generate secrets
python -c "import secrets; print(secrets.token_hex(32))"
```

Edit `k8s/base/secret.yaml` and replace the placeholder values:

```yaml
stringData:
  # PostgreSQL connection (adjust for your database)
  AUTH_DATABASE_URI: "postgresql://appuser:apppass@postgres-db:5432/authdb"

  # Generate with the command above
  AUTH_JWT_SECRET: "your-generated-jwt-secret-here"
  AUTH_SECRET_KEY: "your-generated-secret-key-here"
```

**IMPORTANT**: The `AUTH_JWT_SECRET` must match the JWT secret used in your main Goalixa application.

### 2. Review ConfigMap

The `k8s/base/configmap.yaml` is pre-configured with production settings:

```yaml
data:
  GOALIXA_APP_URL: "https://app.goalixa.com/"
  AUTH_COOKIE_DOMAIN: "goalixa.com"
  AUTH_COOKIE_SECURE: "1"
  REGISTERABLE: "1"
```

Adjust these values if needed.

### 3. Deploy to Kubernetes

```bash
# Apply all manifests
kubectl apply -k k8s/base

# Check deployment status
kubectl get pods -n goalixa-auth
kubectl get ingress -n goalixa-auth

# View logs
kubectl logs -f deployment/auth -n goalixa-auth
```

### 4. Verify Deployment

```bash
# Check health endpoint
curl http://auth.goalixa.com/health

# Check if ingress is configured
kubectl describe ingress auth -n goalixa-auth
```

## Database Setup

### Option 1: Use Existing PostgreSQL

If you have a PostgreSQL instance, update the secret:

```yaml
AUTH_DATABASE_URI: "postgresql://user:password@your-postgres-host:5432/authdb"
```

### Option 2: Deploy PostgreSQL in Kubernetes

Create a PostgreSQL deployment (example):

```yaml
# postgres.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  namespace: goalixa-auth
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:16
        env:
        - name: POSTGRES_DB
          value: authdb
        - name: POSTGRES_USER
          value: appuser
        - name: POSTGRES_PASSWORD
          value: apppass
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
      volumes:
      - name: postgres-storage
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: postgres-db
  namespace: goalixa-auth
spec:
  selector:
    app: postgres
  ports:
  - port: 5432
    targetPort: 5432
```

Then deploy:
```bash
kubectl apply -f postgres.yaml
```

## CI/CD Pipeline

The GitHub Actions workflow automatically:

1. Builds Docker image on push to main
2. Pushes to ghcr.io/goalixa/goalixa-auth:latest
3. Deploys to k3s cluster (self-hosted runner)
4. Restarts the deployment

### Setup GitHub Secrets

Ensure your repository has access to:
- GitHub Container Registry (automatic with GITHUB_TOKEN)
- Self-hosted runner configured with kubectl access

## Environment Variables Reference

### Required (in Kubernetes Secret)

| Variable | Description | Example |
|----------|-------------|---------|
| `AUTH_DATABASE_URI` | Database connection string | `postgresql://user:pass@host:5432/db` |
| `AUTH_JWT_SECRET` | JWT signing secret (must match main app) | Random 64-char hex |
| `AUTH_SECRET_KEY` | Flask session secret | Random 64-char hex |

### Optional (in ConfigMap)

| Variable | Default | Description |
|----------|---------|-------------|
| `GOALIXA_APP_URL` | `https://app.goalixa.com/` | Redirect URL after login |
| `AUTH_JWT_TTL_MINUTES` | `120` | Token lifetime |
| `AUTH_COOKIE_NAME` | `goalixa_auth` | Cookie name |
| `AUTH_COOKIE_SECURE` | `1` | Require HTTPS |
| `AUTH_COOKIE_DOMAIN` | `goalixa.com` | Cookie domain |
| `REGISTERABLE` | `1` | Allow new user registration |
| `LOG_LEVEL` | `INFO` | Logging level |

### Optional (in Secret for Google OAuth)

| Variable | Description |
|----------|-------------|
| `GOOGLE_CLIENT_ID` | Google OAuth Client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth Client Secret |
| `GOOGLE_REDIRECT_URI` | `https://auth.goalixa.com/login/google/callback` |

## Endpoints

- `GET /health` - Health check
- `GET /metrics` - Prometheus metrics
- `GET /login` - Login page
- `POST /api/login` - API login endpoint
- `GET /register` - Registration page
- `POST /api/register` - API registration endpoint
- `GET /logout` - Logout
- `GET /login/google` - Google OAuth login

## Troubleshooting

### Pod not starting

```bash
# Check pod status
kubectl describe pod -n goalixa-auth -l app=auth

# Check logs
kubectl logs -n goalixa-auth -l app=auth
```

### Database connection issues

```bash
# Test database connection from pod
kubectl exec -it deployment/auth -n goalixa-auth -- python -c "
from app import create_app
app = create_app()
print('Database:', app.config['SQLALCHEMY_DATABASE_URI'])
"
```

### Ingress not working

```bash
# Check ingress
kubectl get ingress -n goalixa-auth
kubectl describe ingress auth -n goalixa-auth

# Check Traefik
kubectl logs -n kube-system -l app.kubernetes.io/name=traefik
```

### Cookie issues

Ensure:
- `AUTH_COOKIE_DOMAIN` is set to `goalixa.com` (not `auth.goalixa.com`)
- `AUTH_COOKIE_SECURE` is `1` for HTTPS
- `GOALIXA_APP_URL` ends with trailing slash

## Monitoring

### Prometheus Metrics

The service exposes Prometheus metrics at `/metrics`:

```bash
curl http://auth.goalixa.com/metrics
```

Available metrics:
- `http_requests_total` - Total HTTP requests
- `http_request_duration_seconds` - Request latency
- `http_requests_inprogress` - In-progress requests

### Log Monitoring

Logs are structured JSON and include:

```bash
kubectl logs -f deployment/auth -n goalixa-auth | jq .
```

## Security Checklist

- [ ] Secrets properly configured (not using REPLACE_ME values)
- [ ] JWT secret matches main Goalixa app
- [ ] AUTH_COOKIE_SECURE set to "1" for HTTPS
- [ ] Database credentials are strong
- [ ] TLS/SSL certificate configured for auth.goalixa.com
- [ ] Network policies configured (if needed)
- [ ] Regular secret rotation schedule

## Updating the Deployment

```bash
# Method 1: GitOps (recommended)
# Push changes to main branch, GitHub Actions will deploy

# Method 2: Manual deployment
kubectl apply -k k8s/base
kubectl rollout restart deployment/auth -n goalixa-auth

# Watch rollout
kubectl rollout status deployment/auth -n goalixa-auth
```

## Rollback

```bash
# View rollout history
kubectl rollout history deployment/auth -n goalixa-auth

# Rollback to previous version
kubectl rollout undo deployment/auth -n goalixa-auth

# Rollback to specific revision
kubectl rollout undo deployment/auth -n goalixa-auth --to-revision=2
```
