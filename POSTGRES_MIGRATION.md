# SQLite to PostgreSQL Migration Guide

## Overview

This document describes the migration of goalixa-auth from SQLite to dedicated PostgreSQL database.

## Architecture Changes

**Before:**
- Auth service: Uses SQLite database locally
- Database: Single file (`data.db`)

**After:**
- Auth service: Connects to dedicated PostgreSQL
- Database: Kubernetes StatefulSet (`goalixa-auth-db`)
- Network: Service-to-service communication via DNS

## Migration Process

### Phase 1: Pre-Migration Checklist

- [ ] Backup existing SQLite database
- [ ] Verify PostgreSQL deployment is running
- [ ] Confirm database connectivity from auth pod
- [ ] Review migration script output

### Phase 2: Local Development Migration

```bash
# 1. Start postgres container
docker-compose up -d postgres
sleep 10

# 2. Run migration script
export AUTH_DATABASE_URI="postgresql://appuser:apppass@postgres:5432/authdb"
python init_db_migration.py

# 3. Verify migration
curl -s http://localhost:5001/health | jq .

# 4. Test authentication
curl -X POST http://localhost:5001/register \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "Test123!"}'
```

### Phase 3: Kubernetes Production Migration

#### Step 1: Create Namespace

```bash
kubectl create namespace goalixa-auth
```

#### Step 2: Create Secrets

```bash
# Create database password secret
kubectl create secret generic postgres-secret \
  -n goalixa-auth \
  --from-literal=POSTGRES_USER=authuser \
  --from-literal=POSTGRES_PASSWORD=$(openssl rand -base64 32) \
  --from-literal=POSTGRES_DB=goalixa_auth_prod
```

#### Step 3: Deploy PostgreSQL via ArgoCD

```bash
# Apply ArgoCD application
kubectl apply -f goalixa-auth/.argo/app-db.yaml

# Wait for StatefulSet
kubectl wait --for=condition=ready pod \
  -l app=postgres \
  -n goalixa-auth \
  --timeout=300s
```

#### Step 4: Run Migration

```bash
# Create migration job
kubectl create job goalixa-auth-migrate \
  --image=harbor.goalixa.com/goalixa/auth:latest \
  --image-pull-policy=Always \
  -n goalixa-auth \
  -- python init_db_migration.py

# Monitor job
kubectl logs -f -n goalixa-auth job/goalixa-auth-migrate
```

#### Step 5: Deploy Auth Service

```bash
# ArgoCD auto-syncs, just verify pods are ready
kubectl get pods -n goalixa-auth -w
```

### Phase 4: Post-Migration Validation

- [ ] Check pod logs for errors
- [ ] Verify database is initialized
- [ ] Test login endpoints
- [ ] Verify token refresh flow
- [ ] Check metrics endpoint
- [ ] Monitor for 24 hours

### Rollback Procedure

If migration fails:

```bash
# 1. Delete auth pods (forces restart)
kubectl delete pod -n goalixa-auth -l app=goalixa-auth

# 2. Verify service is running
kubectl get pods -n goalixa-auth

# 3. Check logs
kubectl logs -n goalixa-auth -l app=goalixa-auth
```

## Connection String Format

**PostgreSQL Connection String:**
```
postgresql://username:password@host:5432/database
```

**Environment Variable:**
```
AUTH_DATABASE_URI=postgresql://authuser:password@postgres:5432/goalixa_auth_prod
```

**Within Kubernetes:**
- Hostname: `postgres` (service DNS)
- Port: `5432` (default PostgreSQL)
- Database: From `POSTGRES_DB` environment variable

## Troubleshooting

### Issue: "Connection refused"

**Cause:** PostgreSQL not running or not ready

**Solution:**
```bash
kubectl wait --for=condition=ready pod -l app=postgres -n goalixa-auth
```

### Issue: "Authentication failed"

**Cause:** Wrong credentials in connection string

**Solution:**
```bash
# Verify secret
kubectl get secret postgres-secret -n goalixa-auth -o yaml

# Check deployment env
kubectl describe pod -n goalixa-auth -l app=goalixa-auth
```

### Issue: "Migration validation failed"

**Cause:** Data corruption or partial migration

**Solution:**
```bash
# Delete PostgreSQL and restart
kubectl delete pvc -n goalixa-auth data-postgres-0
kubectl delete pod -n goalixa-auth -l app=postgres
# Wait for PVC to be recreated, then run migration again
```

## Performance Considerations

- PostgreSQL uses 512Mi memory (dev) to 1Gi (production)
- Connection pooling recommended for high-traffic scenarios
- Enable backups for production (see values-production.yaml)

## Security Notes

- All secrets use random generation (openssl)
- Database password is 32-character random string
- Credentials stored in K8s Secrets (at-rest encryption recommended)
- Database access is internal-only (ClusterIP service)
