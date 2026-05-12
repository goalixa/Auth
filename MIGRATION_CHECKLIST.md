# PostgreSQL Migration Verification Checklist

## Pre-Deployment

- [ ] All code changes committed
- [ ] Docker image built and pushed to Harbor
- [ ] Migration scripts tested locally
- [ ] Backup of existing SQLite database created
- [ ] Team notified of scheduled maintenance window

## Kubernetes Deployment

### Database Deployment
- [ ] `postgres` StatefulSet deployed
- [ ] PostgreSQL pod is `Running` and `Ready`
- [ ] PersistentVolumeClaim is `Bound`
- [ ] Health check shows postgres is responsive
- [ ] Database `goalixa_auth_prod` exists

### Secret Creation
- [ ] Database credentials secret created (`postgres-secret`)
- [ ] JWT secret created (`auth-secrets`)
- [ ] Secrets are accessible from auth pod

### Auth Service Deployment
- [ ] Auth pods are `Running` and `Ready`
- [ ] Init container `wait-for-db` completed (if used)
- [ ] Auth service is accessible
- [ ] Health endpoint returns 200 OK

## Functional Tests

### Database Connectivity
- [ ] Auth service logs show successful DB connection
- [ ] No "Connection refused" errors
- [ ] No authentication errors

### User Operations
- [ ] User registration works
- [ ] User login works
- [ ] Token refresh works
- [ ] Token revocation works
- [ ] Password reset works
- [ ] Email verification works

### Data Integrity
- [ ] All users migrated correctly
- [ ] All tokens present
- [ ] Passwords still work (bcrypt hashes intact)
- [ ] Token expiration dates preserved

### API Endpoints
- [ ] `GET /health` returns 200
- [ ] `POST /register` works
- [ ] `POST /login` works
- [ ] `POST /refresh` works
- [ ] `POST /logout` works
- [ ] `POST /forgot-password` works

### Monitoring
- [ ] Prometheus metrics available
- [ ] No critical errors in logs
- [ ] Database metrics showing healthy stats
- [ ] Query performance acceptable

## Post-Migration

- [ ] Monitor for 24 hours
- [ ] Check logs for warnings/errors
- [ ] Verify database backups running (if enabled)
- [ ] Update status documentation
- [ ] Archive SQLite backup securely
- [ ] Team debrief on any issues

## Rollback (If Needed)

- [ ] Delete postgres pods
- [ ] Auth service reverts to SQLite (if configured)
- [ ] Verify service stability
- [ ] Investigate root cause
