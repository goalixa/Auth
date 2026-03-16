# Goalixa Auth - Helm Chart

This Helm chart deploys the Goalixa Authentication Service with dual-token JWT authentication and Google OAuth support.

## Architecture

```
┌───────────────────────────────────────────────────────────┐
│                    GitHub Workflow                         │
│  ┌────────────────┐      ┌────────────────────────┐      │
│  │  Build Image   │ ───► │  Push to Harbor       │      │
│  │  (git SHA tag) │      │  harbor.goalixa.com   │      │
│  └────────────────┘      └──────────┬─────────────┘      │
│                                      │                     │
│                           ┌──────────▼─────────────┐      │
│                           │  kubectl patch ArgoCD  │      │
│                           │  Update image.tag     │      │
│                           └──────────┬─────────────┘      │
│                                      │                     │
│                           ┌──────────▼─────────────┐      │
│                           │  Trigger ArgoCD Sync   │      │
│                           └────────────────────────┘      │
└───────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌───────────────────────────────────────────────────────────┐
│                       ArgoCD                               │
│  ┌────────────────┐      ┌────────────────────────┐      │
│  │ Helm Chart     │ ───► │  Render with Values   │      │
│  │ (helm/)        │      │  + Image Tag (param)  │      │
│  └────────────────┘      └──────────┬─────────────┘      │
│                                      │                     │
│                           ┌──────────▼─────────────┐      │
│                           │  Deploy to K8s         │      │
│                           │  (goalixa-auth ns)     │      │
│                           └────────────────────────┘      │
└───────────────────────────────────────────────────────────┘
```

**Key Improvement**: No git commits back to repo - image tags updated directly on ArgoCD Application resource!

## Quick Start

### 1. Install Secrets (First Time Only)

```bash
kubectl create secret generic auth-secrets \
  --from-literal=AUTH_JWT_SECRET='your-jwt-secret' \
  --from-literal=AUTH_SECRET_KEY='your-flask-secret' \
  --from-literal=AUTH_DATABASE_URI='postgresql://...' \
  --from-literal=GOOGLE_CLIENT_ID='your-client-id' \
  --from-literal=GOOGLE_CLIENT_SECRET='your-client-secret' \
  --from-literal=GOOGLE_REDIRECT_URI='https://auth.goalixa.com/oauth/callback' \
  -n goalixa-auth
```

### 2. Install Chart Locally (Testing)

```bash
# From the helm/ directory
helm install goalixa-auth . -n goalixa-auth --create-namespace
```

### 3. Upgrade Chart

```bash
helm upgrade goalixa-auth . -n goalixa-auth
```

### 4. Uninstall Chart

```bash
helm uninstall goalixa-auth -n goalixa-auth
```

## Configuration

### Image Tag Management

**Important**: The image tag is managed automatically by GitHub workflow updating ArgoCD:

```bash
# View current ArgoCD Helm parameters
kubectl get application goalixa-auth -n argocd -o jsonpath='{.spec.source.helm.parameters}'

# Manually update image tag (if needed)
kubectl patch application goalixa-auth -n argocd \
  --type='merge' \
  -p='{"spec":{"source":{"helm":{"parameters":[{"name":"image.tag","value":"abc1234"}]}}}}'

# Trigger immediate sync
kubectl annotate application goalixa-auth \
  -n argocd \
  "force-sync-at=$(date +%s)" \
  --overwrite
```

### Key Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.tag` | Docker image tag | `latest` |
| `replicaCount` | Number of replicas | `1` |
| `env.LOG_LEVEL` | Logging level | `INFO` |
| `env.AUTH_ACCESS_TOKEN_TTL_MINUTES` | Access token TTL | `15` |
| `env.AUTH_REFRESH_TOKEN_TTL_DAYS` | Refresh token TTL | `7` |
| `persistence.size` | PVC storage size | `1Gi` |
| `cronJob.enabled` | Enable token cleanup CronJob | `true` |

See [values.yaml](values.yaml) for all configuration options.

## Environments

### Production

```bash
helm install goalixa-auth . -n goalixa-auth \
  -f values-production.yaml
```

### Staging

```bash
helm install goalixa-auth . -n goalixa-auth \
  -f values-staging.yaml
```

## ArgoCD Integration

The chart is configured for ArgoCD GitOps deployment:

1. **Application Manifest**: [`.argo/app-helm.yaml`](../.argo/app-helm.yaml)
2. **Sync Mode**: Automated (auto-prune, self-heal)
3. **Image Updates**: Via kubectl patch to ArgoCD app (no git commit needed)

### Manual ArgoCD Sync

```bash
# Trigger immediate sync
kubectl annotate app goalixa-auth \
  -n argocd \
  "force-sync-at=$(date +%s)" \
  --overwrite
```

## Workflow Integration

The GitHub workflow (`.github/workflows/main.yml`) automatically:

1. Builds Docker image with git SHA tag (e.g., `82d1ebf`)
2. Pushes to Harbor registry
3. Patches ArgoCD Application with new image tag
4. Triggers ArgoCD sync

**Key Benefits**:
- ✅ No git commits back to repository
- ✅ No `git pull --rebase` race conditions
- ✅ Clean separation of code and deployment state

## Troubleshooting

### View Deployed Resources

```bash
# Pods
kubectl get pods -n goalixa-auth

# Deployment
kubectl get deployment auth -n goalixa-auth

# Logs
kubectl logs -f deployment/auth -n goalixa-auth

# CronJob
kubectl get cronjob token-cleanup -n goalixa-auth
```

### Check Image Tag

```bash
# What's in ArgoCD app spec?
kubectl get application goalixa-auth -n argocd -o jsonpath='{.spec.source.helm.parameters[0].value}'

# What's actually deployed?
kubectl get deployment auth -n goalixa-auth -o jsonpath='{.spec.template.spec.containers[0].image}'
```

### Sync Issues

```bash
# Check ArgoCD app status
kubectl get app goalixa-auth -n argocd -o yaml

# Force re-sync
kubectl patch app goalixa-auth -n argocd \
  --type='json' \
  -p='[{"op": "replace", "path": "/spec/sync/retry", "value": {"limit": 5}}]'
```

## Structure

```
helm/
├── Chart.yaml                  # Chart metadata
├── values.yaml                 # Default values
├── values-production.yaml      # Production overrides
├── values-staging.yaml         # Staging overrides
├── README.md                   # This file
└── templates/
    ├── _helpers.tpl            # Template helpers
    ├── namespace.yaml          # Namespace
    ├── configmap.yaml          # ConfigMap
    ├── deployment.yaml         # Deployment
    ├── service.yaml            # Service
    ├── pvc.yaml                # PersistentVolumeClaim
    └── cronjob.yaml            # Token cleanup CronJob
```

## Security Notes

- Secrets are stored as Kubernetes secrets (not in Helm values)
- Image pull secrets required for Harbor registry
- HTTP-only cookies for refresh tokens
- CSRF protection enabled
- Rate limiting recommended (configure via ingress)

## Maintenance

### Updating Secrets

```bash
kubectl delete secret auth-secrets -n goalixa-auth
# Re-create with new values (see step 1)
kubectl rollout restart deployment/auth -n goalixa-auth
```

### Database Migrations

Run migrations before deploying new image:

```bash
kubectl exec -it deployment/auth -n goalixa-auth -- \
  flask db upgrade
```

