#!/bin/bash
# Quick one-liner to update Kubernetes config and restart auth pods
# Run this directly on your server: ssh root@202.133.91.244 'bash -s' < run-on-server.sh

kubectl patch configmap auth-config -n goalixa-auth --type merge -p '{
  "data": {
    "AUTH_COOKIE_DOMAIN": ".goalixa.com",
    "AUTH_COOKIE_SAMESITE": "None",
    "AUTH_COOKIE_SECURE": "1",
    "GOALIXA_APP_URL": "https://app.goalixa.com"
  }
}' && \
kubectl rollout restart deployment/auth -n goalixa-auth && \
echo "✓ Config updated and auth service restarted. Waiting for rollout..." && \
kubectl rollout status deployment/auth -n goalixa-auth --timeout=60s && \
echo "✓ Done! Test login at: https://auth.goalixa.com/login?next=https://app.goalixa.com/"
