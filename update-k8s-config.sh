#!/bin/bash
# Script to fix auth redirect issue in Kubernetes cluster
# Run this on the server or from your local machine with kubectl configured

set -e

echo "=== Fixing Auth Redirect in Kubernetes ==="
echo ""

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl not found. Please install kubectl first."
    exit 1
fi

# Check current context
echo "Current kubectl context:"
kubectl config current-context
echo ""

NAMESPACE="goalixa-auth"
CONFIGMAP="auth-config"

echo "Checking current ConfigMap..."
echo ""

# Get current AUTH_COOKIE_DOMAIN value
CURRENT_COOKIE_DOMAIN=$(kubectl get configmap $CONFIGMAP -n $NAMESPACE -o jsonpath='{.data.AUTH_COOKIE_DOMAIN}' 2>/dev/null || echo "")

if [ "$CURRENT_COOKIE_DOMAIN" = ".goalixa.com" ]; then
    echo "✓ AUTH_COOKIE_DOMAIN is already set to: $CURRENT_COOKIE_DOMAIN"
else
    echo "⚠ Current AUTH_COOKIE_DOMAIN: $CURRENT_COOKIE_DOMAIN"
    echo "→ Updating to: .goalixa.com"

    kubectl patch configmap $CONFIGMAP -n $NAMESPACE --type merge \
        -p '{"data":{"AUTH_COOKIE_DOMAIN":".goalixa.com"}}' 2>/dev/null || \
    kubectl create configmap $CONFIGMAP -n $NAMESPACE \
        --from-literal=AUTH_COOKIE_DOMAIN=".goalixa.com" \
        --dry-run=client -o yaml | kubectl apply -f -

    echo "✓ Updated AUTH_COOKIE_DOMAIN"
fi

echo ""

# Check GOALIXA_APP_URL
CURRENT_APP_URL=$(kubectl get configmap $CONFIGMAP -n $NAMESPACE -o jsonpath='{.data.GOALIXA_APP_URL}' 2>/dev/null || echo "")
EXPECTED_APP_URL="https://app.goalixa.com"

if [ "$CURRENT_APP_URL" = "$EXPECTED_APP_URL" ] || [ "$CURRENT_APP_URL" = "$EXPECTED_APP_URL/" ]; then
    echo "✓ GOALIXA_APP_URL is already set to: $CURRENT_APP_URL"
else
    echo "⚠ Current GOALIXA_APP_URL: $CURRENT_APP_URL"
    echo "→ Updating to: $EXPECTED_APP_URL"

    kubectl patch configmap $CONFIGMAP -n $NAMESPACE --type merge \
        -p "{\"data\":{\"GOALIXA_APP_URL\":\"$EXPECTED_APP_URL\"}}" 2>/dev/null || \
    kubectl create configmap $CONFIGMAP -n $NAMESPACE \
        --from-literal=GOALIXA_APP_URL="$EXPECTED_APP_URL" \
        --dry-run=client -o yaml | kubectl apply -f -

    echo "✓ Updated GOALIXA_APP_URL"
fi

echo ""

# Check AUTH_COOKIE_SAMESITE
CURRENT_SAMESITE=$(kubectl get configmap $CONFIGMAP -n $NAMESPACE -o jsonpath='{.data.AUTH_COOKIE_SAMESITE}' 2>/dev/null || echo "")

if [ "$CURRENT_SAMESITE" = "None" ] || [ "$CURRENT_SAMESITE" = "Lax" ]; then
    echo "✓ AUTH_COOKIE_SAMESITE is set to: $CURRENT_SAMESITE"
else
    echo "⚠ Current AUTH_COOKIE_SAMESITE: $CURRENT_SAMESITE"
    echo "→ Updating to: Lax"

    kubectl patch configmap $CONFIGMAP -n $NAMESPACE --type merge \
        -p '{"data":{"AUTH_COOKIE_SAMESITE":"Lax"}}' 2>/dev/null || \
    kubectl create configmap $CONFIGMAP -n $NAMESPACE \
        --from-literal=AUTH_COOKIE_SAMESITE="Lax" \
        --dry-run=client -o yaml | kubectl apply -f -

    echo "✓ Updated AUTH_COOKIE_SAMESITE"
fi

echo ""

# Check AUTH_COOKIE_SECURE
CURRENT_SECURE=$(kubectl get configmap $CONFIGMAP -n $NAMESPACE -o jsonpath='{.data.AUTH_COOKIE_SECURE}' 2>/dev/null || echo "")

if [ "$CURRENT_SECURE" = "1" ]; then
    echo "✓ AUTH_COOKIE_SECURE is already set to: $CURRENT_SECURE"
else
    echo "⚠ Current AUTH_COOKIE_SECURE: $CURRENT_SECURE"
    echo "→ Updating to: 1"

    kubectl patch configmap $CONFIGMAP -n $NAMESPACE --type merge \
        -p '{"data":{"AUTH_COOKIE_SECURE":"1"}}' 2>/dev/null || \
    kubectl create configmap $CONFIGMAP -n $NAMESPACE \
        --from-literal=AUTH_COOKIE_SECURE="1" \
        --dry-run=client -o yaml | kubectl apply -f -

    echo "✓ Updated AUTH_COOKIE_SECURE"
fi

echo ""
echo "Restarting auth pods to pick up new configuration..."

# Restart the deployment
kubectl rollout restart deployment/auth -n $NAMESPACE

echo "✓ Restarted auth deployment"
echo ""
echo "Waiting for rollout to complete..."
kubectl rollout status deployment/auth -n $NAMESPACE --timeout=60s

echo ""
echo "=== Fix Complete ==="
echo ""
echo "Configuration updated:"
echo "  AUTH_COOKIE_DOMAIN=.goalixa.com"
echo "  GOALIXA_APP_URL=https://app.goalixa.com"
echo "  AUTH_COOKIE_SECURE=1"
echo "  AUTH_COOKIE_SAMESITE=Lax"
echo ""
echo "Test the login at:"
echo "  https://auth.goalixa.com/login?next=https://app.goalixa.com/"
