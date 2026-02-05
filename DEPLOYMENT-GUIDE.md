# Auth Redirect Fix - Deployment Guide

## Problem
After login, users are redirected back to `/login?next=...` instead of being redirected to `app.goalixa.com`.

## Root Cause
The auth cookie domain is not set correctly for cross-subdomain authentication. The cookie set on `auth.goalixa.com` is not being sent to `app.goalixa.com`.

## Solution
Update Kubernetes ConfigMap with correct cookie domain settings and restart the auth deployment.

---

## Quick Fix - Run on Your Server

### Option 1: SSH and run one-liner
```bash
ssh root@202.133.91.244 bash -s' < run-on-server.sh
```

### Option 2: SSH and run kubectl commands directly
```bash
ssh root@202.133.91.244

# Update the ConfigMap
kubectl patch configmap auth-config -n goalixa-auth --type merge -p '{
  "data": {
    "AUTH_COOKIE_DOMAIN": ".goalixa.com",
    "AUTH_COOKIE_SAMESITE": "None",
    "AUTH_COOKIE_SECURE": "1",
    "GOALIXA_APP_URL": "https://app.goalixa.com"
  }
}'

# Restart the auth deployment
kubectl rollout restart deployment/auth -n goalixa-auth

# Wait for rollout to complete
kubectl rollout status deployment/auth -n goalixa-auth
```

---

## Local Files Changed

The following files have been updated in your local repository. Deploy these changes if needed:

### 1. `k8s/auth/configmap.yaml`
- Updated `AUTH_COOKIE_SAMESITE` from "Lax" to "None"
- Removed trailing slash from `GOALIXA_APP_URL`

### 2. `auth-ui/auth.js`
- Fixed login redirect to use `next` parameter
- Now properly redirects to external URLs after successful login

### 3. `auth-ui/index.html` and `auth-ui/signup.html`
- Fixed social button `href` attributes (changed from `#` to `javascript:void(0)`)
- Added `name` attributes to form inputs for server-side fallback

---

## Configuration Details

### Updated ConfigMap Values

| Setting | Old Value | New Value |
|---------|-----------|-----------|
| `AUTH_COOKIE_DOMAIN` | (missing or wrong) | `.goalixa.com` |
| `AUTH_COOKIE_SAMESITE` | `Lax` | `None` |
| `AUTH_COOKIE_SECURE` | `1` | `1` (unchanged) |
| `GOALIXA_APP_URL` | (wrong) | `https://app.goalixa.com` |

### Why These Settings?

1. **`AUTH_COOKIE_DOMAIN=.goalixa.com`**
   - The leading dot (`.`) allows the cookie to work on ALL goalixa.com subdomains
   - Cookie set on `auth.goalixa.com` will be sent to `app.goalixa.com`

2. **`AUTH_COOKIE_SAMESITE=None`**
   - Required for cross-site cookie sending
   - Allows the auth cookie to be sent with redirects between subdomains
   - Must be used with `Secure` flag

3. **`AUTH_COOKIE_SECURE=1`**
   - Cookie is only sent over HTTPS
   - Required when using `SameSite=None`

4. **`GOALIXA_APP_URL=https://app.goalixa.com`**
   - Where users are redirected after successful login
   - No trailing slash to avoid redirect issues

---

## Testing

After applying the fix, test the login flow:

1. Visit: `https://auth.goalixa.com/login?next=https://app.goalixa.com/`
2. Login with your credentials
3. You should be redirected to `https://app.goalixa.com/`

### Check Cookie in Browser
1. Open browser DevTools (F12)
2. Go to Application → Cookies → `https://app.goalixa.com`
3. You should see a cookie named `goalixa_auth` with domain `.goalixa.com`

---

## Troubleshooting

### If redirect still doesn't work:

1. **Check ConfigMap was applied:**
   ```bash
   kubectl get configmap auth-config -n goalixa-auth -o yaml
   ```

2. **Check pod is using new config:**
   ```bash
   kubectl logs -n goalixa-auth deployment/auth --tail=50
   ```

3. **Check cookie in browser:**
   - The cookie domain must be `.goalixa.com` (with leading dot)
   - The SameSite attribute must be `None`

4. **Clear browser cookies:**
   - Sometimes old cookies interfere with new settings
   - Clear all cookies for goalixa.com domain

---

## Security Notes

⚠️ **Important:** After fixing, make sure your secrets are properly configured:

```bash
# Check if secrets exist
kubectl get secrets -n goalixa-auth

# Update Google OAuth credentials if needed
kubectl patch secret auth-secrets -n goalixa-auth --type=json -p='[
  {"op": "replace", "path": "/data/GOOGLE_CLIENT_ID", "value": "your-client-id.apps.googleusercontent.com"},
  {"op": "replace", "path": "/data/GOOGLE_CLIENT_SECRET", "value": "your-client-secret"}
]'
```

---

## Files Created

- `update-k8s-config.sh` - Comprehensive script to check and update k8s configuration
- `run-on-server.sh` - Quick one-liner to run on your server via SSH
- `DEPLOYMENT-GUIDE.md` - This document
