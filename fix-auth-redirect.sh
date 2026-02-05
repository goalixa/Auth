#!/bin/bash
# Script to fix auth redirect issue on production server
# Run this on your server: ssh root@202.133.91.244 'bash -s' < fix-auth-redirect.sh

echo "=== Fixing Auth Redirect Issue ==="
echo ""

# Set the correct environment variables
cat >> /root/goalixa-auth/.env <<EOF

# Production settings - Fixed for cross-subdomain auth
GOALIXA_APP_URL=https://app.goalixa.com
AUTH_COOKIE_DOMAIN=.goalixa.com
AUTH_COOKIE_SECURE=1
AUTH_COOKIE_SAMESITE=None
EOF

echo "✓ Updated .env file with correct cookie domain settings"
echo ""

# Find and restart the auth service
echo "Restarting auth service..."
if systemctl restart goalixa-auth 2>/dev/null; then
    echo "✓ Restarted goalixa-auth service"
elif docker restart goalixa-auth 2>/dev/null; then
    echo "✓ Restarted goalixa-auth container"
else
    echo "⚠ Could not automatically restart service"
    echo "Please restart your auth service manually"
fi

echo ""
echo "=== Fix Complete ==="
echo ""
echo "The auth cookie will now work across all goalixa.com subdomains."
echo "Test by logging in at https://auth.goalixa.com/login?next=https://app.goalixa.com/"
