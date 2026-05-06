# Email Verification Documentation

## Overview

The goalixa-auth service now includes comprehensive email verification functionality to ensure users have access to the email addresses they register with.

## Features

✅ **Automatic Email Sending** - Verification emails sent immediately upon registration
✅ **Login Protection** - Unverified users are blocked from logging in
✅ **Resend Capability** - Users can request new verification emails
✅ **Welcome Emails** - Friendly welcome message after successful verification
✅ **Google OAuth Auto-Verify** - Google-authenticated users are pre-verified
✅ **Rate Limiting** - Protection against abuse (3 resend requests per hour)
✅ **Token Expiration** - Verification tokens expire after 60 minutes
✅ **Prometheus Metrics** - Track verification success/failure rates

## API Endpoints

### 1. POST `/api/register`
**Register a new user and send verification email**

Request:
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

Response:
```json
{
  "success": true,
  "user": {"email": "user@example.com"},
  "verification_token": "abc123...",
  "email_verified": false,
  "message": "Registration successful. Please check your email to verify your account."
}
```

### 2. POST `/api/verify-email`
**Verify email address with token**

Request:
```json
{
  "token": "abc123..."
}
```

Success Response:
```json
{
  "success": true,
  "message": "Email verified successfully. Welcome to Goalixa!"
}
```

Error Responses:
- `400` - Token missing or invalid format
- `400` - Token expired or already used
- `404` - User not found

### 3. POST `/api/resend-verification`
**Resend verification email**

Request:
```json
{
  "email": "user@example.com"
}
```

Response:
```json
{
  "success": true,
  "message": "If an account exists with this email, a verification link has been sent."
}
```

**Rate Limiting**: 3 requests per hour per IP
**Note**: Always returns success to prevent email enumeration attacks

Error Response (Already Verified):
```json
{
  "success": false,
  "error": "This email address is already verified."
}
```

### 4. POST `/api/login`
**Login (requires verified email)**

Request:
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

Error Response (Unverified):
```json
{
  "success": false,
  "error": "Please verify your email address before logging in.",
  "email_verified": false,
  "user_id": 123
}
```

## Email Configuration

Add these environment variables to your `.env` file:

```env
# Email Configuration
EMAIL_ENABLED=1
EMAIL_SMTP_HOST=smtp.gmail.com
EMAIL_SMTP_PORT=587
EMAIL_USERNAME=your-email@gmail.com
EMAIL_PASSWORD=your-app-password
EMAIL_FROM=Goalixa <noreply@goalixa.com>
EMAIL_USE_TLS=1

# Application URL (used in email links)
GOALIXA_APP_URL=https://app.goalixa.com
```

### Gmail Setup

1. Enable 2-factor authentication on your Google account
2. Generate an App Password:
   - Go to https://myaccount.google.com/apppasswords
   - Select "Mail" and "Other (Custom name)"
   - Copy the generated password
3. Use the app password as `EMAIL_PASSWORD`

### Other SMTP Providers

**SendGrid**:
```env
EMAIL_SMTP_HOST=smtp.sendgrid.net
EMAIL_SMTP_PORT=587
EMAIL_USERNAME=apikey
EMAIL_PASSWORD=your-sendgrid-api-key
```

**AWS SES**:
```env
EMAIL_SMTP_HOST=email-smtp.us-east-1.amazonaws.com
EMAIL_SMTP_PORT=587
EMAIL_USERNAME=your-smtp-username
EMAIL_PASSWORD=your-smtp-password
```

**Mailgun**:
```env
EMAIL_SMTP_HOST=smtp.mailgun.org
EMAIL_SMTP_PORT=587
EMAIL_USERNAME=postmaster@your-domain.mailgun.org
EMAIL_PASSWORD=your-mailgun-password
```

## User Flow

1. **Registration**:
   - User submits email + password
   - Account created with `email_verified = false`
   - Verification token generated (60-minute expiry)
   - Verification email sent with link

2. **Email Verification**:
   - User clicks link in email (format: `https://app.goalixa.com/verify-email?token=abc123`)
   - Frontend calls `/api/verify-email` with token
   - Token validated and marked as used
   - User's `email_verified` set to `true`
   - Welcome email sent

3. **Login**:
   - User attempts login
   - Email verification checked
   - If not verified → login blocked with error message
   - If verified → login succeeds

4. **Resend (if needed)**:
   - User didn't receive email
   - Frontend calls `/api/resend-verification`
   - New email sent (or existing valid token reused)

## Google OAuth

Users authenticating via Google OAuth are automatically verified since Google has already confirmed their email address.

## Security Features

- **Rate Limiting**: Prevents brute-force token guessing and email spam
- **Token Expiration**: 60-minute window reduces exposure
- **One-time Use**: Tokens can only be used once
- **Email Enumeration Protection**: Resend endpoint doesn't reveal if email exists
- **HTTPS Links**: All email links use secure protocol

## Database Schema

### `email_verification_token` Table

| Column | Type | Description |
|--------|------|-------------|
| `id` | Integer | Primary key |
| `user_id` | Integer | Foreign key to user table |
| `token` | String(64) | Unique verification token (UUID) |
| `expires_at` | DateTime | Token expiration timestamp |
| `used_at` | DateTime | When token was verified (NULL if unused) |
| `created_at` | DateTime | Token creation timestamp |

### `user` Table (Updated)

| Column | Type | Description |
|--------|------|-------------|
| `email_verified` | Boolean | Email verification status (default: false) |

## Prometheus Metrics

```
# Email verification attempts
goalixa_auth_email_verification_total{status="success"}
goalixa_auth_email_verification_total{status="failed_invalid"}
goalixa_auth_email_verification_total{status="failed_expired"}

# Resend requests
goalixa_auth_email_verification_resend_total{status="success"}
goalixa_auth_email_verification_resend_total{status="failed_already_verified"}

# Login failures due to unverified email
goalixa_auth_login_total{status="failed_unverified"}
```

## Token Cleanup

Expired and used verification tokens are automatically cleaned up by the admin cleanup job:

```bash
curl -X POST http://localhost:5001/admin/cleanup-tokens?days=7 \
  -H "X-Admin-API-Key: your-admin-key"
```

This removes:
- Used verification tokens older than 7 days
- Expired verification tokens older than 7 days
- Expired password reset tokens
- Revoked refresh tokens

## Testing

### Local Development

When `EMAIL_ENABLED=0`, verification emails are logged instead of sent:

```
INFO: Email sending is disabled. Would have sent to: user@example.com
DEBUG: Email Subject: Verify Your Email Address
DEBUG: Email Body: <html>...
```

The verification token is still returned in the registration response for testing.

### Production Testing

1. Register a new account
2. Check email inbox (including spam folder)
3. Click verification link
4. Confirm welcome email received
5. Verify login works after verification

## Frontend Integration

### Registration Flow

```javascript
const response = await fetch('/api/register', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email, password})
});

const data = await response.json();

if (data.success && !data.email_verified) {
  // Show "Check your email" message
  showMessage('Please check your email to verify your account');
  // Redirect to verification pending page
  router.push('/verify-email-pending');
}
```

### Verification Flow

```javascript
// Extract token from URL: /verify-email?token=abc123
const token = new URLSearchParams(window.location.search).get('token');

const response = await fetch('/api/verify-email', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({token})
});

const data = await response.json();

if (data.success) {
  showMessage('Email verified! Welcome to Goalixa');
  router.push('/login');
}
```

### Resend Flow

```javascript
const response = await fetch('/api/resend-verification', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email})
});

const data = await response.json();
showMessage(data.message);
```

### Login Error Handling

```javascript
const response = await fetch('/api/login', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email, password})
});

const data = await response.json();

if (!data.success && !data.email_verified) {
  // Show verification required message with resend option
  showVerificationRequired(email);
}
```

## Troubleshooting

### Emails Not Sending

1. Check `EMAIL_ENABLED=1` in environment
2. Verify SMTP credentials are correct
3. Check application logs for SMTP errors
4. Test SMTP connection manually
5. Verify firewall allows outbound SMTP traffic

### Tokens Expiring Too Quickly

Default is 60 minutes. To change:

```python
# In auth/models.py, line 67
verification_token = create_email_verification_token(user, ttl_minutes=120)  # 2 hours
```

### Welcome Emails Not Sending

Check logs for errors in `/api/verify-email` endpoint. Welcome email failures are logged but don't block verification.

## Email Templates

Email templates are located in `auth/email_templates.py` and use responsive HTML with inline CSS.

Templates available:
- `verify_email()` - Email verification
- `welcome_user()` - Post-verification welcome
- `password_reset_request()` - Password reset
- `password_reset_confirmation()` - Password reset confirmation

Customize branding by editing `EmailTemplates` class variables:
```python
APP_NAME = "Goalixa"
PRIMARY_COLOR = "#111827"
LINK_COLOR = "#2563eb"
```

## Best Practices

1. **Always use HTTPS** for verification links in production
2. **Monitor metrics** to track verification rates
3. **Set up DKIM/SPF** to improve email deliverability
4. **Use a dedicated email service** (SendGrid, AWS SES) in production
5. **Implement email bounce handling** for invalid addresses
6. **Add unsubscribe links** for marketing emails (not auth emails)
7. **Rate limit aggressively** to prevent abuse

## Future Enhancements

- [ ] Email change verification (when user updates email)
- [ ] SMS verification as alternative
- [ ] Magic link login (passwordless)
- [ ] Email verification reminders
- [ ] Admin dashboard to view verification stats
- [ ] Bulk user verification tools
- [ ] Custom email template editor

---

**Last Updated**: 2026-05-05
**Version**: 1.0.0
