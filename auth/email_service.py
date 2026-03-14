import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)


class EmailService:
    """Service for sending emails via SMTP."""

    def __init__(self):
        """Initialize email service with configuration from environment."""
        self.enabled = os.getenv("EMAIL_ENABLED", "0") == "1"
        self.smtp_host = os.getenv("EMAIL_SMTP_HOST", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("EMAIL_SMTP_PORT", "587"))
        self.username = os.getenv("EMAIL_USERNAME", "")
        self.password = os.getenv("EMAIL_PASSWORD", "")
        self.from_address = os.getenv("EMAIL_FROM", "Goalixa <noreply@goalixa.com>")
        self.use_tls = os.getenv("EMAIL_USE_TLS", "1") == "1"

        if self.enabled and not self.username:
            logger.warning("Email is enabled but EMAIL_USERNAME is not set")
            self.enabled = False

    def send_email(self, to: str, subject: str, html_body: str) -> bool:
        """
        Send an email via SMTP.

        Args:
            to: Recipient email address
            subject: Email subject line
            html_body: HTML body content

        Returns:
            True if email was sent successfully, False otherwise
        """
        if not self.enabled:
            logger.info(f"Email sending is disabled. Would have sent to: {to}")
            # For development/testing, log what would be sent
            logger.debug(f"Email Subject: {subject}")
            logger.debug(f"Email Body: {html_body[:200]}...")
            return False

        try:
            # Create message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.from_address
            msg["To"] = to

            # Add HTML body
            html_part = MIMEText(html_body, "html")
            msg.attach(html_part)

            # Connect to SMTP server and send
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.send_message(msg)

            logger.info(f"Email sent successfully to {to}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email to {to}: {str(e)}", exc_info=True)
            return False

    def send_password_reset_email(
        self, to: str, reset_token: str, app_url: str
    ) -> bool:
        """
        Send a password reset email with a reset link.

        Args:
            to: Recipient email address
            reset_token: Password reset token
            app_url: Base URL of the application (e.g., https://app.goalixa.com)

        Returns:
            True if email was sent successfully, False otherwise
        """
        # Create reset URL
        reset_url = f"{app_url}/reset-password?token={reset_token}"

        # Create HTML email body
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #f4f4f4;
                }}
                .container {{
                    background-color: #ffffff;
                    border-radius: 8px;
                    padding: 40px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                .header {{
                    text-align: center;
                    margin-bottom: 30px;
                }}
                .logo {{
                    font-size: 24px;
                    font-weight: bold;
                    color: #4F46E5;
                    margin-bottom: 10px;
                }}
                h1 {{
                    color: #333;
                    font-size: 24px;
                    margin-bottom: 20px;
                }}
                p {{
                    margin-bottom: 20px;
                    color: #555;
                }}
                .button {{
                    display: inline-block;
                    background-color: #4F46E5;
                    color: #ffffff;
                    text-decoration: none;
                    padding: 12px 30px;
                    border-radius: 6px;
                    font-weight: 600;
                    margin: 20px 0;
                }}
                .button:hover {{
                    background-color: #4338CA;
                }}
                .footer {{
                    margin-top: 30px;
                    padding-top: 20px;
                    border-top: 1px solid #e5e7eb;
                    text-align: center;
                    font-size: 12px;
                    color: #9ca3af;
                }}
                .warning {{
                    background-color: #FEF3C7;
                    border-left: 4px solid #F59E0B;
                    padding: 12px;
                    margin: 20px 0;
                    font-size: 14px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="logo">Goalixa</div>
                </div>

                <h1>Password Reset Request</h1>

                <p>Hello,</p>

                <p>We received a request to reset your password for your Goalixa account. Click the button below to create a new password:</p>

                <div style="text-align: center;">
                    <a href="{reset_url}" class="button">Reset Password</a>
                </div>

                <p>Or copy and paste this link into your browser:</p>
                <p style="word-break: break-all; color: #4F46E5; font-size: 14px;">{reset_url}</p>

                <div class="warning">
                    <strong>Important:</strong> This link will expire in 30 minutes. If you didn't request a password reset, you can safely ignore this email.
                </div>

                <p>If you have any questions, please contact our support team.</p>

                <div class="footer">
                    <p>&copy; 2026 Goalixa. All rights reserved.</p>
                    <p>This is an automated email. Please do not reply.</p>
                </div>
            </div>
        </body>
        </html>
        """

        subject = "Reset Your Goalixa Password"
        return self.send_email(to, subject, html_body)


# Global email service instance
email_service = EmailService()
