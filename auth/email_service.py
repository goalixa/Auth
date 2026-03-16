import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from auth.email_templates import EmailTemplates

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
        Send an email via SMTP

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

        # Use template
        html_body = EmailTemplates.password_reset_request(
            reset_link=reset_url,
            recipient_email=to
        )

        return self.send_email(to, "Reset Your Password", html_body)

    def send_email_verification_email(
        self, to: str, verify_token: str, app_url: str
    ) -> bool:
        """
        Send an email verification email.

        Args:
            to: Recipient email address
            verify_token: Email verification token
            app_url: Base URL of the application

        Returns:
            True if email was sent successfully, False otherwise
        """
        # Create verification URL
        verify_url = f"{app_url}/verify-email?token={verify_token}"

        # Use template
        html_body = EmailTemplates.verify_email(
            verify_link=verify_url,
            recipient_email=to
        )

        return self.send_email(to, "Verify Your Email Address", html_body)

    def send_password_reset_confirmation_email(
        self, to: str
    ) -> bool:
        """
        Send a password reset confirmation email.

        Args:
            to: Recipient email address

        Returns:
            True if email was sent successfully, False otherwise
        """
        html_body = EmailTemplates.password_reset_confirmation(
            recipient_email=to
        )

        return self.send_email(to, "Password Successfully Reset", html_body)

    def send_welcome_email(
        self, to: str, app_url: str = None
    ) -> bool:
        """
        Send a welcome email to newly verified users.

        Args:
            to: Recipient email address
            app_url: Base URL of the application

        Returns:
            True if email was sent successfully, False otherwise
        """
        if not app_url:
            app_url = os.getenv("GOALIXA_APP_URL", "https://app.goalixa.com")

        login_url = f"{app_url}/#/login"

        html_body = EmailTemplates.welcome_user(
            recipient_email=to,
            login_link=login_url
        )

        return self.send_email(to, "Welcome to Goalixa!", html_body)


# Global email service instance
email_service = EmailService()
