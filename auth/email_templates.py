"""
Email Templates for Goalixa
Compatible with Postmark template system
"""

from datetime import datetime
from typing import Dict


class EmailTemplates:
    """HTML email templates for Goalixa."""

    APP_NAME = "Goalixa"
    PRIMARY_COLOR = "#111827"
    SECONDARY_COLOR = "#4b5563"
    LINK_COLOR = "#2563eb"
    BG_COLOR = "#f6f9fc"
    CARD_BG = "#ffffff"

    @staticmethod
    def _base_template(
        subject: str,
        title: str,
        content: str,
        button_text: str = None,
        button_link: str = None,
        show_link: bool = False,
        footer_text: str = None
    ) -> str:
        """Base email template structure"""
        year = datetime.now().year

        button_html = ""
        if button_text and button_link:
            button_html = f"""
            <tr>
              <td align="center" style="padding:28px 32px 8px 32px;">
                <a
                  href="{button_link}"
                  target="_blank"
                  style="display:inline-block; background-color:{EmailTemplates.PRIMARY_COLOR}; color:#ffffff; text-decoration:none; font-size:16px; font-weight:600; padding:14px 24px; border-radius:10px;"
                >
                  {button_text}
                </a>
              </td>
            </tr>"""

        link_html = ""
        if show_link and button_link:
            link_html = f"""
            <tr>
              <td style="padding:24px 32px 0 32px; font-size:14px; line-height:22px; color:#6b7280;">
                If the button above does not work, copy and paste this link into your browser:
              </td>
            </tr>
            <tr>
              <td style="padding:8px 32px 0 32px; word-break:break-all; font-size:14px; line-height:22px; color:{EmailTemplates.LINK_COLOR};">
                <a href="{button_link}" target="_blank" style="color:{EmailTemplates.LINK_COLOR}; text-decoration:none;">{button_link}</a>
              </td>
            </tr>"""

        custom_footer = ""
        if footer_text:
            custom_footer = f"""
            <tr>
              <td style="padding:24px 32px 0 32px; font-size:14px; line-height:22px; color:#6b7280;">
                {footer_text}
              </td>
            </tr>"""

        return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>{subject}</title>
  </head>
  <body style="margin:0; padding:0; background-color:{EmailTemplates.BG_COLOR}; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,Cantarell,sans-serif; color:#1f2937;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color:{EmailTemplates.BG_COLOR}; margin:0; padding:24px 0;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:560px; background-color:{EmailTemplates.CARD_BG}; border-radius:16px; overflow:hidden; border:1px solid #e5e7eb; box-shadow:0 1px 3px 0 rgba(0,0,0,0.1);">
            <tr>
              <td style="padding:32px 32px 16px 32px; text-align:center;">
                <div style="font-size:28px; font-weight:700; color:{EmailTemplates.PRIMARY_COLOR}; letter-spacing:-0.5px;">
                  {EmailTemplates.APP_NAME}
                </div>
              </td>
            </tr>

            <tr>
              <td style="padding:8px 32px 0 32px; text-align:center;">
                <h1 style="margin:0; font-size:24px; line-height:32px; color:{EmailTemplates.PRIMARY_COLOR};">
                  {title}
                </h1>
              </td>
            </tr>

            <tr>
              <td style="padding:16px 32px 0 32px; text-align:left; font-size:16px; line-height:26px; color:{EmailTemplates.SECONDARY_COLOR};">
                {content}
              </td>
            </tr>
{button_html}
{link_html}
{custom_footer}
            <tr>
              <td style="padding:32px; font-size:13px; line-height:20px; color:#9ca3af; text-align:center; border-top:1px solid #f3f4f6;">
                © {year} {EmailTemplates.APP_NAME}. All rights reserved.<br/>
                You're receiving this email because you signed up for {EmailTemplates.APP_NAME}.
              </td>
            </tr>
          </table>

          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:560px;">
            <tr>
              <td style="padding:16px 24px 0 24px; text-align:center; font-size:12px; line-height:18px; color:#9ca3af;">
                This is an automated email from {EmailTemplates.APP_NAME}. Please do not reply.
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>"""

    @staticmethod
    def verify_email(verify_link: str, recipient_email: str = None) -> str:
        """
        Email verification template

        Args:
            verify_link: Verification URL with token
            recipient_email: Optional email address for personalization
        """
        greeting = f"Hi {recipient_email.split('@')[0]}," if recipient_email else "Hello,"
        recipient_info = f" at <strong>{recipient_email}</strong>" if recipient_email else ""

        content = f"""{greeting}

Thank you for signing up for {EmailTemplates.APP_NAME}!

To complete your registration and secure your account, please verify your email address{recipient_info}."""

        footer_text = """If you did not create an account with {app_name}, you can safely ignore this email."""

        return EmailTemplates._base_template(
            subject="Verify Your Email Address",
            title="Verify Your Email",
            content=content,
            button_text="Verify Email Address",
            button_link=verify_link,
            show_link=True,
            footer_text=footer_text
        )

    @staticmethod
    def password_reset_request(reset_link: str, recipient_email: str = None) -> str:
        """
        Password reset request template

        Args:
            reset_link: Password reset URL with token
            recipient_email: Optional email address for personalization
        """
        greeting = f"Hi {recipient_email.split('@')[0]}," if recipient_email else "Hello,"

        content = f"""{greeting}

We received a request to reset the password for your {EmailTemplates.APP_NAME} account.

Click the button below to create a new password. This link will expire in <strong>30 minutes</strong> for your security."""

        footer_text = """If you did not request a password reset, you can safely ignore this email. Your password will remain unchanged."""

        return EmailTemplates._base_template(
            subject="Reset Your Password",
            title="Reset Your Password",
            content=content,
            button_text="Reset Password",
            button_link=reset_link,
            show_link=True,
            footer_text=footer_text
        )

    @staticmethod
    def password_reset_confirmation(recipient_email: str = None) -> str:
        """
        Password reset confirmation template

        Args:
            recipient_email: Optional email address for personalization
        """
        greeting = f"Hi {recipient_email.split('@')[0]}," if recipient_email else "Hello,"

        content = f"""{greeting}

This email confirms that your {EmailTemplates.APP_NAME} password has been successfully reset.

If you did not make this change, please contact our support team immediately."""

        return EmailTemplates._base_template(
            subject="Password Successfully Reset",
            title="Password Has Been Reset",
            content=content,
            footer_text="For your security, please never share your password with anyone."
        )

    @staticmethod
    def welcome_user(recipient_email: str = None, login_link: str = None) -> str:
        """
        Welcome email for newly verified users

        Args:
            recipient_email: User's email address
            login_link: Optional link to login page
        """
        greeting = f"Hi {recipient_email.split('@')[0]}," if recipient_email else "Hello,"

        content = f"""{greeting}

Welcome to {EmailTemplates.APP_NAME}! 🎉

Your email has been verified and your account is now active.

You can now:
<br/>
• Track your goals and projects
<br/>
• Manage tasks efficiently
<br/>
• Monitor your progress with detailed analytics
<br/>
• Set reminders and stay organized"""

        login_link = login_link or "https://app.goalixa.com/#/login"

        return EmailTemplates._base_template(
            subject="Welcome to Goalixa!",
            title="Welcome Aboard! 🚀",
            content=content,
            button_text="Go to Dashboard",
            button_link=login_link,
            show_link=True
        )


# For Postmark template server compatibility
def get_postmark_template_data(template_type: str, variables: Dict) -> Dict:
    """
    Get template data for Postmark

    Args:
        template_type: Type of template (verify_email, password_reset, etc.)
        variables: Dictionary of template variables

    Returns:
        Dictionary with template data for Postmark API
    """
    templates = {
        "verify_email": {
            "templateId": None,  # Set your Postmark template ID here
            "subject": "Verify Your Email Address",
            "html": EmailTemplates.verify_email(
                verify_link=variables.get("verify_link", ""),
                recipient_email=variables.get("email", "")
            )
        },
        "password_reset": {
            "templateId": None,
            "subject": "Reset Your Password",
            "html": EmailTemplates.password_reset_request(
                reset_link=variables.get("reset_link", ""),
                recipient_email=variables.get("email", "")
            )
        },
        "password_reset_confirmation": {
            "templateId": None,
            "subject": "Password Successfully Reset",
            "html": EmailTemplates.password_reset_confirmation(
                recipient_email=variables.get("email", "")
            )
        },
        "welcome": {
            "templateId": None,
            "subject": "Welcome to Goalixa!",
            "html": EmailTemplates.welcome_user(
                recipient_email=variables.get("email", ""),
                login_link=variables.get("login_link", "")
            )
        }
    }

    return templates.get(template_type, {})
