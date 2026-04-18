"""
Metrics Helper Module for Goalixa Auth Service
Provides convenient functions for recording Prometheus metrics..
"""
import time
from contextlib import contextmanager
from functools import wraps

# Import metrics from app.py (will be imported after app creation)
def _get_metrics():
    """Lazy import of metrics to avoid circular imports."""
    from app import (
        AUTH_LOGIN_TOTAL,
        AUTH_REGISTER_TOTAL,
        AUTH_LOGOUT_TOTAL,
        AUTH_REFRESH_TOTAL,
        AUTH_TOKEN_ISSUED_TOTAL,
        AUTH_VALIDATION_TOTAL,
        AUTH_FAILURES_TOTAL,
        OAUTH_GOOGLE_TOTAL,
        OAUTH_GOOGLE_DURATION_SECONDS,
        PASSWORD_RESET_REQUEST_TOTAL,
        PASSWORD_RESET_CONFIRM_TOTAL,
        DB_QUERY_DURATION_SECONDS,
        DB_QUERY_TOTAL,
    )
    return {
        'AUTH_LOGIN_TOTAL': AUTH_LOGIN_TOTAL,
        'AUTH_REGISTER_TOTAL': AUTH_REGISTER_TOTAL,
        'AUTH_LOGOUT_TOTAL': AUTH_LOGOUT_TOTAL,
        'AUTH_REFRESH_TOTAL': AUTH_REFRESH_TOTAL,
        'AUTH_TOKEN_ISSUED_TOTAL': AUTH_TOKEN_ISSUED_TOTAL,
        'AUTH_VALIDATION_TOTAL': AUTH_VALIDATION_TOTAL,
        'AUTH_FAILURES_TOTAL': AUTH_FAILURES_TOTAL,
        'OAUTH_GOOGLE_TOTAL': OAUTH_GOOGLE_TOTAL,
        'OAUTH_GOOGLE_DURATION_SECONDS': OAUTH_GOOGLE_DURATION_SECONDS,
        'PASSWORD_RESET_REQUEST_TOTAL': PASSWORD_RESET_REQUEST_TOTAL,
        'PASSWORD_RESET_CONFIRM_TOTAL': PASSWORD_RESET_CONFIRM_TOTAL,
        'DB_QUERY_DURATION_SECONDS': DB_QUERY_DURATION_SECONDS,
        'DB_QUERY_TOTAL': DB_QUERY_TOTAL,
    }


# ============= Authentication Metrics Helpers =============

def record_login_attempt(status: str):
    """
    Record a login attempt.

    Args:
        status: Status of the login attempt (success, failed_credentials, failed_inactive, missing_creds)
    """
    metrics = _get_metrics()
    metrics['AUTH_LOGIN_TOTAL'].labels(status=status).inc()


def record_registration_attempt(status: str):
    """
    Record a registration attempt.

    Args:
        status: Status of the registration (success, failed_disabled, failed_exists, failed_validation)
    """
    metrics = _get_metrics()
    metrics['AUTH_REGISTER_TOTAL'].labels(status=status).inc()


def record_logout(status: str = "success"):
    """
    Record a logout attempt.

    Args:
        status: Status of the logout (success, failed)
    """
    metrics = _get_metrics()
    metrics['AUTH_LOGOUT_TOTAL'].labels(status=status).inc()


def record_token_refresh(status: str):
    """
    Record a token refresh attempt.

    Args:
        status: Status of the refresh (success, failed_missing, failed_invalid, failed_expired, failed_user_inactive)
    """
    metrics = _get_metrics()
    metrics['AUTH_REFRESH_TOTAL'].labels(status=status).inc()


def record_token_issued(token_type: str):
    """
    Record a token being issued.

    Args:
        token_type: Type of token issued (access, refresh)
    """
    metrics = _get_metrics()
    metrics['AUTH_TOKEN_ISSUED_TOTAL'].labels(token_type=token_type).inc()


def record_token_validation(token_type: str, status: str):
    """
    Record a token validation attempt.

    Args:
        token_type: Type of token validated (access, refresh)
        status: Status of validation (success, failed, expired)
    """
    metrics = _get_metrics()
    metrics['AUTH_VALIDATION_TOTAL'].labels(token_type=token_type, status=status).inc()


def record_auth_failure(failure_type: str):
    """
    Record an authentication failure.

    Args:
        failure_type: Type of failure (invalid_credentials, invalid_token, expired_token, account_inactive)
    """
    metrics = _get_metrics()
    metrics['AUTH_FAILURES_TOTAL'].labels(failure_type=failure_type).inc()


# ============= OAuth Metrics Helpers =============

@contextmanager
def track_oauth_operation(operation: str):
    """
    Context manager to track OAuth operation metrics.

    Args:
        operation: Operation being performed (start, callback, user_info)

    Usage:
        with track_oauth_operation("callback"):
            result = oauth.google.authorize_access_token()
    """
    metrics = _get_metrics()
    start_time = time.time()
    status = "success"

    try:
        yield
    except Exception:
        status = "failed"
        raise
    finally:
        duration = time.time() - start_time
        metrics['OAUTH_GOOGLE_DURATION_SECONDS'].labels(operation=operation).observe(duration)
        metrics['OAUTH_GOOGLE_TOTAL'].labels(operation=operation, status=status).inc()


def record_oauth_operation(operation: str, status: str):
    """
    Record an OAuth operation.

    Args:
        operation: Operation performed (start, callback, user_created, user_login)
        status: Status of the operation (success, failed)
    """
    metrics = _get_metrics()
    metrics['OAUTH_GOOGLE_TOTAL'].labels(operation=operation, status=status).inc()


# ============= Password Reset Metrics Helpers =============

def record_password_reset_request(status: str):
    """
    Record a password reset request.

    Args:
        status: Status of the request (success, failed_validation)
    """
    metrics = _get_metrics()
    metrics['PASSWORD_RESET_REQUEST_TOTAL'].labels(status=status).inc()


def record_password_reset_confirm(status: str):
    """
    Record a password reset confirmation.

    Args:
        status: Status of the confirmation (success, failed_invalid, failed_expired)
    """
    metrics = _get_metrics()
    metrics['PASSWORD_RESET_CONFIRM_TOTAL'].labels(status=status).inc()


# ============= Database Metrics Helpers =============

@contextmanager
def track_db_query(operation: str, table: str):
    """
    Context manager to track database query metrics.

    Usage:
        with track_db_query("SELECT", "users"):
            user = User.query.get(user_id)
    """
    metrics = _get_metrics()
    start_time = time.perf_counter()
    status = "success"

    try:
        yield
    except Exception:
        status = "error"
        raise
    finally:
        duration = time.perf_counter() - start_time
        metrics['DB_QUERY_DURATION_SECONDS'].labels(operation=operation, table=table).observe(duration)
        metrics['DB_QUERY_TOTAL'].labels(operation=operation, table=table, status=status).inc()


def track_db_query_decorator(operation: str, table: str):
    """
    Decorator to track database query metrics.

    Usage:
        @track_db_query_decorator("SELECT", "users")
        def get_user(user_id):
            return User.query.get(user_id)
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            with track_db_query(operation, table):
                return func(*args, **kwargs)
        return wrapper
    return decorator


# ============= Generic Decorators =============

def track_operation(metric_counter, operation: str):
    """
    Generic decorator to track operations using any metric counter.

    Usage:
        @track_operation(AUTH_LOGIN_TOTAL, "login")
        def login():
            # ... implementation
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                result = func(*args, **kwargs)
                metric_counter.labels(status="success").inc()
                return result
            except Exception:
                metric_counter.labels(status="failed").inc()
                raise
        return wrapper
    return decorator
