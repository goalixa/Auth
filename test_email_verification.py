#!/usr/bin/env python3
"""
Test script for email verification functionality
Run this after starting the auth service to test email verification flow
"""

import requests
import json
import time
from typing import Dict, Any

BASE_URL = "http://localhost:5001"  # Adjust if your service runs on a different port

def print_response(title: str, response: requests.Response):
    """Pretty print API response"""
    print(f"\n{'='*60}")
    print(f"{title}")
    print(f"{'='*60}")
    print(f"Status Code: {response.status_code}")
    try:
        print(f"Response: {json.dumps(response.json(), indent=2)}")
    except:
        print(f"Response: {response.text}")

def test_registration():
    """Test user registration with email verification"""
    print("\n🔹 Testing Registration...")

    # Generate unique email
    timestamp = int(time.time())
    email = f"test.user.{timestamp}@example.com"
    password = "SecurePass123!"

    response = requests.post(
        f"{BASE_URL}/api/register",
        json={"email": email, "password": password}
    )

    print_response("Registration Response", response)

    if response.status_code == 200:
        data = response.json()
        verification_token = data.get("verification_token")
        email_verified = data.get("email_verified")

        print(f"\n✅ Registration successful!")
        print(f"   Email: {email}")
        print(f"   Verified: {email_verified}")
        print(f"   Token: {verification_token[:20]}..." if verification_token else "")

        return email, password, verification_token
    else:
        print(f"\n❌ Registration failed!")
        return None, None, None

def test_login_unverified(email: str, password: str):
    """Test login with unverified email (should fail)"""
    print("\n🔹 Testing Login (Unverified)...")

    response = requests.post(
        f"{BASE_URL}/api/login",
        json={"email": email, "password": password}
    )

    print_response("Login Response (Unverified)", response)

    if response.status_code == 403:
        print(f"\n✅ Login correctly blocked for unverified email")
    else:
        print(f"\n❌ Login should have been blocked!")

def test_resend_verification(email: str):
    """Test resending verification email"""
    print("\n🔹 Testing Resend Verification...")

    response = requests.post(
        f"{BASE_URL}/api/resend-verification",
        json={"email": email}
    )

    print_response("Resend Verification Response", response)

    if response.status_code == 200:
        print(f"\n✅ Resend verification successful")
    else:
        print(f"\n❌ Resend verification failed")

def test_verify_email(token: str):
    """Test email verification"""
    print("\n🔹 Testing Email Verification...")

    response = requests.post(
        f"{BASE_URL}/api/verify-email",
        json={"token": token}
    )

    print_response("Email Verification Response", response)

    if response.status_code == 200:
        print(f"\n✅ Email verification successful!")
        return True
    else:
        print(f"\n❌ Email verification failed!")
        return False

def test_login_verified(email: str, password: str):
    """Test login with verified email (should succeed)"""
    print("\n🔹 Testing Login (Verified)...")

    response = requests.post(
        f"{BASE_URL}/api/login",
        json={"email": email, "password": password}
    )

    print_response("Login Response (Verified)", response)

    if response.status_code == 200:
        print(f"\n✅ Login successful after verification!")
        # Print cookies
        print(f"\nCookies received:")
        for cookie_name, cookie_value in response.cookies.items():
            print(f"   {cookie_name}: {cookie_value[:20]}...")
    else:
        print(f"\n❌ Login failed after verification!")

def test_invalid_token():
    """Test verification with invalid token"""
    print("\n🔹 Testing Invalid Token...")

    response = requests.post(
        f"{BASE_URL}/api/verify-email",
        json={"token": "invalid-token-12345"}
    )

    print_response("Invalid Token Response", response)

    if response.status_code == 400:
        print(f"\n✅ Invalid token correctly rejected")
    else:
        print(f"\n❌ Invalid token should have been rejected!")

def test_resend_already_verified(email: str):
    """Test resending verification for already verified email"""
    print("\n🔹 Testing Resend for Already Verified Email...")

    response = requests.post(
        f"{BASE_URL}/api/resend-verification",
        json={"email": email}
    )

    print_response("Resend Already Verified Response", response)

    if response.status_code == 400:
        print(f"\n✅ Resend correctly blocked for verified email")
    else:
        print(f"\n⚠️  Resend should indicate email is already verified")

def test_google_oauth():
    """Test Google OAuth (just check endpoint exists)"""
    print("\n🔹 Testing Google OAuth Endpoint...")

    response = requests.get(
        f"{BASE_URL}/api/oauth/google/start",
        params={"return_to": "http://localhost:5000"},
        allow_redirects=False
    )

    print_response("Google OAuth Start Response", response)

    if response.status_code in [302, 400, 503]:
        print(f"\n✅ Google OAuth endpoint exists")
    else:
        print(f"\n⚠️  Unexpected Google OAuth response")

def check_health():
    """Check if service is running"""
    print("\n🔹 Checking Service Health...")

    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        print_response("Health Check", response)

        if response.status_code == 200:
            print(f"\n✅ Service is healthy")
            return True
        else:
            print(f"\n❌ Service health check failed")
            return False
    except requests.exceptions.ConnectionError:
        print(f"\n❌ Cannot connect to service at {BASE_URL}")
        print(f"   Make sure the auth service is running!")
        return False

def main():
    """Run all tests"""
    print("\n" + "="*60)
    print(" Email Verification Test Suite")
    print("="*60)

    # Check if service is running
    if not check_health():
        return

    # Test flow
    email, password, token = test_registration()

    if not email:
        print("\n❌ Registration failed - cannot continue tests")
        return

    # Test login with unverified email
    test_login_unverified(email, password)

    # Test resend verification
    test_resend_verification(email)

    # Test invalid token
    test_invalid_token()

    # Verify email
    verified = test_verify_email(token)

    if verified:
        # Test login with verified email
        test_login_verified(email, password)

        # Test resend for already verified
        test_resend_already_verified(email)

    # Test Google OAuth endpoint
    test_google_oauth()

    print("\n" + "="*60)
    print(" Test Suite Complete")
    print("="*60)
    print(f"\n📧 Check your email logs to see verification emails")
    print(f"   (if EMAIL_ENABLED=1, check your inbox)")
    print(f"   (if EMAIL_ENABLED=0, check application logs)")

if __name__ == "__main__":
    main()
