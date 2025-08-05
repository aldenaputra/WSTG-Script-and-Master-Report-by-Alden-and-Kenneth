#!/usr/bin/env python3
"""
OWASP Authentication Testing Toolkit
Covers OTG-AUTHN-001 to OTG-AUTHN-010
Outputs results in SysReptor-compatible markdown format.
"""

import requests
import re
import json
import random
import string
import ssl
from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# -----------------------------------------------------------
# Configuration
# -----------------------------------------------------------
TARGET_URL = "http://localhost:8080"  # Change to your target URL
LOGIN_URL = f"{TARGET_URL}/login.php"
LOGOUT_URL = f"{TARGET_URL}/logout.php"
RESET_PASSWORD_URL = f"{TARGET_URL}/reset_password.php"
CHANGE_PASSWORD_URL = f"{TARGET_URL}/change_password.php"
SECURITY_QUESTION_URL = f"{TARGET_URL}/security_questions.php"
PROFILE_URL = f"{TARGET_URL}/profile.php"
REGISTER_URL = f"{TARGET_URL}/register.php"

# Test credentials
TEST_USER = ("testuser", "Password123!")
TEST_ADMIN = ("admin", "password123")

# Default credentials to test
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("root", "root"),
    ("test", "test"),
    ("user", "user"),
    ("administrator", "administrator"),
    ("guest", "guest"),
    ("demo", "demo"),
]

# Common security questions and answers
COMMON_SECURITY_QUESTIONS = {
    "What was your first pet's name?": ["Fluffy", "Max", "Bella"],
    "What is your mother's maiden name?": ["Smith", "Johnson", "Williams"],
    "What city were you born in?": ["New York", "London", "Paris"],
    "What was the name of your elementary school?": ["Lincoln Elementary", "Roosevelt High"],
    "What was your childhood nickname?": ["Buddy", "Princess", "Tiger"],
}

# Weak passwords for testing
WEAK_PASSWORDS = [
    "password", "123456", "qwerty", "letmein", "welcome",
    "admin123", "passw0rd", "12345678", "abc123", "Password1",
    "password123", "qwerty123", "1q2w3e4r", "111111", "admin"
]

# -----------------------------------------------------------
# Utility Functions
# -----------------------------------------------------------
def banner(msg):
    """Print banner message."""
    print("\n" + "=" * 70)
    print(f"  {msg}")
    print("=" * 70)

def http_request(method, url, data=None, cookies=None, headers=None, allow_redirects=True):
    """Generic HTTP request function."""
    try:
        if method.upper() == "GET":
            response = requests.get(url, params=data, cookies=cookies, headers=headers, 
                                  timeout=10, verify=False, allow_redirects=allow_redirects)
        else:
            response = requests.post(url, data=data, cookies=cookies, headers=headers, 
                                   timeout=10, verify=False, allow_redirects=allow_redirects)
        return response
    except requests.RequestException as e:
        print(f"HTTP error: {e}")
        return None

def extract_csrf_token(html_content):
    """Extract CSRF token from HTML content."""
    soup = BeautifulSoup(html_content, 'html.parser')
    csrf_input = soup.find('input', {'name': 'csrf_token'})
    return csrf_input['value'] if csrf_input else None

def get_session_cookies(response):
    """Extract session cookies from response."""
    return requests.utils.dict_from_cookiejar(response.cookies)

def generate_random_string(length=8):
    """Generate random string for test data."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def is_https(url):
    """Check if URL uses HTTPS."""
    return urlparse(url).scheme == "https"

# -----------------------------------------------------------
# Test Functions
# -----------------------------------------------------------
def otg_authn_001():
    """OTG-AUTHN-001: Testing for Credentials Transported over an Encrypted Channel"""
    banner("OTG-AUTHN-001: Testing Credentials Encryption")
    results = {
        "login_encrypted": False,
        "other_auth_endpoints": {},
        "vulnerabilities": []
    }
    
    # 1. Check if login uses HTTPS
    if is_https(LOGIN_URL):
        results["login_encrypted"] = True
    else:
        results["vulnerabilities"].append("Login credentials transmitted over unencrypted HTTP")
    
    # 2. Check other authentication-related endpoints
    auth_endpoints = [
        ("logout", LOGOUT_URL),
        ("password_reset", RESET_PASSWORD_URL),
        ("change_password", CHANGE_PASSWORD_URL),
        ("security_questions", SECURITY_QUESTION_URL),
        ("profile", PROFILE_URL)
    ]
    
    for name, url in auth_endpoints:
        if is_https(url):
            results["other_auth_endpoints"][name] = "HTTPS"
        else:
            results["other_auth_endpoints"][name] = "HTTP"
            results["vulnerabilities"].append(f"{name} endpoint uses HTTP")
    
    # 3. Check for mixed content issues
    login_page = http_request("GET", LOGIN_URL)
    if login_page and login_page.status_code == 200:
        if "http://" in login_page.text:
            results["vulnerabilities"].append("Mixed content detected in login page")
    
    return results

def otg_authn_002():
    """OTG-AUTHN-002: Testing for Default Credentials"""
    banner("OTG-AUTHN-002: Testing Default Credentials")
    results = {
        "tested_credentials": [],
        "vulnerable_accounts": [],
        "vulnerabilities": []
    }
    
    # Test default credentials
    for username, password in DEFAULT_CREDENTIALS:
        data = {"username": username, "password": password}
        response = http_request("POST", LOGIN_URL, data=data)
        
        success = response and response.status_code == 200 and "logout" in response.text.lower()
        results["tested_credentials"].append({
            "username": username,
            "password": password,
            "success": success
        })
        
        if success:
            results["vulnerable_accounts"].append(username)
            results["vulnerabilities"].append(f"Default credentials work: {username}/{password}")
    
    # Check for default admin paths
    admin_paths = ["/admin", "/administrator", "/manager", "/wp-admin"]
    for path in admin_paths:
        response = http_request("GET", TARGET_URL + path)
        if response and response.status_code == 200:
            results["vulnerabilities"].append(f"Default admin path accessible: {path}")
    
    return results

def otg_authn_003():
    """OTG-AUTHN-003: Testing for Weak Lockout Mechanism"""
    banner("OTG-AUTHN-003: Testing Lockout Mechanism")
    results = {
        "failed_attempts": 0,
        "lockout_threshold": None,
        "vulnerabilities": []
    }
    
    # Test with invalid credentials
    for i in range(1, 11):  # Test up to 10 attempts
        data = {"username": TEST_USER[0], "password": f"wrongpassword{i}"}
        response = http_request("POST", LOGIN_URL, data=data)
        
        if response and "invalid" in response.text.lower():
            results["failed_attempts"] = i
            print(f"Attempt {i}: Failed")
        else:
            print(f"Attempt {i}: Unexpected response")
            break
    
    # Test if account is locked after multiple attempts
    data = {"username": TEST_USER[0], "password": TEST_USER[1]}
    response = http_request("POST", LOGIN_URL, data=data)
    
    if response and "locked" in response.text.lower():
        results["lockout_threshold"] = results["failed_attempts"]
        print(f"Account locked after {results['failed_attempts']} attempts")
    elif response and "logout" in response.text.lower():
        results["vulnerabilities"].append("No account lockout mechanism detected")
        print("Login successful after multiple failed attempts")
    else:
        results["vulnerabilities"].append("Lockout mechanism not functioning properly")
    
    return results

def otg_authn_004():
    """OTG-AUTHN-004: Testing for Bypassing Authentication Schema"""
    banner("OTG-AUTHN-004: Testing Authentication Bypass")
    results = {
        "methods_tested": [],
        "vulnerabilities": []
    }
    
    # 1. Direct access to protected pages
    protected_pages = [PROFILE_URL, CHANGE_PASSWORD_URL, "/admin/dashboard.php"]
    for page in protected_pages:
        response = http_request("GET", page)
        if response and response.status_code == 200:
            results["methods_tested"].append(f"Direct access to {page}")
            results["vulnerabilities"].append(f"Direct access to protected page: {page}")
    
    # 2. Parameter tampering
    # Try to set authenticated=true in session
    cookies = {"session": "authenticated=true; user=admin"}
    response = http_request("GET", PROFILE_URL, cookies=cookies)
    if response and "Welcome" in response.text:
        results["methods_tested"].append("Session parameter tampering")
        results["vulnerabilities"].append("Authentication bypass via session tampering")
    
    # 3. HTTP verb tampering
    methods = ["PUT", "DELETE", "PATCH"]
    for method in methods:
        response = http_request(method, PROFILE_URL)
        if response and response.status_code == 200:
            results["methods_tested"].append(f"HTTP verb tampering: {method}")
            results["vulnerabilities"].append(f"Authentication bypass via {method} verb")
    
    # 4. Path traversal
    traversal_paths = [
        "/admin/../user/profile",
        "/%2e%2e/%2e%2e/admin",
        "/....//....//admin"
    ]
    for path in traversal_paths:
        response = http_request("GET", TARGET_URL + path)
        if response and "Admin Dashboard" in response.text:
            results["methods_tested"].append(f"Path traversal: {path}")
            results["vulnerabilities"].append(f"Authentication bypass via path traversal: {path}")
    
    return results

def otg_authn_005():
    """OTG-AUTHN-005: Test Remember Password Functionality"""
    banner("OTG-AUTHN-005: Testing Remember Password")
    results = {
        "cookie_analysis": {},
        "vulnerabilities": []
    }
    
    # Login with remember me
    data = {
        "username": TEST_USER[0],
        "password": TEST_USER[1],
        "remember": "on"
    }
    response = http_request("POST", LOGIN_URL, data=data)
    
    if not response or response.status_code != 200:
        return {"error": "Login failed"}
    
    # Analyze cookies
    cookies = get_session_cookies(response)
    for cookie in response.cookies:
        name = cookie.name
        value = cookie.value
        results["cookie_analysis"][name] = {
            "value": value,
            "secure": cookie.secure,
            "httponly": 'httponly' in (cookie._rest or {}),
            "samesite": (cookie._rest or {}).get("samesite")
        }


    
    # Check for sensitive data in cookies
    sensitive_patterns = ["user", "pass", "token", "auth", "sess"]
    for name, value in cookies.items():
        if any(pattern in name.lower() for pattern in sensitive_patterns):
            if "password" in value.lower() or TEST_USER[1] in value:
                results["vulnerabilities"].append(f"Sensitive data in cookie: {name}")
    
    # Test if cookie allows session restoration
    response = http_request("GET", PROFILE_URL, cookies=cookies)
    if response and "Welcome" in response.text:
        results["vulnerabilities"].append("Remember me functionality stores persistent session")
    
    return results

def otg_authn_006():
    """OTG-AUTHN-006: Testing for Browser Cache Weakness"""
    banner("OTG-AUTHN-006: Testing Browser Cache")
    results = {
        "cache_headers": {},
        "vulnerabilities": []
    }
    
    # Login and access sensitive page
    data = {"username": TEST_USER[0], "password": TEST_USER[1]}
    response = http_request("POST", LOGIN_URL, data=data)
    
    if not response or response.status_code != 200:
        return {"error": "Login failed"}
    
    cookies = get_session_cookies(response)
    
    # Access sensitive page
    response = http_request("GET", PROFILE_URL, cookies=cookies)
    if not response:
        return {"error": "Failed to access profile"}
    
    # Check cache headers
    headers = response.headers
    cache_related = ["Cache-Control", "Pragma", "Expires"]
    
    for header in cache_related:
        if header in headers:
            results["cache_headers"][header] = headers[header]
    
    # Evaluate cache settings
    if "Cache-Control" in headers:
        if "no-store" not in headers["Cache-Control"] and "no-cache" not in headers["Cache-Control"]:
            results["vulnerabilities"].append("Missing no-store in Cache-Control")
    else:
        results["vulnerabilities"].append("Cache-Control header missing")
    
    if "Pragma" in headers:
        if "no-cache" not in headers["Pragma"]:
            results["vulnerabilities"].append("Pragma header not set to no-cache")
    else:
        results["vulnerabilities"].append("Pragma header missing")
    
    # Test back button behavior
    response = http_request("GET", LOGOUT_URL, cookies=cookies)
    response = http_request("GET", PROFILE_URL, allow_redirects=False)
    if response and response.status_code == 200:
        results["vulnerabilities"].append("Sensitive content accessible after logout via back button")
    
    return results

def otg_authn_007():
    """OTG-AUTHN-007: Testing for Weak Password Policy"""
    banner("OTG-AUTHN-007: Testing Password Policy")
    results = {
        "tested_passwords": [],
        "vulnerabilities": []
    }
    
    # Get registration page to extract CSRF token
    reg_response = http_request("GET", REGISTER_URL)
    if not reg_response or reg_response.status_code != 200:
        return {"error": "Registration page not found"}
    
    csrf_token = extract_csrf_token(reg_response.text)
    
    # Test weak passwords
    for password in WEAK_PASSWORDS:
        user = f"test_{generate_random_string(4)}"
        data = {
            "username": user,
            "password": password,
            "email": f"{user}@example.com",
            "csrf_token": csrf_token
        }
        response = http_request("POST", REGISTER_URL, data=data)
        
        success = response and response.status_code == 200 and "success" in response.text.lower()
        results["tested_passwords"].append({
            "password": password,
            "accepted": success
        })
        
        if success:
            results["vulnerabilities"].append(f"Weak password accepted: {password}")
    
    # Test password change with weak password
    # First login
    login_data = {"username": TEST_USER[0], "password": TEST_USER[1]}
    login_response = http_request("POST", LOGIN_URL, data=login_data)
    if not login_response or login_response.status_code != 200:
        return {"error": "Test user login failed"}
    
    cookies = get_session_cookies(login_response)
    
    # Access change password page
    change_pw_page = http_request("GET", CHANGE_PASSWORD_URL, cookies=cookies)
    if not change_pw_page:
        return {"error": "Failed to access change password page"}
    
    csrf_token = extract_csrf_token(change_pw_page.text)
    
    # Try to change to weak password
    for password in WEAK_PASSWORDS[:3]:  # Test first 3 to avoid lockout
        data = {
            "current_password": TEST_USER[1],
            "new_password": password,
            "confirm_password": password,
            "csrf_token": csrf_token
        }
        response = http_request("POST", CHANGE_PASSWORD_URL, data=data, cookies=cookies)
        
        if response and "success" in response.text.lower():
            results["vulnerabilities"].append(f"Weak password accepted in change: {password}")
    
    return results

def otg_authn_008():
    """OTG-AUTHN-008: Testing for Weak Security Question/Answer"""
    banner("OTG-AUTHN-008: Testing Security Questions")
    results = {
        "questions_tested": [],
        "vulnerabilities": []
    }
    
    # Check if security questions are enabled
    response = http_request("GET", RESET_PASSWORD_URL)
    if not response or "security question" not in response.text.lower():
        return {"status": "Security questions not implemented"}
    
    # Get username for testing
    data = {"username": TEST_USER[0]}
    response = http_request("POST", RESET_PASSWORD_URL, data=data)
    
    if not response or response.status_code != 200:
        return {"error": "Password reset request failed"}
    
    # Extract security question
    soup = BeautifulSoup(response.text, 'html.parser')
    question_label = soup.find('label', string=re.compile(r'security question', re.I))
    if not question_label:
        return {"error": "Security question not found"}
    
    question = question_label.text.strip().replace(':', '').strip()
    results["questions_tested"].append(question)
    
    # Test common answers
    if question in COMMON_SECURITY_QUESTIONS:
        answers = COMMON_SECURITY_QUESTIONS[question]
    else:
        answers = ["test", "answer", "123456", "password"]
    
    for answer in answers:
        data = {
            "username": TEST_USER[0],
            "answer": answer
        }
        response = http_request("POST", SECURITY_QUESTION_URL, data=data)
        
        if response and "reset token" in response.text.lower():
            results["vulnerabilities"].append(f"Security question bypassed with: {answer}")
            break
    
    # Test brute force
    for i in range(1, 11):  # Try 10 random answers
        random_answer = generate_random_string(6)
        data = {
            "username": TEST_USER[0],
            "answer": random_answer
        }
        response = http_request("POST", SECURITY_QUESTION_URL, data=data)
        
        if response and "reset token" in response.text.lower():
            results["vulnerabilities"].append(f"Security question bypassed with random answer: {random_answer}")
            break
    
    return results

def otg_authn_009():
    """OTG-AUTHN-009: Testing for Weak Password Change/Reset Functionalities"""
    banner("OTG-AUTHN-009: Testing Password Reset")
    results = {
        "tests": [],
        "vulnerabilities": []
    }
    
    # 1. Test password reset without authentication
    # Request reset for test user
    data = {"username": TEST_USER[0]}
    response = http_request("POST", RESET_PASSWORD_URL, data=data)
    
    if not response or response.status_code != 200:
        return {"error": "Password reset request failed"}
    
    # Check if reset token is exposed in response
    if "token=" in response.text:
        token_match = re.search(r'token=([a-f0-9]{32})', response.text)
        if token_match:
            token = token_match.group(1)
            results["vulnerabilities"].append(f"Password reset token exposed: {token}")
    
    # 2. Test token predictability
    predictable_token = "000000"
    reset_url = f"{RESET_PASSWORD_URL}?token={predictable_token}"
    response = http_request("GET", reset_url)
    if response and "Reset Password" in response.text:
        results["vulnerabilities"].append("Predictable password reset token accepted")
    
    # 3. Test token expiration
    # (Would need a valid token to test expiration, which we don't have)
    
    # 4. Test token reuse
    # (Would require capturing a valid token)
    
    # 5. Test account takeover via email change
    # First login as test user
    login_data = {"username": TEST_USER[0], "password": TEST_USER[1]}
    login_response = http_request("POST", LOGIN_URL, data=login_data)
    cookies = get_session_cookies(login_response) if login_response else None
    
    if cookies:
        # Access profile page
        profile_page = http_request("GET", PROFILE_URL, cookies=cookies)
        if profile_page:
            csrf_token = extract_csrf_token(profile_page.text)
            new_email = f"attacker_{generate_random_string(4)}@example.com"
            data = {
                "email": new_email,
                "csrf_token": csrf_token
            }
            response = http_request("POST", PROFILE_URL, data=data, cookies=cookies)
            
            if response and "success" in response.text.lower():
                # Now try to reset password using new email
                data = {"email": new_email}
                response = http_request("POST", RESET_PASSWORD_URL, data=data)
                
                if response and "reset link" in response.text.lower():
                    results["vulnerabilities"].append("Account takeover via email change")
    
    return results

def otg_authn_010():
    """OTG-AUTHN-010: Testing for Weaker Authentication in Alternative Channel"""
    banner("OTG-AUTHN-010: Testing Alternative Channels")
    results = {
        "channels_tested": [],
        "vulnerabilities": []
    }
    
    # Identify alternative channels (mobile API, etc.)
    alternative_channels = [
        {"name": "Mobile API", "url": f"{TARGET_URL}/api/v1/login", "method": "POST"},
        {"name": "Web Services", "url": f"{TARGET_URL}/webservice/login", "method": "POST"},
        {"name": "Mobile Site", "url": f"{TARGET_URL}/m/login", "method": "POST"},
    ]
    
    for channel in alternative_channels:
        # Test if channel exists
        response = http_request("GET", channel['url'])
        if not response or response.status_code != 200:
            continue
        
        results["channels_tested"].append(channel['name'])
        
        # Test authentication with weak credentials
        data = {"username": "admin", "password": "admin"}
        response = http_request(channel['method'], channel['url'], data=data)
        
        if response and response.status_code == 200 and "authenticated" in response.text.lower():
            results["vulnerabilities"].append(f"Weak authentication in {channel['name']} channel")
        
        # Check if MFA is missing
        if "mfa" not in response.text.lower() and "two-factor" not in response.text.lower():
            results["vulnerabilities"].append(f"MFA missing in {channel['name']} channel")
    
    # Test if alternative channel has weaker session management
    for channel in alternative_channels:
        if not results["channels_tested"]:
            continue
        
        # Get session from main channel
        main_login = http_request("POST", LOGIN_URL, data={"username": TEST_USER[0], "password": TEST_USER[1]})
        main_cookies = get_session_cookies(main_login) if main_login else None
        
        if main_cookies:
            # Try to access alternative channel with main session
            response = http_request("GET", channel['url'], cookies=main_cookies)
            if response and response.status_code == 200:
                results["vulnerabilities"].append(f"Session accepted across channels: {channel['name']}")
    
    return results

# -----------------------------------------------------------
# Report Generation
# -----------------------------------------------------------
def generate_report(results, output_file="authentication_testing_report.md"):
    """Generate markdown report in SysReptor format."""
    md = "# Authentication Testing Report\n\n"
    md += f"**Target URL**: {TARGET_URL}\n"
    md += f"**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    
    # Summary of findings
    vulnerability_count = sum(1 for test in results.values() if "vulnerabilities" in test and test["vulnerabilities"])
    md += "## Executive Summary\n\n"
    md += f"**Total Tests**: {len(results)}\n"
    md += f"**Vulnerabilities Found**: {vulnerability_count}\n\n"
    
    # Detailed results
    test_order = [
        ("OTG-AUTHN-001", "Testing for Credentials Transported over an Encrypted Channel"),
        ("OTG-AUTHN-002", "Testing for Default Credentials"),
        ("OTG-AUTHN-003", "Testing for Weak Lockout Mechanism"),
        ("OTG-AUTHN-004", "Testing for Bypassing Authentication Schema"),
        ("OTG-AUTHN-005", "Test Remember Password Functionality"),
        ("OTG-AUTHN-006", "Testing for Browser Cache Weakness"),
        ("OTG-AUTHN-007", "Testing for Weak Password Policy"),
        ("OTG-AUTHN-008", "Testing for Weak Security Question/Answer"),
        ("OTG-AUTHN-009", "Testing for Weak Password Change or Reset Functionalities"),
        ("OTG-AUTHN-010", "Testing for Weaker Authentication in Alternative Channel")
    ]
    
    for test_id, test_name in test_order:
        if test_id not in results:
            continue
            
        md += f"## {test_id}: {test_name}\n\n"
        test_data = results[test_id]
        
        # Show vulnerabilities first
        if "vulnerabilities" in test_data and test_data["vulnerabilities"]:
            md += "### 🚨 Vulnerabilities\n"
            for vuln in test_data["vulnerabilities"]:
                md += f"- {vuln}\n"
            md += "\n"
        else:
            md += "**Status**: ✅ No vulnerabilities found\n\n"
        
        # Show detailed test results
        md += "### Detailed Results\n"
        
        # Special handling for different test types
        if test_id == "OTG-AUTHN-001":
            md += f"- Login encrypted: {'✅ Yes' if test_data.get('login_encrypted') else '❌ No'}\n"
            for endpoint, status in test_data.get("other_auth_endpoints", {}).items():
                md += f"- {endpoint}: {'🔒 HTTPS' if status == 'HTTPS' else '⚠️ HTTP'}\n"
        
        elif test_id == "OTG-AUTHN-002":
            if test_data.get("vulnerable_accounts"):
                md += f"- **Vulnerable accounts**: {', '.join(test_data['vulnerable_accounts'])}\n"
            for cred in test_data.get("tested_credentials", []):
                status = "✅ Success" if cred["success"] else "❌ Failed"
                md += f"- `{cred['username']}/{cred['password']}`: {status}\n"
        
        elif test_id == "OTG-AUTHN-003":
            if test_data.get("lockout_threshold"):
                md += f"- Account locked after {test_data['lockout_threshold']} attempts\n"
            else:
                md += "- No lockout detected\n"
            md += f"- Failed attempts tested: {test_data.get('failed_attempts', 0)}\n"
        
        elif test_id == "OTG-AUTHN-004":
            for method in test_data.get("methods_tested", []):
                md += f"- Tested: {method}\n"
        
        elif test_id == "OTG-AUTHN-005":
            for name, details in test_data.get("cookie_analysis", {}).items():
                flags = []
                if details["secure"]: flags.append("Secure")
                if details["httponly"]: flags.append("HttpOnly")
                if details["samesite"]: flags.append(f"SameSite={details['samesite']}")
                
                flag_status = ", ".join(flags) if flags else "⚠️ No security flags"
                md += f"- Cookie `{name}`: {flag_status}\n"
        
        elif test_id == "OTG-AUTHN-006":
            for header, value in test_data.get("cache_headers", {}).items():
                md += f"- `{header}`: `{value}`\n"
        
        elif test_id == "OTG-AUTHN-007":
            for pw_test in test_data.get("tested_passwords", []):
                status = "✅ Accepted" if pw_test["accepted"] else "❌ Rejected"
                md += f"- Password `{pw_test['password']}`: {status}\n"
        
        elif test_id == "OTG-AUTHN-008":
            for question in test_data.get("questions_tested", []):
                md += f"- Security question: `{question}`\n"
        
        elif test_id == "OTG-AUTHN-009":
            for test in test_data.get("tests", []):
                md += f"- {test}\n"
        
        elif test_id == "OTG-AUTHN-010":
            if test_data.get("channels_tested"):
                md += f"- Tested channels: {', '.join(test_data['channels_tested'])}\n"
            else:
                md += "- No alternative channels found\n"
        
        # Add raw data for reference
        md += "\n#### Raw Test Data\n```json\n"
        md += json.dumps(test_data, indent=2)
        md += "\n```\n\n"
    
    # Write report
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(md)
    
    return output_file

# -----------------------------------------------------------
# Main Execution
# -----------------------------------------------------------
def main():
    """Main function to run all tests and generate report."""
    results = {}
    
    # Run all tests
    results["OTG-AUTHN-001"] = otg_authn_001()
    results["OTG-AUTHN-002"] = otg_authn_002()
    results["OTG-AUTHN-003"] = otg_authn_003()
    results["OTG-AUTHN-004"] = otg_authn_004()
    results["OTG-AUTHN-005"] = otg_authn_005()
    results["OTG-AUTHN-006"] = otg_authn_006()
    results["OTG-AUTHN-007"] = otg_authn_007()
    results["OTG-AUTHN-008"] = otg_authn_008()
    results["OTG-AUTHN-009"] = otg_authn_009()
    results["OTG-AUTHN-010"] = otg_authn_010()
    
    # Generate report
    report_file = generate_report(results)
    print(f"\nReport generated: {report_file}")

if __name__ == "__main__":
    main()