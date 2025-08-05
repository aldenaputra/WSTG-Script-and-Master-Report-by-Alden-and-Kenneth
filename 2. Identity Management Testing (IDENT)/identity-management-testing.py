#!/usr/bin/env python3
"""
Identity Management Testing Toolkit
Covers OTG-IDENT-001 to OTG-IDENT-005
Outputs results in SysReptor-compatible markdown format.
"""

import requests
import re
import json
import random
import string
from datetime import datetime
from urllib.parse import urlparse

# -----------------------------------------------------------
# Configuration
# -----------------------------------------------------------
TARGET_URL = "http://localhost:8080"  # Change to your target URL
LOGIN_URL = f"{TARGET_URL}/login.php"
REGISTER_URL = f"{TARGET_URL}/register.php"  # Update if different
ADMIN_URL = f"{TARGET_URL}/admin/"  # Update if different
USER_MANAGEMENT_URL = f"{TARGET_URL}/admin/users"  # Update if different

# Test credentials
TEST_ADMIN = ("admin", "password123")
TEST_USER = ("testuser", "Password123!")

# Common username wordlist
COMMON_USERNAMES = [
    "admin", "administrator", "root", "test", "guest", "user", 
    "demo", "support", "info", "webmaster", "sysadmin"
]

# Common password wordlist
COMMON_PASSWORDS = [
    "password", "123456", "qwerty", "letmein", "welcome", 
    "admin123", "Password1", "passw0rd", "12345678", "abc123"
]

# -----------------------------------------------------------
# Utility Functions
# -----------------------------------------------------------
def banner(msg):
    """Print banner message."""
    print("\n" + "=" * 70)
    print(f"  {msg}")
    print("=" * 70)

def http_request(method, url, data=None, cookies=None, headers=None):
    """Generic HTTP request function."""
    try:
        if method.upper() == "GET":
            response = requests.get(url, params=data, cookies=cookies, headers=headers, timeout=10, verify=False)
        else:
            response = requests.post(url, data=data, cookies=cookies, headers=headers, timeout=10, verify=False)
        return response
    except requests.RequestException as e:
        print(f"HTTP error: {e}")
        return None

def extract_csrf_token(html_content):
    """Extract CSRF token from HTML content."""
    match = re.search(r'name="csrf_token" value="([^"]+)"', html_content)
    return match.group(1) if match else None

def generate_random_string(length=8):
    """Generate random string for test data."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# -----------------------------------------------------------
# Test Functions
# -----------------------------------------------------------
def otg_ident_001():
    """OTG-IDENT-001: Test Role Definitions"""
    banner("OTG-IDENT-001: Testing Role Definitions")
    results = {
        "role_checks": [],
        "vulnerabilities": []
    }
    
    # 1. Check if different roles exist
    roles = ["admin", "user", "guest", "manager", "supervisor"]
    found_roles = []
    
    login_page = http_request("GET", LOGIN_URL)
    if login_page and login_page.status_code == 200:
        page_content = login_page.text.lower()
        for role in roles:
            if role in page_content:
                found_roles.append(role)
    
    results["found_roles"] = found_roles
    results["role_checks"].append({
        "test": "Role references in login page",
        "found": bool(found_roles),
        "roles": found_roles
    })
    
    # 2. Attempt to access admin area as regular user
    # First, login as regular user
    session = requests.Session()
    login_response = http_request("POST", LOGIN_URL, 
                                 data={"username": TEST_USER[0], "password": TEST_USER[1]})
    
    if login_response and login_response.status_code == 200:
        cookies = session.cookies.get_dict()
        
        # Try to access admin area
        admin_response = http_request("GET", ADMIN_URL, cookies=cookies)
        
        if admin_response:
            results["role_checks"].append({
                "test": "Access admin area as regular user",
                "status": admin_response.status_code,
                "vulnerable": admin_response.status_code == 200
            })
            if admin_response.status_code == 200:
                results["vulnerabilities"].append(
                    "Regular user can access admin area - improper role definition"
                )
    
    # 3. Check for role privileges in HTML source
    if login_page:
        if "is_admin" in login_page.text or "role=" in login_page.text:
            results["vulnerabilities"].append(
                "Role information exposed in HTML source"
            )
    
    return results

def otg_ident_002():
    """OTG-IDENT-002: Test User Registration Process"""
    banner("OTG-IDENT-002: Testing User Registration Process")
    results = {
        "tests": [],
        "vulnerabilities": []
    }
    
    # Check if registration page exists
    reg_response = http_request("GET", REGISTER_URL)
    if not reg_response or reg_response.status_code != 200:
        return {"error": "Registration page not found"}
    
    # Extract CSRF token
    csrf_token = extract_csrf_token(reg_response.text)
    
    # Test 1: Weak password policy
    weak_passwords = ["123456", "password", "qwerty", "admin123"]
    for pwd in weak_passwords:
        user = f"test_{generate_random_string(4)}"
        data = {
            "username": user,
            "password": pwd,
            "email": f"{user}@example.com",
            "csrf_token": csrf_token
        }
        response = http_request("POST", REGISTER_URL, data=data)
        
        if response and response.status_code == 200:
            results["tests"].append({
                "test": f"Register with weak password: {pwd}",
                "success": True,
                "vulnerable": True
            })
            results["vulnerabilities"].append(
                f"Weak password '{pwd}' accepted during registration"
            )
        else:
            results["tests"].append({
                "test": f"Register with weak password: {pwd}",
                "success": False,
                "vulnerable": False
            })
    
    # Test 2: Insecure transmission (HTTP vs HTTPS)
    if TARGET_URL.startswith("http://"):
        results["vulnerabilities"].append(
            "Registration occurs over HTTP (insecure)"
        )
    
    # Test 3: Information leakage in error messages
    # Try to register with existing username
    data = {
        "username": TEST_USER[0],
        "password": "Test123!",
        "email": "existing@example.com",
        "csrf_token": csrf_token
    }
    response = http_request("POST", REGISTER_URL, data=data)
    
    if response and response.status_code == 200:
        if "already exists" in response.text or "already registered" in response.text:
            results["vulnerabilities"].append(
                "Error message discloses existing usernames during registration"
            )
    
    # Test 4: Lack of email verification
    invalid_emails = ["invalid", "test@", "test@invalid", "test@example."]
    for email in invalid_emails:
        user = f"test_{generate_random_string(4)}"
        data = {
            "username": user,
            "password": "ValidPass123!",
            "email": email,
            "csrf_token": csrf_token
        }
        response = http_request("POST", REGISTER_URL, data=data)
        
        if response and response.status_code == 200:
            results["tests"].append({
                "test": f"Register with invalid email: {email}",
                "success": True,
                "vulnerable": True
            })
            results["vulnerabilities"].append(
                f"Invalid email '{email}' accepted during registration"
            )
    
    return results

def otg_ident_003():
    """OTG-IDENT-003: Test Account Provisioning Process"""
    banner("OTG-IDENT-003: Testing Account Provisioning Process")
    results = {
        "tests": [],
        "vulnerabilities": []
    }
    
    # 1. Login as admin
    session = requests.Session()
    login_response = http_request("POST", LOGIN_URL, 
                                 data={"username": TEST_ADMIN[0], "password": TEST_ADMIN[1]})
    
    if not login_response or login_response.status_code != 200:
        return {"error": "Admin login failed"}
    
    cookies = session.cookies.get_dict()
    
    # 2. Access user management page
    user_mgmt_response = http_request("GET", USER_MANAGEMENT_URL, cookies=cookies)
    if not user_mgmt_response or user_mgmt_response.status_code != 200:
        return {"error": "User management page not accessible"}
    
    # Extract CSRF token
    csrf_token = extract_csrf_token(user_mgmt_response.text)
    
    # 3. Test creating user with excessive privileges
    new_user = f"poweruser_{generate_random_string(4)}"
    data = {
        "username": new_user,
        "password": "StrongPass123!",
        "email": f"{new_user}@example.com",
        "role": "admin",  # Attempt to set admin role
        "csrf_token": csrf_token
    }
    create_response = http_request("POST", USER_MANAGEMENT_URL, data=data, cookies=cookies)
    
    if create_response and create_response.status_code == 200:
        results["tests"].append({
            "test": "Create user with admin role",
            "success": True,
            "vulnerable": True
        })
        results["vulnerabilities"].append(
            "Able to create user with admin privileges through provisioning"
        )
    
    # 4. Test insecure transmission of account creation
    if TARGET_URL.startswith("http://"):
        results["vulnerabilities"].append(
            "Account provisioning occurs over HTTP (insecure)"
        )
    
    # 5. Test for lack of approval process
    # (We assume that if creation was successful, there was no approval needed)
    if "success" in results.get("tests", [{}])[0]:
        results["vulnerabilities"].append(
            "No approval process required for account provisioning"
        )
    
    return results

def otg_ident_004():
    """OTG-IDENT-004: Testing for Account Enumeration and Guessable User Accounts"""
    banner("OTG-IDENT-004: Testing Account Enumeration and Guessable Accounts")
    results = {
        "enumeration_tests": [],
        "guessable_accounts": [],
        "vulnerabilities": []
    }
    
    # 1. Account enumeration via login
    valid_user = TEST_USER[0]
    invalid_user = "nonexistentuser123"
    
    # Test with valid user + wrong password
    response_valid = http_request("POST", LOGIN_URL, 
                                 data={"username": valid_user, "password": "wrongpassword"})
    
    # Test with invalid user
    response_invalid = http_request("POST", LOGIN_URL, 
                                   data={"username": invalid_user, "password": "anypassword"})
    
    if response_valid and response_invalid:
        # Check response time difference
        time_diff = abs(response_valid.elapsed.total_seconds() - 
                       response_invalid.elapsed.total_seconds())
        if time_diff > 0.5:  # 500ms difference
            results["enumeration_tests"].append({
                "method": "Response timing",
                "difference": f"{time_diff:.3f} seconds",
                "vulnerable": True
            })
            results["vulnerabilities"].append(
                "Account enumeration possible via response timing"
            )
        
        # Check error message differences
        if response_valid.text != response_invalid.text:
            results["enumeration_tests"].append({
                "method": "Error message content",
                "vulnerable": True
            })
            results["vulnerabilities"].append(
                "Account enumeration possible via different error messages"
            )
    
    # 2. Account enumeration via password reset
    reset_url = f"{TARGET_URL}/reset-password"  # Update if different
    reset_response = http_request("POST", reset_url, 
                                 data={"email": f"{valid_user}@example.com"})
    
    if reset_response and reset_response.status_code == 200:
        if "exists" in reset_response.text or "sent" in reset_response.text:
            results["enumeration_tests"].append({
                "method": "Password reset messaging",
                "vulnerable": True
            })
            results["vulnerabilities"].append(
                "Account enumeration possible via password reset feature"
            )
    
    # 3. Check for guessable user accounts
    for username in COMMON_USERNAMES:
        response = http_request("POST", LOGIN_URL, 
                               data={"username": username, "password": "wrongpassword"})
        if response and "invalid password" in response.text.lower():
            results["guessable_accounts"].append(username)
            results["vulnerabilities"].append(
                f"Guessable account found: {username}"
            )
    
    return results

def otg_ident_005():
    """OTG-IDENT-005: Testing for Weak or Unenforced Username Policy"""
    banner("OTG-IDENT-005: Testing Username Policy")
    results = {
        "username_tests": [],
        "vulnerabilities": []
    }
    
    # 1. Test various username formats
    test_usernames = [
        "admin",  # Common username
        "a",  # Too short
        "username_with_very_long_string_over_thirty_characters",  # Too long
        "test@user",  # Special characters
        " testuser ",  # Leading/trailing spaces
        "USERNAME",  # All caps
        "username123",  # Alphanumeric
        "ユーザー名",  # Unicode
    ]
    
    # Get registration page to extract CSRF token
    reg_response = http_request("GET", REGISTER_URL)
    if not reg_response or reg_response.status_code != 200:
        return {"error": "Registration page not found"}
    
    csrf_token = extract_csrf_token(reg_response.text)
    
    for username in test_usernames:
        data = {
            "username": username,
            "password": "ValidPass123!",
            "email": f"{generate_random_string(6)}@example.com",
            "csrf_token": csrf_token
        }
        response = http_request("POST", REGISTER_URL, data=data)
        
        success = response and response.status_code == 200 and "success" in response.text.lower()
        results["username_tests"].append({
            "username": username,
            "accepted": success
        })
        
        # Check if policy is too weak
        if success and len(username) < 4:
            results["vulnerabilities"].append(
                f"Username policy too weak: '{username}' (too short) accepted"
            )
        
        if success and len(username) > 30:
            results["vulnerabilities"].append(
                f"Username policy too weak: '{username}' (too long) accepted"
            )
    
    # 2. Check for consistent username normalization
    normalized_tests = [
        ("TestUser", "testuser"),
        ("TESTUSER", "testuser"),
        (" Test User ", "testuser"),
    ]
    
    for original, normalized in normalized_tests:
        data = {
            "username": original,
            "password": "ValidPass123!",
            "email": f"{generate_random_string(6)}@example.com",
            "csrf_token": csrf_token
        }
        response = http_request("POST", REGISTER_URL, data=data)
        
        if response and response.status_code == 200:
            # Check if we can login with normalized version
            login_response = http_request("POST", LOGIN_URL, 
                                        data={"username": normalized, "password": "ValidPass123!"})
            if login_response and login_response.status_code == 200:
                results["vulnerabilities"].append(
                    f"Inconsistent username normalization: "
                    f"'{original}' registered but '{normalized}' can login"
                )
    
    # 3. Check for case sensitivity
    if "testuser" in [t["username"] for t in results["username_tests"]]:
        login_response1 = http_request("POST", LOGIN_URL, 
                                     data={"username": "testuser", "password": TEST_USER[1]})
        login_response2 = http_request("POST", LOGIN_URL, 
                                     data={"username": "TestUser", "password": TEST_USER[1]})
        
        if (login_response1 and login_response1.status_code == 200 and
            login_response2 and login_response2.status_code == 200):
            results["vulnerabilities"].append(
                "Username case sensitivity not enforced"
            )
    
    return results

# -----------------------------------------------------------
# Report Generation
# -----------------------------------------------------------
def generate_report(results, output_file="identity_management_report.md"):
    """Generate markdown report in SysReptor format."""
    md = "# Identity Management Testing Report\n\n"
    md += f"**Target URL**: {TARGET_URL}\n"
    md += f"**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    
    # Summary of findings
    vulnerability_count = sum(1 for test in results.values() if "vulnerabilities" in test and test["vulnerabilities"])
    md += "## Executive Summary\n\n"
    md += f"**Total Tests**: {len(results)}\n"
    md += f"**Vulnerabilities Found**: {vulnerability_count}\n\n"
    
    # Detailed results
    test_order = [
        ("OTG-IDENT-001", "Test Role Definitions"),
        ("OTG-IDENT-002", "Test User Registration Process"),
        ("OTG-IDENT-003", "Test Account Provisioning Process"),
        ("OTG-IDENT-004", "Testing for Account Enumeration and Guessable User Account"),
        ("OTG-IDENT-005", "Testing for Weak or unenforced username policy")
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
        if test_id == "OTG-IDENT-001":
            if "found_roles" in test_data:
                md += f"- **Roles found**: {', '.join(test_data['found_roles']) or 'None'}\n"
            for check in test_data.get("role_checks", []):
                status = "✅ Passed" if not check.get("vulnerable", False) else "❌ Failed"
                md += f"- {check['test']}: {status}\n"
        
        elif test_id == "OTG-IDENT-002":
            for test in test_data.get("tests", []):
                status = "✅ Passed" if not test.get("vulnerable", False) else "❌ Failed"
                md += f"- {test['test']}: {status}\n"
        
        elif test_id == "OTG-IDENT-003":
            for test in test_data.get("tests", []):
                status = "✅ Passed" if not test.get("vulnerable", False) else "❌ Failed"
                md += f"- {test['test']}: {status}\n"
        
        elif test_id == "OTG-IDENT-004":
            if test_data.get("guessable_accounts"):
                md += f"- **Guessable accounts**: {', '.join(test_data['guessable_accounts'])}\n"
            for test in test_data.get("enumeration_tests", []):
                status = "✅ Passed" if not test.get("vulnerable", False) else "❌ Failed"
                details = f"({test.get('difference', '')})" if "difference" in test else ""
                md += f"- {test['method']} {details}: {status}\n"
        
        elif test_id == "OTG-IDENT-005":
            md += "#### Username Policy Tests\n"
            for test in test_data.get("username_tests", []):
                status = "✅ Accepted" if test["accepted"] else "❌ Rejected"
                md += f"- `{test['username']}`: {status}\n"
        
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
    results["OTG-IDENT-001"] = otg_ident_001()
    results["OTG-IDENT-002"] = otg_ident_002()
    results["OTG-IDENT-003"] = otg_ident_003()
    results["OTG-IDENT-004"] = otg_ident_004()
    results["OTG-IDENT-005"] = otg_ident_005()
    
    # Generate report
    report_file = generate_report(results)
    print(f"\nReport generated: {report_file}")

if __name__ == "__main__":
    main()