#!/usr/bin/env python3
"""
OWASP Session Management Testing Toolkit
Covers OTG-SESS-001 to OTG-SESS-008
Outputs results in SysReptor-compatible markdown format.
"""

import requests
import re
import json
import random
import string
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# -----------------------------------------------------------
# Configuration
# -----------------------------------------------------------
TARGET_URL = "http://localhost:8080"  # Change to your target URL
LOGIN_URL = f"{TARGET_URL}/login.php"
LOGOUT_URL = f"{TARGET_URL}/logout.php"
PROFILE_URL = f"{TARGET_URL}/profile.php"
SENSITIVE_ACTION_URL = f"{TARGET_URL}/change_email.php"  # Example sensitive action

# User credentials
USER_CREDENTIALS = ("testuser", "Password123!")

# Session timeout threshold (in seconds)
SESSION_TIMEOUT = 900  # 15 minutes

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

def login_user(username, password):
    """Login to application and return session cookies."""
    data = {"username": username, "password": password}
    response = http_request("POST", LOGIN_URL, data=data)
    if response and response.status_code == 200 and "logout" in response.text.lower():
        return requests.utils.dict_from_cookiejar(response.cookies)
    return None

def extract_csrf_token(html_content):
    """Extract CSRF token from HTML content."""
    soup = BeautifulSoup(html_content, 'html.parser')
    csrf_input = soup.find('input', {'name': 'csrf_token'})
    return csrf_input['value'] if csrf_input else None

def analyze_cookie(cookie_value):
    """Analyze cookie for common vulnerabilities."""
    analysis = {"length": len(cookie_value)}
    
    # Check if cookie is predictable
    if cookie_value.isdigit():
        analysis["predictable"] = True
    elif len(set(cookie_value)) < 5:  # Low entropy
        analysis["predictable"] = True
    else:
        analysis["predictable"] = False
    
    # Check encoding
    if "%" in cookie_value:
        analysis["encoded"] = True
    else:
        analysis["encoded"] = False
    
    return analysis

def get_cookie_attributes(response, cookie_name):
    """Get security attributes of a cookie."""
    cookie = response.cookies.get(cookie_name)
    if not cookie:
        return None
    
    return {
        "secure": cookie.secure,
        "httponly": "HttpOnly" in str(cookie),
        "samesite": "None",
        "domain": cookie.domain,
        "path": cookie.path,
        "expires": cookie.expires
    }

# -----------------------------------------------------------
# Test Functions
# -----------------------------------------------------------
def otg_sess_001():
    """OTG-SESS-001: Testing for Bypassing Session Management Schema"""
    banner("OTG-SESS-001: Testing Session Management Bypass")
    results = {
        "session_manipulation_tests": [],
        "vulnerabilities": []
    }
    
    # Test 1: Session ID prediction/brute force
    # First get a valid session ID
    valid_cookies = login_user(*USER_CREDENTIALS)
    if not valid_cookies:
        return {"error": "Login failed"}
    
    session_cookie_name = list(valid_cookies.keys())[0]
    valid_session_id = valid_cookies[session_cookie_name]
    
    # Analyze the session ID
    session_analysis = analyze_cookie(valid_session_id)
    results["session_analysis"] = session_analysis
    
    if session_analysis["predictable"]:
        results["vulnerabilities"].append("Session ID is predictable")
    
    # Test 2: Session ID manipulation
    # Try to modify session ID
    modified_session_id = valid_session_id[:-4] + "AAAA"  # Change last 4 characters
    manipulated_cookies = {session_cookie_name: modified_session_id}
    
    response = http_request("GET", PROFILE_URL, cookies=manipulated_cookies)
    if response and "Welcome" in response.text:
        results["vulnerabilities"].append("Session ID manipulation possible - invalid session accepted")
    
    # Test 3: Accepting arbitrary session IDs
    random_session_id = ''.join(random.choices(string.ascii_letters + string.digits, k=len(valid_session_id)))
    random_cookies = {session_cookie_name: random_session_id}
    
    response = http_request("GET", PROFILE_URL, cookies=random_cookies)
    if response and "Welcome" in response.text:
        results["vulnerabilities"].append("Arbitrary session IDs accepted")
    
    # Test 4: Session ID in URL
    response = http_request("GET", f"{PROFILE_URL}?session_id={valid_session_id}")
    if response and "Welcome" in response.text:
        results["vulnerabilities"].append("Session ID accepted via URL parameter")
    
    return results

def otg_sess_002():
    """OTG-SESS-002: Testing for Cookies Attributes"""
    banner("OTG-SESS-002: Testing Cookie Attributes")
    results = {
        "cookies_analyzed": {},
        "vulnerabilities": []
    }
    
    # Login to get cookies
    response = http_request("POST", LOGIN_URL, data={"username": USER_CREDENTIALS[0], "password": USER_CREDENTIALS[1]})
    if not response or response.status_code != 200:
        return {"error": "Login failed"}
    
    # Analyze all cookies
    for cookie in response.cookies:
        cookie_name = cookie.name
        attributes = {
            "secure": cookie.secure,
            "httponly": "HttpOnly" in str(cookie),
            "samesite": "None",
            "domain": cookie.domain,
            "path": cookie.path,
            "expires": cookie.expires
        }
        
        results["cookies_analyzed"][cookie_name] = attributes
        
        # Check for vulnerabilities
        if "session" in cookie_name.lower() and not attributes["secure"]:
            results["vulnerabilities"].append(f"Session cookie {cookie_name} missing Secure flag")
        
        if "session" in cookie_name.lower() and not attributes["httponly"]:
            results["vulnerabilities"].append(f"Session cookie {cookie_name} missing HttpOnly flag")
        
        if attributes["samesite"].lower() not in ["lax", "strict"]:
            results["vulnerabilities"].append(f"Cookie {cookie_name} has weak SameSite policy: {attributes['samesite']}")
        
        if attributes["domain"] and "example.com" not in attributes["domain"]:  # Adjust for your target
            results["vulnerabilities"].append(f"Cookie {cookie_name} has overly broad domain: {attributes['domain']}")
    
    # Check if session cookie is persistent
    session_cookie = next((c for c in response.cookies if "session" in c.name.lower()), None)
    if session_cookie and session_cookie.expires:
        results["vulnerabilities"].append("Session cookie is persistent (has expiration date)")
    
    return results

def otg_sess_003():
    """OTG-SESS-003: Testing for Session Fixation"""
    banner("OTG-SESS-003: Testing Session Fixation")
    results = {
        "session_id_before_login": "",
        "session_id_after_login": "",
        "vulnerable": False
    }
    
    # Step 1: Get a session before login
    response = http_request("GET", LOGIN_URL)
    if not response:
        return {"error": "Failed to access login page"}
    
    # Extract session cookie
    session_cookie = next((c for c in response.cookies if "session" in c.name.lower()), None)
    if not session_cookie:
        return {"error": "No session cookie found"}
    
    session_cookie_name = session_cookie.name
    session_id_before = session_cookie.value
    results["session_id_before_login"] = session_id_before
    
    # Step 2: Login with the same session
    cookies = {session_cookie_name: session_id_before}
    login_response = http_request("POST", LOGIN_URL, data={
        "username": USER_CREDENTIALS[0],
        "password": USER_CREDENTIALS[1]
    }, cookies=cookies)
    
    if not login_response or login_response.status_code != 200:
        return {"error": "Login failed"}
    
    # Step 3: Check if session ID changed
    session_id_after = login_response.cookies.get(session_cookie_name)
    results["session_id_after_login"] = session_id_after
    
    # Step 4: Verify if we're logged in with the original session
    profile_response = http_request("GET", PROFILE_URL, cookies=cookies)
    if profile_response and "Welcome" in profile_response.text:
        results["vulnerable"] = True
        results["vulnerabilities"] = ["Session fixation vulnerability found"]
    
    return results

def otg_sess_004():
    """OTG-SESS-004: Testing for Exposed Session Variables"""
    banner("OTG-SESS-004: Testing Exposed Session Variables")
    results = {
        "exposed_variables": [],
        "vulnerabilities": []
    }
    
    # Login to get authenticated session
    cookies = login_user(*USER_CREDENTIALS)
    if not cookies:
        return {"error": "Login failed"}
    
    # Access various pages and look for session data
    pages_to_check = [
        PROFILE_URL,
        f"{TARGET_URL}/dashboard.php",
        f"{TARGET_URL}/account.php",
        f"{TARGET_URL}/settings.php"
    ]
    
    sensitive_patterns = [
        r'session["\']?[_:]?(id|token)\s*=\s*["\']?([^\s"\']+)',
        r'user["\']?[_:]?(id|token)\s*=\s*["\']?([^\s"\']+)',
        r'auth["\']?[_:]?(token|key)\s*=\s*["\']?([^\s"\']+)',
        r'<input [^>]*name=["\']?(session_?id|token)["\']? [^>]*value=["\']?([^\s"\']+)',
        r'data-?session=["\']?([^\s"\']+)',
        r'window\.session(?:Id|Token)\s*=\s*["\']?([^\s"\']+)'
    ]
    
    for page_url in pages_to_check:
        response = http_request("GET", page_url, cookies=cookies)
        if not response:
            continue
            
        content = response.text
        
        # Check HTML content
        for pattern in sensitive_patterns:
            matches = re.findall(pattern, content, re.I)
            for match in matches:
                if isinstance(match, tuple):
                    value = match[1]
                else:
                    value = match
                
                # Skip empty values
                if len(value) < 5:
                    continue
                    
                results["exposed_variables"].append({
                    "page": page_url,
                    "variable": value,
                    "context": content[content.find(value)-20:content.find(value)+20].replace("\n", " ")
                })
    
    # Check URL parameters
    response = http_request("GET", PROFILE_URL, cookies=cookies)
    if response and response.url:
        url_params = urlparse(response.url).query
        if "session" in url_params.lower() or "token" in url_params.lower():
            results["exposed_variables"].append({
                "page": PROFILE_URL,
                "variable": "URL parameters",
                "context": url_params
            })
    
    # Check for vulnerabilities
    if results["exposed_variables"]:
        results["vulnerabilities"].append("Session variables exposed in client-side code")
    
    return results

def otg_sess_005():
    """OTG-SESS-005: Testing for Cross Site Request Forgery (CSRF)"""
    banner("OTG-SESS-005: Testing CSRF Protection")
    results = {
        "forms_tested": [],
        "vulnerabilities": []
    }
    
    # Login to get authenticated session
    cookies = login_user(*USER_CREDENTIALS)
    if not cookies:
        return {"error": "Login failed"}
    
    # Access a page with sensitive forms (e.g., change email)
    response = http_request("GET", SENSITIVE_ACTION_URL, cookies=cookies)
    if not response or response.status_code != 200:
        return {"error": f"Failed to access {SENSITIVE_ACTION_URL}"}
    
    # Parse forms on the page
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')
    
    for form in forms:
        form_data = {}
        form_action = form.get('action')
        if not form_action:
            continue
            
        # Make URL absolute
        if not form_action.startswith('http'):
            form_action = TARGET_URL + ('' if form_action.startswith('/') else '/') + form_action
        
        form_method = form.get('method', 'get').upper()
        
        # Extract form inputs
        for input_tag in form.find_all('input'):
            if input_tag.get('type') in ['submit', 'button']:
                continue
                
            name = input_tag.get('name')
            value = input_tag.get('value', '')
            
            if name:
                form_data[name] = value
        
        # Check if form has CSRF protection
        has_csrf = any('csrf' in key.lower() or 'token' in key.lower() for key in form_data.keys())
        results["forms_tested"].append({
            "action": form_action,
            "method": form_method,
            "has_csrf": has_csrf
        })
        
        # Test without CSRF token if form should have one
        if has_csrf:
            # Remove CSRF token
            modified_data = {k: v for k, v in form_data.items() if 'csrf' not in k.lower() and 'token' not in k.lower()}
            
            # Submit the form without CSRF token
            response = http_request(form_method, form_action, data=modified_data, cookies=cookies)
            
            if response and response.status_code == 200 and "success" in response.text.lower():
                results["vulnerabilities"].append(f"CSRF vulnerability in form at {form_action}")
    
    return results

def otg_sess_006():
    """OTG-SESS-006: Testing for Logout Functionality"""
    banner("OTG-SESS-006: Testing Logout Functionality")
    results = {
        "session_invalidation_tests": [],
        "vulnerabilities": []
    }
    
    # Login to get authenticated session
    cookies = login_user(*USER_CREDENTIALS)
    if not cookies:
        return {"error": "Login failed"}
    
    # Step 1: Perform logout
    logout_response = http_request("GET", LOGOUT_URL, cookies=cookies)
    if not logout_response:
        return {"error": "Logout request failed"}
    
    # Step 2: Try to access protected page after logout
    profile_response = http_request("GET", PROFILE_URL, cookies=cookies)
    
    # Check if we're still authenticated
    if profile_response and "Welcome" in profile_response.text:
        results["vulnerabilities"].append("Session not invalidated after logout")
        results["session_invalidation_tests"].append("Failed: Session still valid after logout")
    else:
        results["session_invalidation_tests"].append("Passed: Session invalidated after logout")
    
    # Step 3: Test back button after logout
    # First, login again
    cookies = login_user(*USER_CREDENTIALS)
    if not cookies:
        return {"error": "Re-login failed"}
    
    # Access a protected page
    http_request("GET", PROFILE_URL, cookies=cookies)
    
    # Perform logout
    http_request("GET", LOGOUT_URL, cookies=cookies)
    
    # Use back button (simulate by accessing the same page again with same cookies)
    back_response = http_request("GET", PROFILE_URL, cookies=cookies)
    
    if back_response and "Welcome" in back_response.text:
        results["vulnerabilities"].append("Back button allows access to protected pages after logout")
        results["session_invalidation_tests"].append("Failed: Back button allows access")
    else:
        results["session_invalidation_tests"].append("Passed: Back button blocked")
    
    # Step 4: Test session cookie removal
    session_cookie_name = list(cookies.keys())[0]
    if logout_response.cookies.get(session_cookie_name):
        # Check if cookie was set to expire
        logout_cookie = logout_response.cookies.get(session_cookie_name)
        if logout_cookie and logout_cookie.expires and logout_cookie.expires < time.time():
            results["session_invalidation_tests"].append("Passed: Session cookie expired on logout")
        else:
            results["vulnerabilities"].append("Session cookie not properly expired on logout")
            results["session_invalidation_tests"].append("Failed: Session cookie not expired")
    
    return results

def otg_sess_007():
    """OTG-SESS-007: Test Session Timeout"""
    banner("OTG-SESS-007: Testing Session Timeout")
    results = {
        "timeout_seconds": SESSION_TIMEOUT,
        "vulnerabilities": []
    }
    
    # Login to get authenticated session
    cookies = login_user(*USER_CREDENTIALS)
    if not cookies:
        return {"error": "Login failed"}
    
    # Wait for session to expire (plus buffer time)
    wait_time = SESSION_TIMEOUT + 60  # Session timeout + 1 minute
    print(f"Waiting {wait_time} seconds for session to expire...")
    time.sleep(wait_time)
    
    # Try to access protected page
    response = http_request("GET", PROFILE_URL, cookies=cookies)
    
    if response and "Welcome" in response.text:
        results["vulnerabilities"].append("Session timeout not enforced")
        results["status"] = "VULNERABLE"
    else:
        results["status"] = "SECURE"
    
    return results

def otg_sess_008():
    """OTG-SESS-008: Testing for Session Puzzling"""
    banner("OTG-SESS-008: Testing Session Puzzling")
    results = {
        "session_variables_tested": [],
        "vulnerabilities": []
    }
    
    # Login to get authenticated session
    cookies = login_user(*USER_CREDENTIALS)
    if not cookies:
        return {"error": "Login failed"}
    
    # Access a page that might store session variables
    response = http_request("GET", f"{TARGET_URL}/cart.php?item=123", cookies=cookies)
    if not response:
        return {"error": "Failed to access cart page"}
    
    # Extract session ID
    session_cookie_name = list(cookies.keys())[0]
    session_id = cookies[session_cookie_name]
    
    # Access a different page that might interpret session variables differently
    response = http_request("GET", f"{TARGET_URL}/checkout.php", cookies=cookies)
    if not response:
        return {"error": "Failed to access checkout page"}
    
    # Check if cart item is present (shouldn't be, if proper session isolation)
    if "item=123" in response.text:
        results["vulnerabilities"].append("Session puzzling vulnerability detected")
        results["session_variables_tested"].append({
            "from_page": "/cart.php",
            "to_page": "/checkout.php",
            "variable": "cart_item",
            "value": "123"
        })
    
    # Test with admin page if accessible
    admin_response = http_request("GET", f"{TARGET_URL}/admin", cookies=cookies)
    if admin_response and admin_response.status_code == 200:
        # Try to set a session variable on admin page
        http_request("GET", f"{TARGET_URL}/admin?set_debug=1", cookies=cookies)
        
        # Access user page and check if debug mode is enabled
        user_response = http_request("GET", PROFILE_URL, cookies=cookies)
        if user_response and "Debug Mode: ON" in user_response.text:
            results["vulnerabilities"].append("Session puzzling across privilege levels")
            results["session_variables_tested"].append({
                "from_page": "/admin",
                "to_page": PROFILE_URL,
                "variable": "debug_mode",
                "value": "1"
            })
    
    return results

# -----------------------------------------------------------
# Report Generation
# -----------------------------------------------------------
def generate_report(results, output_file="session_management_report.md"):
    """Generate markdown report in SysReptor format."""
    md = "# Session Management Testing Report\n\n"
    md += f"**Target URL**: {TARGET_URL}\n"
    md += f"**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    
    # Summary of findings
    vulnerability_count = sum(1 for test in results.values() if "vulnerabilities" in test and test["vulnerabilities"])
    md += "## Executive Summary\n\n"
    md += f"**Total Tests**: {len(results)}\n"
    md += f"**Vulnerabilities Found**: {vulnerability_count}\n\n"
    
    # Detailed results
    test_order = [
        ("OTG-SESS-001", "Testing for Bypassing Session Management Schema"),
        ("OTG-SESS-002", "Testing for Cookies attributes"),
        ("OTG-SESS-003", "Testing for Session Fixation"),
        ("OTG-SESS-004", "Testing for Exposed Session Variables"),
        ("OTG-SESS-005", "Testing for Cross Site Request Forgery (CSRF)"),
        ("OTG-SESS-006", "Testing for logout functionality"),
        ("OTG-SESS-007", "Test Session Timeout"),
        ("OTG-SESS-008", "Testing for Session puzzling")
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
        if test_id == "OTG-SESS-001":
            if "session_analysis" in test_data:
                analysis = test_data["session_analysis"]
                md += f"- Session ID length: {analysis['length']}\n"
                md += f"- Predictable: {'❌ Yes' if analysis['predictable'] else '✅ No'}\n"
                md += f"- Encoded: {'✅ Yes' if analysis['encoded'] else '❌ No'}\n"
        
        elif test_id == "OTG-SESS-002":
            for cookie, attrs in test_data.get("cookies_analyzed", {}).items():
                flags = []
                if attrs["secure"]: flags.append("Secure")
                if attrs["httponly"]: flags.append("HttpOnly")
                if attrs["samesite"]: flags.append(f"SameSite={attrs['samesite']}")
                
                flag_status = ", ".join(flags) if flags else "⚠️ No security flags"
                md += f"- Cookie `{cookie}`: {flag_status}\n"
        
        elif test_id == "OTG-SESS-003":
            md += f"- Session ID before login: `{test_data.get('session_id_before_login', '')}`\n"
            md += f"- Session ID after login: `{test_data.get('session_id_after_login', '')}`\n"
            if test_data.get("vulnerable"):
                md += "- **VULNERABLE**: Session not regenerated after login\n"
        
        elif test_id == "OTG-SESS-004":
            if test_data.get("exposed_variables"):
                md += "#### Exposed Session Variables\n"
                for var in test_data["exposed_variables"][:3]:  # Show first 3
                    md += f"- On `{var['page']}`: `{var['variable']}` (Context: `{var['context']}`)\n"
                if len(test_data["exposed_variables"]) > 3:
                    md += f"- ... and {len(test_data['exposed_variables'])-3} more exposed variables\n"
        
        elif test_id == "OTG-SESS-005":
            for form in test_data.get("forms_tested", []):
                status = "✅ Protected" if form["has_csrf"] else "❌ Unprotected"
                md += f"- Form at `{form['action']}` ({form['method']}): {status}\n"
        
        elif test_id == "OTG-SESS-006":
            for test in test_data.get("session_invalidation_tests", []):
                if "Passed" in test:
                    md += f"- ✅ {test}\n"
                else:
                    md += f"- ❌ {test}\n"
        
        elif test_id == "OTG-SESS-007":
            if test_data.get("status") == "SECURE":
                md += f"- ✅ Session timeout enforced after {test_data['timeout_seconds']} seconds\n"
            else:
                if 'timeout_seconds' in test_data:
                    md += f"- ❌ Session timeout NOT enforced after {test_data['timeout_seconds']} seconds\n"
                else:
                    md += "- ❌ Session timeout NOT enforced (timeout value unknown)\n"
        
        elif test_id == "OTG-SESS-008":
            for test in test_data.get("session_variables_tested", []):
                md += f"- Session variable `{test['variable']}={test['value']}` carried from "
                md += f"`{test['from_page']}` to `{test['to_page']}`\n"
        
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
    results["OTG-SESS-001"] = otg_sess_001()
    results["OTG-SESS-002"] = otg_sess_002()
    results["OTG-SESS-003"] = otg_sess_003()
    results["OTG-SESS-004"] = otg_sess_004()
    results["OTG-SESS-005"] = otg_sess_005()
    results["OTG-SESS-006"] = otg_sess_006()
    results["OTG-SESS-007"] = otg_sess_007()
    results["OTG-SESS-008"] = otg_sess_008()
    
    # Generate report
    report_file = generate_report(results)
    print(f"\nReport generated: {report_file}")

if __name__ == "__main__":
    main()