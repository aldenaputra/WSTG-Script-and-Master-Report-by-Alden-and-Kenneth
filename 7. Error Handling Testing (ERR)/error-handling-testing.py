#!/usr/bin/env python3
"""
OWASP Error Handling Testing Toolkit
Covers OTG-ERR-001 and OTG-ERR-002
Outputs results in SysReptor-compatible markdown format.
"""

import requests
import re
import json
import random
import string
from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# -----------------------------------------------------------
# Configuration
# -----------------------------------------------------------
TARGET_URL = "http://localhost:8080"  # Change to your target URL
TEST_ENDPOINTS = [
    f"{TARGET_URL}/users/",          # Will trigger 404 if ID not provided
    f"{TARGET_URL}/products/",       # Will trigger 404 if ID not provided
    f"{TARGET_URL}/api/v1/data",     # Might trigger 400 for invalid input
    f"{TARGET_URL}/admin/",          # Might trigger 403 for unauthorized
    f"{TARGET_URL}/search?query=",   # Might trigger 500 with invalid input
]

# Test parameters for triggering errors
TEST_PARAMETERS = {
    "id": ["'", "0", "999999", "-1", "null", "undefined", "1' OR '1'='1"],
    "limit": ["-1", "0", "1000000", "'", "true", "false"],
    "page": ["-1", "0", "999999", "'", "null"],
    "query": ["'", "\"", "<script>", "{{7*7}}", "| cat /etc/passwd"],
    "sort": ["'; DROP TABLE users;--", "invalid_column", "ASC; SELECT * FROM users"],
}

# Sensitive patterns to look for in error responses
SENSITIVE_PATTERNS = [
    r"(\/etc\/passwd)",  # Linux password file
    r"(C:\\Windows\\system32\\drivers\\etc\\hosts)",  # Windows hosts file
    r"(database\.yml|\.env)",  # Configuration files
    r"(ssh-rsa|BEGIN RSA PRIVATE KEY)",  # SSH keys
    r"(aws_access_key_id|aws_secret_access_key)",  # AWS credentials
    r"(DB_USERNAME|DB_PASSWORD)",  # Database credentials
    r"(stack trace:)",  # Stack traces
    r"(at \w+\.\w+\(\))",  # Java/C# stack trace lines
    r"(vendor/\w+/\w+)",  # PHP file paths
    r"(Traceback \(most recent call last\))",  # Python stack traces
]

# -----------------------------------------------------------
# Utility Functions
# -----------------------------------------------------------
def banner(msg):
    """Print banner message."""
    print("\n" + "=" * 70)
    print(f"  {msg}")
    print("=" * 70)

def http_request(method, url, params=None, data=None):
    """Generic HTTP request function that returns response and error info."""
    try:
        if method.upper() == "GET":
            response = requests.get(url, params=params, timeout=10, verify=False)
        else:
            response = requests.post(url, params=params, data=data, timeout=10, verify=False)
        
        return {
            "url": response.url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text,
            "error": None
        }
    except requests.RequestException as e:
        return {
            "url": url,
            "status_code": None,
            "error": str(e)
        }

def find_sensitive_info(content):
    """Search for sensitive information patterns in content."""
    findings = []
    for pattern in SENSITIVE_PATTERNS:
        matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            # Capture context around the match
            start = max(0, match.start() - 50)
            end = min(len(content), match.end() + 50)
            context = content[start:end].replace("\n", " ").replace("\r", " ")
            
            findings.append({
                "pattern": pattern,
                "match": match.group(),
                "context": context
            })
    return findings

def generate_test_cases(endpoint):
    """Generate test cases for a given endpoint."""
    test_cases = []
    
    # Test with invalid resource IDs
    if re.search(r'/users/|/products/', endpoint):
        for test_id in TEST_PARAMETERS["id"]:
            test_url = endpoint + test_id
            test_cases.append({
                "url": test_url,
                "method": "GET",
                "params": None,
                "description": f"Testing invalid ID: {test_id}"
            })
    
    # Test with invalid query parameters
    if "?" in endpoint:
        base_url, query = endpoint.split("?", 1)
        for param, values in TEST_PARAMETERS.items():
            for value in values:
                test_url = f"{base_url}?{param}={value}"
                test_cases.append({
                    "url": test_url,
                    "method": "GET",
                    "params": None,
                    "description": f"Testing param '{param}' with value '{value}'"
                })
    
    # Test with invalid POST data
    if "/api/" in endpoint:
        for param, values in TEST_PARAMETERS.items():
            for value in values:
                test_cases.append({
                    "url": endpoint,
                    "method": "POST",
                    "params": {param: value},
                    "description": f"Testing POST param '{param}' with value '{value}'"
                })
    
    # Add a test for non-existent endpoint
    if not test_cases:
        test_url = endpoint + ''.join(random.choices(string.ascii_letters, k=10))
        test_cases.append({
            "url": test_url,
            "method": "GET",
            "params": None,
            "description": "Testing non-existent resource"
        })
    
    return test_cases

# -----------------------------------------------------------
# Test Functions
# -----------------------------------------------------------
def otg_err_001():
    """OTG-ERR-001: Analysis of Error Codes"""
    banner("OTG-ERR-001: Testing Error Codes")
    results = {
        "endpoints_tested": [],
        "error_responses": {},
        "vulnerabilities": []
    }
    
    for endpoint in TEST_ENDPOINTS:
        endpoint_results = {
            "url": endpoint,
            "test_cases": [],
            "sensitive_info_found": False
        }
        
        test_cases = generate_test_cases(endpoint)
        for test_case in test_cases:
            response = http_request(test_case["method"], test_case["url"], params=test_case.get("params"))
            
            # Skip successful responses
            if response.get("status_code") and 200 <= response["status_code"] < 300:
                continue
                
            test_result = {
                "description": test_case["description"],
                "request": {
                    "method": test_case["method"],
                    "url": test_case["url"],
                    "params": test_case.get("params")
                },
                "response": response
            }
            
            # Check for sensitive information
            if response.get("body"):
                sensitive_info = find_sensitive_info(response["body"])
                if sensitive_info:
                    test_result["sensitive_info"] = sensitive_info
                    endpoint_results["sensitive_info_found"] = True
                    results["vulnerabilities"].append(
                        f"Sensitive information in error response for {test_case['url']}"
                    )
            
            endpoint_results["test_cases"].append(test_result)
        
        results["endpoints_tested"].append(endpoint_results)
    
    return results

def otg_err_002():
    """OTG-ERR-002: Analysis of Stack Traces"""
    banner("OTG-ERR-002: Testing Stack Traces")
    results = {
        "stack_traces_found": [],
        "vulnerabilities": []
    }
    
    # Test cases designed to trigger server errors
    error_triggers = [
        # SQL Injection attempts
        {"url": f"{TARGET_URL}/users/1'", "method": "GET"},
        {"url": f"{TARGET_URL}/products/1 OR 1=1--", "method": "GET"},
        {"url": f"{TARGET_URL}/search", "method": "GET", "params": {"query": "' OR SLEEP(5)--"}},
        
        # Path traversal
        {"url": f"{TARGET_URL}/files/../../../../etc/passwd", "method": "GET"},
        
        # Command injection
        {"url": f"{TARGET_URL}/ping?ip=127.0.0.1;id", "method": "GET"},
        
        # Invalid content types
        {"url": f"{TARGET_URL}/api/data", "method": "POST", 
         "headers": {"Content-Type": "application/invalid"}, "data": "invalid"},
        
        # Large payloads
        {"url": f"{TARGET_URL}/api/upload", "method": "POST", 
         "data": "A" * 10000000},  # 10MB payload
    ]
    
    for test_case in error_triggers:
        try:
            if test_case["method"] == "GET":
                response = requests.get(test_case["url"], params=test_case.get("params"), 
                                     headers=test_case.get("headers"), timeout=10, verify=False)
            else:
                response = requests.post(test_case["url"], params=test_case.get("params"), 
                                      data=test_case.get("data"), headers=test_case.get("headers"), 
                                      timeout=10, verify=False)
            
            result = {
                "url": response.url,
                "status_code": response.status_code,
                "body": response.text,
                "error": None
            }
        except requests.RequestException as e:
            result = {
                "url": test_case["url"],
                "status_code": None,
                "error": str(e)
            }
        
        # Check for stack traces
        stack_trace_found = False
        sensitive_info = []
        
        if result.get("body"):
            # Check for common stack trace indicators
            stack_trace_indicators = [
                "stack trace",
                "at java.",
                "at org.",
                "at com.",
                "Traceback (most recent call last)",
                "in <module>",
                "Exception in thread",
                "#0",
                "vendor/",
                "node_modules/",
                "File: ",
                "Line: "
            ]
            
            for indicator in stack_trace_indicators:
                if indicator in result["body"]:
                    stack_trace_found = True
                    break
            
            # Look for sensitive information
            sensitive_info = find_sensitive_info(result["body"])
        
        # Save results if we found a stack trace
        if stack_trace_found:
            stack_trace_result = {
                "test_case": test_case,
                "response": result,
                "sensitive_info": sensitive_info
            }
            results["stack_traces_found"].append(stack_trace_result)
            
            if sensitive_info:
                results["vulnerabilities"].append(
                    f"Sensitive information in stack trace for {test_case['url']}"
                )
    
    return results

# -----------------------------------------------------------
# Report Generation
# -----------------------------------------------------------
def generate_report(results, output_file="error_handling_report.md"):
    """Generate markdown report in SysReptor format."""
    md = "# Error Handling Testing Report\n\n"
    md += f"**Target URL**: {TARGET_URL}\n"
    md += f"**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    
    # Summary of findings
    vulnerability_count = 0
    if "vulnerabilities" in results["OTG-ERR-001"]:
        vulnerability_count += len(results["OTG-ERR-001"]["vulnerabilities"])
    if "vulnerabilities" in results["OTG-ERR-002"]:
        vulnerability_count += len(results["OTG-ERR-002"]["vulnerabilities"])
    
    md += "## Executive Summary\n\n"
    md += f"**Total Tests**: 2\n"
    md += f"**Vulnerabilities Found**: {vulnerability_count}\n\n"
    
    # Detailed results
    md += "## OTG-ERR-001: Analysis of Error Codes\n\n"
    err001 = results["OTG-ERR-001"]
    
    # Show vulnerabilities first
    if "vulnerabilities" in err001 and err001["vulnerabilities"]:
        md += "### 🚨 Vulnerabilities\n"
        for vuln in err001["vulnerabilities"]:
            md += f"- {vuln}\n"
        md += "\n"
    else:
        md += "**Status**: ✅ No vulnerabilities found\n\n"
    
    # Show detailed test results
    md += "### Detailed Results\n"
    md += f"**Endpoints Tested**: {len(err001['endpoints_tested'])}\n\n"
    
    for endpoint in err001["endpoints_tested"]:
        md += f"#### Endpoint: `{endpoint['url']}`\n"
        md += f"**Sensitive Info Found**: {'❌ Yes' if endpoint['sensitive_info_found'] else '✅ No'}\n"
        md += f"**Test Cases**: {len(endpoint['test_cases'])}\n"
        
        # Show sample of test cases
        if endpoint["test_cases"]:
            md += "##### Sample Error Responses:\n"
            for test_case in endpoint["test_cases"][:3]:  # Show first 3
                md += f"- **Test**: {test_case['description']}\n"
                md += f"  - Status: {test_case['response'].get('status_code', 'Error')}\n"
                if "sensitive_info" in test_case:
                    md += f"  - Sensitive Info: Found {len(test_case['sensitive_info'])} items\n"
        md += "\n"
    
    md += "\n## OTG-ERR-002: Analysis of Stack Traces\n\n"
    err002 = results["OTG-ERR-002"]
    
    # Show vulnerabilities first
    if "vulnerabilities" in err002 and err002["vulnerabilities"]:
        md += "### 🚨 Vulnerabilities\n"
        for vuln in err002["vulnerabilities"]:
            md += f"- {vuln}\n"
        md += "\n"
    else:
        md += "**Status**: ✅ No vulnerabilities found\n\n"
    
    # Show detailed test results
    md += "### Detailed Results\n"
    md += f"**Stack Traces Found**: {len(err002['stack_traces_found'])}\n\n"
    
    if err002["stack_traces_found"]:
        md += "##### Stack Traces Found:\n"
        for trace in err002["stack_traces_found"][:3]:  # Show first 3
            md += f"- **URL**: `{trace['test_case']['url']}`\n"
            md += f"  - Status: {trace['response'].get('status_code', 'Error')}\n"
            if "sensitive_info" in trace and trace["sensitive_info"]:
                md += f"  - Sensitive Info: Found {len(trace['sensitive_info'])} items\n"
                # Show one sample sensitive info
                sample = trace["sensitive_info"][0]
                md += f"  - Sample: `{sample['match']}` in context: `{sample['context']}`\n"
        if len(err002["stack_traces_found"]) > 3:
            md += f"- ... and {len(err002['stack_traces_found'])-3} more stack traces\n"
    
    # Add raw data for reference
    md += "\n### Raw Test Data\n"
    md += "```json\n"
    md += json.dumps(results, indent=2)
    md += "\n```\n"
    
    # Write report
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(md)
    
    return output_file

# -----------------------------------------------------------
# Main Execution
# -----------------------------------------------------------
def main():
    """Main function to run all tests and generate report."""
    results = {
        "OTG-ERR-001": otg_err_001(),
        "OTG-ERR-002": otg_err_002()
    }
    
    # Generate report
    report_file = generate_report(results)
    print(f"\nReport generated: {report_file}")

if __name__ == "__main__":
    main()