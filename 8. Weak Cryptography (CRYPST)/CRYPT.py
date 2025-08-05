import requests
from bs4 import BeautifulSoup
from datetime import datetime
from urllib.parse import urlparse
import socket
import subprocess
import argparse
import logging
from typing import Callable, Dict, Any
import time
import random
import string
import re

# Setup logger
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


class DVWACryptTester:
    def __init__(self, base_url="http://localhost:8080", username="admin", password="password"):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.log_file = "dvwa_test_master_log.txt"
        self.host, self.port = self._extract_host_port()
        self.security_level = "low"
        self.report: Dict[str, Dict[str, Any]] = {}

    def write_log(self, entry: str):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"{timestamp} | {entry}\n")

    def _extract_host_port(self):
        parsed = urlparse(self.base_url)
        host = parsed.hostname or 'localhost'
        common_ports = [443, 8443]
        for port in common_ports:
            if self._is_https_port_open(host, port):
                logger.info(f"[+] Found open TLS port: {port}")
                return host, port
        logger.warning("[-] No HTTPS service found on common ports. Defaulting to 443.")
        return host, 443

    def _is_https_port_open(self, host, port):
        try:
            sock = socket.create_connection((host, port), timeout=2)
            sock.close()
            return True
        except:
            return False

    def login(self):
        login_url = f"{self.base_url}/login.php"
        security_url = f"{self.base_url}/security.php"
        resp = self.session.get(login_url)
        soup = BeautifulSoup(resp.text, 'html.parser')
        token_input = soup.find("input", {"name": "user_token"})
        token = token_input['value'] if token_input else ''
        data = {
            "username": self.username,
            "password": self.password,
            "Login": "Login",
            "user_token": token
        }
        login_resp = self.session.post(login_url, data=data)
        if "logout.php" in login_resp.text:
            self.write_log(f"[+] Login successful (Status: {login_resp.status_code})")
            logger.info("[+] Login successful")
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
            logger.info("[+] Security level set to low")
            return True
        else:
            self.write_log(f"[-] Login failed (Status: {login_resp.status_code})")
            logger.error("[-] Login failed")
            return False

    def run_test(self, test_id: str, test_name: str, func: Callable[[], None]):
        self.write_log(f"----- Starting {test_id} ({test_name}) -----")
        try:
            func()
        except Exception as e:
            self.write_log(f"[!] Error in {test_id}: {str(e)}")
            logger.error(f"[!] Error in {test_id}: {str(e)}")
        self.write_log(f"----- {test_id} Test Completed -----\n")

    def OTG_CRYPST_001(self):
        logger.info(f"[+] Running OTG_CRYPST_001 on {self.host}:{self.port}")
        self.write_log(f"[+] Starting OTG_CRYPST_001 on {self.host}:{self.port}")
        try:
            result = subprocess.run(
                ['nmap', '-p', str(self.port), '--script', 'ssl-enum-ciphers', self.host],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            output = result.stdout
            if "ssl-enum-ciphers" not in output:
                self.write_log("[-] OTG_CRYPST_001: SSL not detected or no cipher info returned.")
                return
            self.write_log("[+] OTG_CRYPST_001 Results:\n" + output)
            weak_indicators = ['SSLv2', 'SSLv3', 'TLSv1.0', 'RC4', 'EXP', 'NULL']
            for indicator in weak_indicators:
                if indicator in output:
                    self.write_log(f"[✓] Weak protocol/cipher found: {indicator}")
        except FileNotFoundError:
            self.write_log("[-] OTG_CRYPST_001: Nmap not found.")
        except Exception as e:
            self.write_log(f"[-] OTG_CRYPST_001: Error occurred - {str(e)}")

    def OTG_CRYPST_002(self):
        self.write_log("[*] Starting OTG_CRYPST_002: Testing for Padding Oracle")
        test_url = f"{self.base_url}/vulnerabilities/captcha/"
        try:
            junk1 = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
            junk2 = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
            headers1 = {"Cookie": f"PHPSESSID={junk1}"}
            headers2 = {"Cookie": f"PHPSESSID={junk2}"}
            r1 = self.session.get(test_url, headers=headers1)
            time.sleep(0.5)
            r2 = self.session.get(test_url, headers=headers2)
            if r1.status_code != r2.status_code or abs(len(r1.text) - len(r2.text)) > 50:
                self.write_log("[✓] POSSIBLE padding oracle detected (inconsistent response)")
            else:
                self.write_log("[-] No padding oracle behavior observed (DVWA not vulnerable)")
        except Exception as e:
            self.write_log(f"[!] Error in OTG_CRYPST_002: {str(e)}")

    def OTG_CRYPST_003(self):
        """Test for sensitive information sent via unencrypted channels"""
        self.write_log("[*] Starting OTG_CRYPST_003: Testing for Sensitive Info over Unencrypted Channels")
        
        try:
            # Check if the base URL is using HTTPS
            if not self.base_url.lower().startswith('https://'):
                self.write_log("[!] WARNING: Base URL is not using HTTPS")
            
            # Test pages that might contain sensitive information
            test_urls = [
                f"{self.base_url}/vulnerabilities/weak_id/",
                f"{self.base_url}/vulnerabilities/captcha/",
                f"{self.base_url}/vulnerabilities/sqli/",
                f"{self.base_url}/vulnerabilities/exec/",
                f"{self.base_url}/vulnerabilities/xss_s/",
                f"{self.base_url}/vulnerabilities/xss_r/",
            ]
            
            sensitive_data_found = False
            
            for url in test_urls:
                try:
                    response = self.session.get(url, allow_redirects=False)
                    
                    # Check if sensitive data is transmitted over HTTP
                    if response.url.startswith('http://'):
                        self.write_log(f"[✓] Sensitive data potentially transmitted over HTTP at: {url}")
                        sensitive_data_found = True
                    
                    # Check for forms submitting over HTTP
                    soup = BeautifulSoup(response.text, 'html.parser')
                    forms = soup.find_all('form')
                    for form in forms:
                        action = form.get('action', '')
                        if action and action.startswith('http://'):
                            self.write_log(f"[✓] Form found submitting over HTTP at: {url}")
                            self.write_log(f"    Form action: {action}")
                            sensitive_data_found = True
                    
                    # Check for cookies without Secure flag
                    cookies = response.cookies
                    for cookie in cookies:
                        if not cookie.secure and cookie.has_nonstandard_attr('httponly'):
                            self.write_log(f"[✓] Cookie without Secure flag found at: {url}")
                            self.write_log(f"    Cookie name: {cookie.name}")
                            sensitive_data_found = True
                    
                    # Check for sensitive information in response
                    sensitive_patterns = [
                        r'password', r'passwd', r'pwd', r'credit', r'card', 
                        r'ssn', r'social security', r'cvv', r'expiration',
                        r'dob', r'date of birth', r'phone', r'email'
                    ]
                    for pattern in sensitive_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            self.write_log(f"[!] Potential sensitive data ({pattern}) found in response from: {url}")
                            sensitive_data_found = True
                            
                except Exception as e:
                    self.write_log(f"[!] Error testing {url}: {str(e)}")
                    continue
            
            if not sensitive_data_found:
                self.write_log("[-] No obvious sensitive data transmitted over unencrypted channels found")
                
        except Exception as e:
            self.write_log(f"[!] Error in OTG_CRYPST_003: {str(e)}")


def main():
    parser = argparse.ArgumentParser(description='DVWA Cryptography Testing Script')
    parser.add_argument('--url', default='http://localhost:8080', help='Base URL of DVWA')
    parser.add_argument('--tests', nargs='+',
                        choices=['ALL', 'OTG_CRYPST_001', 'OTG_CRYPST_002', 'OTG_CRYPST_003'],
                        default=['ALL'], help='Tests to run')
    parser.add_argument('--username', default='admin')
    parser.add_argument('--password', default='password')
    args = parser.parse_args()

    logger.info(f"Starting DVWA Cryptography Tests for {args.url}")
    tester = DVWACryptTester(base_url=args.url, username=args.username, password=args.password)
    if not tester.login():
        return

    test_functions = {
        'OTG_CRYPST_001': tester.OTG_CRYPST_001,
        'OTG_CRYPST_002': tester.OTG_CRYPST_002,
        'OTG_CRYPST_003': tester.OTG_CRYPST_003
    }

    test_names = {
        'OTG_CRYPST_001': "Weak SSL/TLS Cipher Test",
        'OTG_CRYPST_002': "Testing for Padding Oracle",
        'OTG_CRYPST_003': "Sensitive Info over Unencrypted Channels"
    }

    selected_tests = ['OTG_CRYPST_001', 'OTG_CRYPST_002', 'OTG_CRYPST_003'] if 'ALL' in args.tests else args.tests

    for test_id in selected_tests:
        if test_id in test_functions:
            tester.run_test(test_id, test_names[test_id], test_functions[test_id])
        else:
            tester.write_log(f"[!] Unknown test: {test_id}")

    logger.info("All selected tests completed.")


if __name__ == '__main__':
    main()
