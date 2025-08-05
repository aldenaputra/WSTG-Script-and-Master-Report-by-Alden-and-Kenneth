#!/usr/bin/env python3
"""
DVWA Configuration & Deployment Testing – Quick-Fire Toolkit (SysReptor Format)
Runs OTG-CONFIG-001 → OTG-CONFIG-008 in sequence.
Outputs results in SysReptor-compatible markdown format with UTF-8 encoding.
"""

import subprocess
import sys
import json
import os
import tempfile
import shutil
from pathlib import Path
import requests
import re
import contextlib
import io

# -----------------------------------------------------------
# Config
# -----------------------------------------------------------
DVWA_URL = "http://localhost:8080"
WORDLISTS = {
    "backup": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt",
    "extensions": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/web-extensions.txt"
}

# -----------------------------------------------------------
# Utilities
# -----------------------------------------------------------
@contextlib.contextmanager
def capture_output():
    """Capture stdout and stderr output."""
    new_out, new_err = io.StringIO(), io.StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = new_out, new_err
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = old_out, old_err

def banner(msg):
    """Print banner message."""
    print("\n" + "=" * 70)
    print(f"  {msg}")
    print("=" * 70)

def run(cmd, capture=True, shell=False):
    """Wrapper around subprocess.run with sane defaults."""
    cmd_str = ' '.join(cmd) if isinstance(cmd, list) else cmd
    try:
        cp = subprocess.run(cmd, shell=shell, capture_output=capture, text=True, timeout=30)
        return {
            'command': cmd_str,
            'stdout': cp.stdout.strip(),
            'stderr': cp.stderr.strip(),
            'returncode': cp.returncode,
            'timeout': False
        }
    except subprocess.TimeoutExpired:
        return {
            'command': cmd_str,
            'stdout': '',
            'stderr': 'TIMEOUT',
            'returncode': 1,
            'timeout': True
        }

def http_get(path="/"):
    """Perform HTTP GET request."""
    try:
        return requests.get(DVWA_URL + path, timeout=10)
    except requests.RequestException as e:
        return None

def log_run(result):
    """Log command execution results."""
    print(f"$ {result['command']}")
    print(f"Returned: {result['returncode']}")
    if result['stdout']:
        print("-- stdout --")
        print(result['stdout'])
    if result['stderr']:
        print("-- stderr --")
        print(result['stderr'])
    if result['timeout']:
        print("Command timed out")

# -----------------------------------------------------------
# Test Modules
# -----------------------------------------------------------
def otg_001():
    """OTG-CONFIG-001 – Network/Infrastructure Configuration"""
    banner("OTG-CONFIG-001 – Network/Infrastructure Configuration")
    result = run(["nmap", "-sS", "-sV", "--top-ports", "1000", "localhost"])
    log_run(result)
    return result

def otg_002():
    """OTG-CONFIG-002 – Application Platform Configuration"""
    banner("OTG-CONFIG-002 – Application Platform Configuration")
    results = {}
    for cmd in [["docker", "exec", "dvwa", "php", "-i"], ["docker", "exec", "dvwa", "apache2ctl", "-S"]]:
        result = run(cmd)
        key = cmd[-2] + "_" + cmd[-1]
        results[key] = result
        log_run(result)
    return results

def otg_003(temp_dir):
    """OTG-CONFIG-003 – File Extensions Handling"""
    banner("OTG-CONFIG-003 – File Extensions Handling")
    ext_file = Path(temp_dir) / "extensions.txt"
    dl_result = run(["curl", "-sSL", WORDLISTS["extensions"]], capture=True)
    if dl_result['returncode'] == 0:
        ext_file.write_text(dl_result['stdout'])
    
    ffuf_path = shutil.which("ffuf")
    if ffuf_path:
        result = run([ffuf_path, "-u", f"{DVWA_URL}/FUZZ", "-w", str(ext_file), "-mc", "200,403", "-t", "30"])
        log_run(result)
        return result
    return {"status": "ffuf not found"}

def otg_004(temp_dir):
    """OTG-CONFIG-004 – Old/Backup/Unreferenced Files"""
    banner("OTG-CONFIG-004 – Old/Backup/Unreferenced Files")
    wordlist = Path(temp_dir) / "raft-small-files.txt"
    dl_result = run(["curl", "-sSL", WORDLISTS["backup"]], capture=True)
    if dl_result['returncode'] == 0:
        wordlist.write_text(dl_result['stdout'])
    
    gb_path = shutil.which("gobuster")
    if gb_path:
        result = run([gb_path, "dir", "-u", DVWA_URL, "-w", str(wordlist), "-x", "bak,old,orig,txt,swp,tmp", "-t", "30"])
        log_run(result)
        return result
    return {"status": "gobuster not found"}

def otg_005():
    """OTG-CONFIG-005 – Enumerate Admin Interfaces"""
    banner("OTG-CONFIG-005 – Enumerate Admin Interfaces")
    r = http_get("/")
    if r is None:
        print("HTTP request failed")
        return None
    
    links = re.findall(r'href=["\'](.*?)["\']', r.text, re.I)
    admin_like = [l for l in links if "admin" in l.lower()]
    print("Possible admin links:", admin_like)
    return admin_like

def otg_006():
    """OTG-CONFIG-006 – Test HTTP Methods"""
    banner("OTG-CONFIG-006 – Test HTTP Methods")
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "TRACE", "TRACK", "CONNECT", "DEBUG"]
    results = {}
    for m in methods:
        try:
            resp = requests.request(m, DVWA_URL, timeout=5)
            results[m] = {"status": resp.status_code, "len": len(resp.content)}
            print(f"{m}: {resp.status_code} (Length: {len(resp.content)})")
        except Exception as e:
            results[m] = {"error": str(e)}
            print(f"{m}: Error - {str(e)}")
    return results

def otg_007():
    """OTG-CONFIG-007 – HTTP Strict Transport Security"""
    banner("OTG-CONFIG-007 – HTTP Strict Transport Security")
    r = http_get("/")
    if r:
        hsts = r.headers.get("Strict-Transport-Security", None)
        print("HSTS header:", hsts)
        return {"present": hsts is not None, "value": hsts}
    print("HTTP request failed")
    return None

def otg_008():
    """OTG-CONFIG-008 – RIA Cross-Domain Policy"""
    banner("OTG-CONFIG-008 – RIA Cross-Domain Policy")
    files = ["/crossdomain.xml", "/clientaccesspolicy.xml"]
    results = {}
    for f in files:
        r = http_get(f)
        if r:
            results[f] = {"status": r.status_code, "body": r.text[:500] if r.status_code == 200 else None}
            print(f"{f}: {r.status_code}")
        else:
            results[f] = {"status": "error"}
            print(f"{f}: Request failed")
    return results

# -----------------------------------------------------------
# Report Generation
# -----------------------------------------------------------
def generate_report(results, output_file="dvwa_config_report.md"):
    """Generate markdown report in SysReptor format with UTF-8 encoding."""
    md = "# DVWA Configuration & Deployment Testing Report\n\n"
    md += "**Target URL**: " + DVWA_URL + "\n\n"
    
    for test_id, data in results.items():
        md += f"## {test_id}\n"
        md += f"**Description**: {data['description']}\n\n"
        
        if data['status'] == "error":
            md += "**Status**: ❌ Error\n\n"
            md += "```\n" + data['output'] + "\n```\n\n"
            continue
        
        md += "**Status**: ✅ Completed\n\n"
        
        if isinstance(data['result'], dict) or isinstance(data['result'], list):
            md += "**Results**:\n```json\n"
            md += json.dumps(data['result'], indent=2)
            md += "\n```\n\n"
        elif data['result']:
            md += "**Results**:\n```\n"
            md += str(data['result'])
            md += "\n```\n\n"
        else:
            md += "**Results**: No data\n\n"
        
        if data['output']:
            md += "**Console Output**:\n```\n"
            md += data['output']
            md += "\n```\n\n"
    
    # Write with explicit UTF-8 encoding
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(md)
    return output_file

# -----------------------------------------------------------
# Main
# -----------------------------------------------------------
def main():
    if shutil.which("docker") is None:
        print("Docker CLI is required for OTG-002.")
        sys.exit(1)
    
    # Setup temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        # Test execution
        test_results = {}
        tests = [
            ("OTG-CONFIG-001", "Network/Infrastructure Configuration", otg_001),
            ("OTG-CONFIG-002", "Application Platform Configuration", otg_002),
            ("OTG-CONFIG-003", "File Extensions Handling", lambda: otg_003(temp_dir)),
            ("OTG-CONFIG-004", "Old/Backup/Unreferenced Files", lambda: otg_004(temp_dir)),
            ("OTG-CONFIG-005", "Enumerate Admin Interfaces", otg_005),
            ("OTG-CONFIG-006", "Test HTTP Methods", otg_006),
            ("OTG-CONFIG-007", "HTTP Strict Transport Security", otg_007),
            ("OTG-CONFIG-008", "RIA Cross-Domain Policy", otg_008),
        ]
        
        for test_id, description, test_func in tests:
            with capture_output() as (out, err):
                try:
                    result = test_func()
                    status = "completed"
                except Exception as e:
                    result = None
                    status = "error"
                    print(f"Test failed: {str(e)}")
                output = out.getvalue() + err.getvalue()
            
            test_results[test_id] = {
                'description': description,
                'status': status,
                'result': result,
                'output': output
            }
        
        # Generate report with UTF-8 encoding
        report_file = generate_report(test_results)
        print(f"\nReport generated: {report_file}")

if __name__ == "__main__":
    main()