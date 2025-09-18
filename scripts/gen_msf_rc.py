#!/usr/bin/env python3
import sys, re, pathlib

def make_rc(cve, target):
    rc = f"""
use auxiliary/scanner/http/msf_cve_scanner
set RHOSTS {target}
set TARGETURI /
set CVE {cve}
run
"""
    return rc.strip()

def make_web_rc(url, target):
    rc = f"""
use auxiliary/scanner/http/http_version
set RHOSTS {target}
set RPORT 80
set TARGETURI /
run

use auxiliary/scanner/http/dir_scanner
set RHOSTS {target}
set RPORT 80
set TARGETURI /
run
"""
    return rc.strip()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: gen_msf_rc.py <cve-list.txt> <target-domain>")
        sys.exit(1)

    cvefile, target = sys.argv[1], sys.argv[2]
    out = pathlib.Path("audit")/f"{target}-auto.rc"
    
    # Create audit directory if it doesn't exist
    pathlib.Path("audit").mkdir(exist_ok=True)
    
    rc_content = []
    
    # Process CVEs
    if pathlib.Path(cvefile).exists():
        with open(cvefile) as f:
            for line in f:
                cve = line.strip()
                if not cve or not cve.startswith("CVE-"):
                    continue
                rc_content.append(make_rc(cve, target))
                print(f"[+] Generated MSF RC for {cve} → {target}")
    
    # Add web scanning modules
    rc_content.append(make_web_rc("", target))
    
    # Write combined RC file
    if rc_content:
        with open(out, 'w') as f:
            f.write("\n\n".join(rc_content))
        print(f"[+] Wrote combined MSF RC file: {out}")
    else:
        print("[!] No CVEs found to generate MSF RC")
