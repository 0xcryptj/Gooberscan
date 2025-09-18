#!/usr/bin/env python3
"""
aggregate_reports.py

Usage:
  python3 aggregate_reports.py --reports reports/<domain-timestamp>

This script scans the reports directory and extracts:
 - hosts (from nmap XML)
 - discovered URLs (from ffuf JSON, gobuster txt)
 - parameterized URLs (simple regex)
 - CVE/plugin/version hints (from wpscan/nikto/nmap .gnmap or .nmap text)

Outputs into: worklists/<domain-timestamp>/
 - hosts.txt
 - urls.txt
 - params.txt
 - cves.txt
"""

import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

URL_RE = re.compile(r"https?://[^\s'\"<>]+")
PARAM_RE = re.compile(r"[?&][^=]+=[^&\s]+")

def parse_nmap_xml(xml_path, out_hosts):
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as e:
        print(f"[!] Failed to parse nmap xml {xml_path}: {e}")
        return
    for host in root.findall('host'):
        addr = None
        for a in host.findall('address'):
            if a.get('addrtype') == 'ipv4' or a.get('addrtype') == 'ipv6':
                addr = a.get('addr')
                break
        if not addr:
            continue
        ports = []
        for ports_el in host.findall('ports'):
            for p in ports_el.findall('port'):
                state = p.find('state')
                if state is not None and state.get('state') == 'open':
                    portnum = p.get('portid')
                    service = p.find('service')
                    svc = service.get('name') if service is not None else ''
                    ports.append(f"{portnum}/{svc}")
        if ports:
            out_hosts.write(f"{addr} {' '.join(ports)}\n")
        else:
            out_hosts.write(f"{addr}\n")

def extract_urls_from_ffuf(json_path, out_urls):
    try:
        with open(json_path, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
    except Exception as e:
        print(f"[!] Could not read ffuf json {json_path}: {e}")
        return
    for item in data.get('results', []):
        url = item.get('input', {}).get('url') or item.get('url') or item.get('input')
        if url:
            out_urls.write(url + "\n")

def extract_urls_from_gobuster(gob_path, out_urls):
    try:
        with open(gob_path, 'r', encoding='utf-8', errors='ignore') as fh:
            for line in fh:
                line = line.strip()
                if line == "" or line.startswith('/') or ' ' not in line:
                    pass
                m = URL_RE.search(line)
                if m:
                    out_urls.write(m.group(0) + "\n")
                else:
                    if line.startswith("/"):
                        out_urls.write(line + "\n")
    except Exception as e:
        print(f"[!] Could not read gobuster file {gob_path}: {e}")

def extract_from_txtlike(path, out_urls, out_cves):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
            for line in fh:
                if "CVE-" in line or "cve-" in line or "vulnerab" in line.lower() or "version" in line.lower():
                    out_cves.write(line.strip() + "\n")
                m = URL_RE.search(line)
                if m:
                    out_urls.write(m.group(0) + "\n")
    except Exception as e:
        print(f"[!] Could not read text file {path}: {e}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--reports', required=True, help="path to the reports directory (one run folder)")
    args = ap.parse_args()
    rpt = Path(args.reports)
    if not rpt.exists():
        print(f"[!] Reports folder not found: {rpt}")
        sys.exit(1)

    outdir = Path("worklists") / rpt.name
    outdir.mkdir(parents=True, exist_ok=True)
    hosts_f = open(outdir / "hosts.txt", "w", encoding='utf-8')
    urls_f = open(outdir / "urls.txt", "w", encoding='utf-8')
    params_f = open(outdir / "params.txt", "w", encoding='utf-8')
    cves_f = open(outdir / "cves.txt", "w", encoding='utf-8')

    # look for nmap xml
    for f in rpt.glob("*.xml"):
        if f.name.startswith("nmap") or f.suffix == ".xml":
            print(f"[+] Parsing nmap xml: {f}")
            parse_nmap_xml(f, hosts_f)

    # ffuf json
    for f in rpt.glob("*.json"):
        if f.name.startswith("ffuf") or f.suffix == ".json":
            print(f"[+] Parsing ffuf json: {f}")
            try:
                extract_urls_from_ffuf(f, urls_f)
            except Exception:
                pass

    # gobuster/gob files
    for f in rpt.glob("**/*gobuster*.txt"):
        print(f"[+] Parsing gobuster output: {f}")
        extract_urls_from_gobuster(f, urls_f)

    # generic text-like files (nikto, wpscan, zap text dumps)
    for f in rpt.glob("**/*.txt"):
        name = f.name.lower()
        if "nikto" in name or "wpscan" in name or "zap" in name or "sqlmap" in name:
            print(f"[+] Parsing text file: {f}")
            extract_from_txtlike(f, urls_f, cves_f)

    # dedupe and post-process
    hosts_f.close(); urls_f.close(); cves_f.close()
    # dedupe urls and extract params
    urls = set()
    with open(outdir / "urls.txt", "r", encoding='utf-8') as fh:
        for line in fh:
            u = line.strip()
            if u:
                urls.add(u)
    # write deduped
    with open(outdir / "urls.txt", "w", encoding='utf-8') as fh:
        for u in sorted(urls):
            fh.write(u + "\n")
            # detect params
            if PARAM_RE.search(u):
                with open(outdir / "params.txt", "a", encoding='utf-8') as pf:
                    pf.write(u + "\n")

    # dedupe cves
    try:
        with open(outdir / "cves.txt", "r", encoding='utf-8') as cf:
            cset = set([l.strip() for l in cf if l.strip()])
        with open(outdir / "cves.txt", "w", encoding='utf-8') as cf:
            for c in sorted(cset):
                cf.write(c + "\n")
    except Exception:
        pass

    print(f"[+] Done. Worklists saved to {outdir}")
    print(f"    hosts: {outdir / 'hosts.txt'}")
    print(f"    urls:  {outdir / 'urls.txt'}")
    print(f"    params:{outdir / 'params.txt'}")
    print(f"    cves:  {outdir / 'cves.txt'}")

if __name__ == "__main__":
    main()
