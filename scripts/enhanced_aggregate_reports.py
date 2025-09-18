#!/usr/bin/env python3
import argparse, json, re, sys
from pathlib import Path
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

URL_RE   = re.compile(r"https?://[^\s'\"<>]+")
PARAM_RE = re.compile(r"[?&][^=]+=[^&\s]+")

# Sensitive endpoint patterns categorized by risk level
SENSITIVE_PATTERNS = {
    'critical': [
        r'admin', r'administrator', r'login', r'wp-admin', r'phpmyadmin', r'dbadmin',
        r'backup', r'backups', r'database', r'db', r'mysql', r'postgres',
        r'root', r'superuser', r'manage', r'management', r'control', r'panel'
    ],
    'high': [
        r'api', r'v1', r'v2', r'rest', r'graphql', r'endpoint',
        r'upload', r'uploads', r'file', r'files', r'download', r'downloads',
        r'config', r'configuration', r'settings', r'setup', r'install', r'installer'
    ],
    'medium': [
        r'test', r'testing', r'dev', r'development', r'staging', r'stage',
        r'debug', r'logs', r'log', r'error', r'errors', r'exception',
        r'temp', r'tmp', r'cache', r'cached', r'session', r'sessions'
    ],
    'low': [
        r'demo', r'demos', r'example', r'examples', r'sample', r'samples',
        r'old', r'legacy', r'archive', r'archives', r'deprecated'
    ]
}

def categorize_sensitive_endpoints(urls):
    """Categorize URLs by sensitivity level"""
    categorized = {'critical': [], 'high': [], 'medium': [], 'low': []}
    
    for url in urls:
        # Clean ANSI codes from the URL
        clean_url = re.sub(r'\[[0-9;]*m', '', url).strip()
        url_lower = clean_url.lower()
        categorized_flag = False
        
        for level, patterns in SENSITIVE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, url_lower):
                    categorized[level].append(clean_url)
                    categorized_flag = True
                    break
            if categorized_flag:
                break
    
    return categorized

def parse_nmap_xml(p):
    hosts=[]
    try:
        root=ET.parse(p).getroot()
    except Exception as e:
        print(f"[!] nmap xml parse failed: {p} -> {e}")
        return hosts
    for h in root.findall('host'):
        ip=None
        for a in h.findall('address'):
            if a.get('addrtype') in ('ipv4','ipv6'): ip=a.get('addr')
        if not ip: continue
        openp=[]
        for ps in h.findall('ports'):
            for pt in ps.findall('port'):
                st=pt.find('state')
                if st is not None and st.get('state')=='open':
                    svc=pt.find('service')
                    openp.append({
                      "port": int(pt.get('portid')),
                      "proto": pt.get('protocol','tcp'),
                      "service": (svc.get('name') if svc is not None else ""),
                      "product": (svc.get('product') if svc is not None else ""),
                      "version": (svc.get('version') if svc is not None else "")
                    })
        hosts.append({"ip":ip,"open_ports":openp})
    return hosts

def read_text(path):
    try:
        return Path(path).read_text(errors='ignore')
    except: return ""

def extract_exposed_endpoints_from_reports(reports_dir):
    """Extract exposed endpoints with response codes from scan reports"""
    exposed_endpoints = {
        'critical_exposed': [],      # Sensitive endpoints with 200 OK
        'high_exposed': [],          # Sensitive endpoints with other exposed codes
        'medium_exposed': [],        # Non-sensitive endpoints with 200 OK
        'low_exposed': [],           # Non-sensitive endpoints with other codes
        'protected_endpoints': []    # 401/403 endpoints
    }
    
    # Response codes that indicate exposure
    exposed_codes = ['200', '201', '202', '204', '301', '302', '307', '308', '401', '403', '405']
    critical_codes = ['200', '201', '202', '204']
    
    # Extract base URL from reports directory name
    base_domain = reports_dir.name.split('-')[0] if '-' in reports_dir.name else 'unknown'
    base_url = f"https://{base_domain}"
    
    # Parse GoBuster results
    gobuster_files = list(reports_dir.glob("*gobuster*.txt"))
    for gob_file in gobuster_files:
        content = read_text(gob_file)
        for line in content.splitlines():
            # Parse GoBuster format: /path [33m (Status: XXX) [0m [Size: YYY]
            # Clean the line first to remove ANSI codes
            clean_line = re.sub(r'\[[0-9;]*m', '', line)
            match = re.search(r'^([^\s]+).*?Status:\s*(\d+).*?Size:\s*(\d+)', clean_line)
            if match:
                path = match.group(1)
                status_code = match.group(2)
                size = int(match.group(3))
                
                if status_code in exposed_codes:
                    # Create full URL
                    if path.startswith('/'):
                        full_url = f"{base_url}{path}"
                    elif path.startswith('http'):
                        full_url = path
                    else:
                        full_url = f"{base_url}/{path}"
                    
                    # Check if endpoint is sensitive
                    is_sensitive = any(re.search(pattern, path.lower()) for pattern in [
                        r'(admin|administrator|manage|management|control|panel)',
                        r'(login|auth|signin|signon|authenticate)',
                        r'(api|rest|graphql|endpoint|service)',
                        r'(config|configuration|settings|setup|install)',
                        r'(db|database|mysql|postgres|sql|phpmyadmin)',
                        r'(upload|download|file|files|backup|backups)',
                        r'(dev|development|test|testing|debug|staging)',
                        r'(\.git|git|\.svn|svn|\.cvs|cvs)',
                        r'(log|logs|\.log|error|errors|exception)',
                        r'(system|sys|root|superuser|shell|cmd)'
                    ])
                    
                    endpoint_data = {
                        'path': path,
                        'full_url': full_url,
                        'status_code': status_code,
                        'size': size,
                        'is_critical_code': status_code in critical_codes
                    }
                    
                    # Categorize based on sensitivity and response code
                    if is_sensitive and status_code in critical_codes:
                        exposed_endpoints['critical_exposed'].append(endpoint_data)
                    elif is_sensitive and status_code not in critical_codes:
                        exposed_endpoints['high_exposed'].append(endpoint_data)
                    elif not is_sensitive and status_code in critical_codes:
                        exposed_endpoints['medium_exposed'].append(endpoint_data)
                    elif not is_sensitive and status_code not in critical_codes:
                        exposed_endpoints['low_exposed'].append(endpoint_data)
                    
                    # Special handling for protected endpoints
                    if status_code in ['401', '403']:
                        exposed_endpoints['protected_endpoints'].append(endpoint_data)
    
    # Parse ffuf results
    ffuf_files = list(reports_dir.glob("ffuf*.json"))
    for ffuf_file in ffuf_files:
        try:
            data = json.loads(read_text(ffuf_file))
            for result in data.get("results", []):
                status_code = str(result.get('status', ''))
                url = result.get('url', '')
                size = result.get('length', 0)
                
                if status_code in exposed_codes:
                    # Extract path from URL for sensitivity checking
                    parsed_url = urlparse(url)
                    path = parsed_url.path
                    
                    # Check if endpoint is sensitive
                    is_sensitive = any(re.search(pattern, path.lower()) for pattern in [
                        r'(admin|administrator|manage|management|control|panel)',
                        r'(login|auth|signin|signon|authenticate)',
                        r'(api|rest|graphql|endpoint|service)',
                        r'(config|configuration|settings|setup|install)',
                        r'(db|database|mysql|postgres|sql|phpmyadmin)',
                        r'(upload|download|file|files|backup|backups)',
                        r'(dev|development|test|testing|debug|staging)',
                        r'(\.git|git|\.svn|svn|\.cvs|cvs)',
                        r'(log|logs|\.log|error|errors|exception)',
                        r'(system|sys|root|superuser|shell|cmd)'
                    ])
                    
                    endpoint_data = {
                        'path': path,
                        'full_url': url,
                        'status_code': status_code,
                        'size': size,
                        'is_critical_code': status_code in critical_codes
                    }
                    
                    # Categorize based on sensitivity and response code
                    if is_sensitive and status_code in critical_codes:
                        exposed_endpoints['critical_exposed'].append(endpoint_data)
                    elif is_sensitive and status_code not in critical_codes:
                        exposed_endpoints['high_exposed'].append(endpoint_data)
                    elif not is_sensitive and status_code in critical_codes:
                        exposed_endpoints['medium_exposed'].append(endpoint_data)
                    elif not is_sensitive and status_code not in critical_codes:
                        exposed_endpoints['low_exposed'].append(endpoint_data)
                    
                    # Special handling for protected endpoints
                    if status_code in ['401', '403']:
                        exposed_endpoints['protected_endpoints'].append(endpoint_data)
        except Exception as e:
            print(f"[!] ffuf parse error: {ffuf_file} -> {e}")
    
    # Remove duplicates
    for category in exposed_endpoints:
        seen_urls = set()
        unique_endpoints = []
        for endpoint in exposed_endpoints[category]:
            if endpoint['full_url'] not in seen_urls:
                unique_endpoints.append(endpoint)
                seen_urls.add(endpoint['full_url'])
        exposed_endpoints[category] = unique_endpoints
    
    return exposed_endpoints

def extract_sensitive_endpoints_from_reports(reports_dir):
    """Extract and categorize sensitive endpoints from all scan reports"""
    sensitive_endpoints = {'critical': [], 'high': [], 'medium': [], 'low': []}
    
    # Check GoBuster results
    gobuster_files = list(reports_dir.glob("*gobuster*.txt"))
    for gob_file in gobuster_files:
        content = read_text(gob_file)
        urls = []
        for line in content.splitlines():
            # Clean ANSI codes from the line
            clean_line = re.sub(r'\[[0-9;]*m', '', line)
            m = URL_RE.search(clean_line)
            if m:
                urls.append(m.group(0))
            elif clean_line.startswith("/"):
                urls.append(clean_line.strip())
        
        categorized = categorize_sensitive_endpoints(urls)
        for level in sensitive_endpoints:
            sensitive_endpoints[level].extend(categorized[level])
    
    # Check ffuf results
    ffuf_files = list(reports_dir.glob("ffuf*.json"))
    for ffuf_file in ffuf_files:
        try:
            data = json.loads(read_text(ffuf_file))
            urls = []
            for item in data.get("results", []):
                url = item.get("url") or item.get("input", {}).get("url") or item.get("input")
                if url:
                    urls.append(url)
            
            categorized = categorize_sensitive_endpoints(urls)
            for level in sensitive_endpoints:
                sensitive_endpoints[level].extend(categorized[level])
        except Exception as e:
            print(f"[!] ffuf parse error: {ffuf_file} -> {e}")
    
    # Deduplicate and sort
    for level in sensitive_endpoints:
        sensitive_endpoints[level] = sorted(set(sensitive_endpoints[level]))
    
    return sensitive_endpoints

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--reports", required=True, help="reports/<domain-timestamp> folder")
    args=ap.parse_args()
    rpt=Path(args.reports)
    if not rpt.exists(): sys.exit(f"missing {rpt}")

    outdir = Path("worklists")/rpt.name
    outdir.mkdir(parents=True, exist_ok=True)

    # Collect inputs
    nmap_xml = next(iter(rpt.glob("*.xml")), None)
    gob_txt  = next(iter(rpt.glob("*gobuster*.txt")), None)
    ffuf_json= next(iter(rpt.glob("ffuf*.json")), None)
    nikto_txt= next(iter(rpt.glob("nikto*.txt")), None)
    wpscan_txt= next(iter(rpt.glob("wpscan*.txt")), None)
    zap_html = list(rpt.glob("zap-*.html"))  # optional baseline/full reports

    result = {"run": rpt.name, "hosts": [], "urls": [], "params": [], "cves": [], "notes": [], "sensitive_endpoints": {}, "exposed_endpoints": {}}

    # nmap
    if nmap_xml:
        result["hosts"]=parse_nmap_xml(nmap_xml)

    # gobuster urls
    if gob_txt:
        for line in read_text(gob_txt).splitlines():
            # Clean ANSI codes from the line
            clean_line = re.sub(r'\[[0-9;]*m', '', line)
            m = URL_RE.search(clean_line)
            if m: result["urls"].append(m.group(0))
            elif clean_line.startswith("/"): result["urls"].append(clean_line.strip())

    # ffuf urls
    if ffuf_json and ffuf_json.exists():
        try:
            data=json.loads(read_text(ffuf_json))
            for it in data.get("results",[]):
                url = it.get("url") or it.get("input",{}).get("url") or it.get("input")
                if url: result["urls"].append(url)
        except Exception as e:
            result["notes"].append(f"ffuf parse error: {e}")

    # nikto & wpscan: collect URLs/CVEs/versions
    def harvest_txt(fp):
        txt=read_text(fp)
        for l in txt.splitlines():
            if "CVE-" in l.upper(): result["cves"].append(l.strip())
            m=URL_RE.search(l)
            if m: result["urls"].append(m.group(0))
    if nikto_txt:  harvest_txt(nikto_txt)
    if wpscan_txt: harvest_txt(wpscan_txt)

    # Extract sensitive endpoints
    result["sensitive_endpoints"] = extract_sensitive_endpoints_from_reports(rpt)
    
    # Extract exposed endpoints with response codes
    result["exposed_endpoints"] = extract_exposed_endpoints_from_reports(rpt)

    # de-dupe
    urls=sorted(set([u.strip() for u in result["urls"] if u.strip()]))
    result["urls"]=urls
    # params
    params=sorted(set([u for u in urls if PARAM_RE.search(u)]))
    result["params"]=params
    # cves dedupe
    result["cves"]=sorted(set([c.strip() for c in result["cves"] if c.strip()]))

    # write worklists
    (outdir/"hosts.txt").write_text(
        "\n".join([f"{h['ip']} "+" ".join([f"{p['port']}/{p['service']}" for p in h['open_ports']]) for h in result["hosts"]])+"\n" if result["hosts"] else ""
    )
    (outdir/"urls.txt").write_text("\n".join(urls)+"\n" if urls else "")
    (outdir/"params.txt").write_text("\n".join(params)+"\n" if params else "")
    (outdir/"cves.txt").write_text("\n".join(result["cves"])+"\n" if result["cves"] else "")
    
    # Write sensitive endpoints by category with full URLs
    base_domain = rpt.name.split('-')[0] if '-' in rpt.name else 'unknown'
    base_url = f"https://{base_domain}"
    
    for level, endpoints in result["sensitive_endpoints"].items():
        if endpoints:
            content = []
            for endpoint in endpoints:
                # Clean up the endpoint and create full URL
                # Remove all ANSI escape sequences and status information
                clean_endpoint = re.sub(r'\[[0-9;]*m', '', endpoint)  # Remove ANSI codes
                clean_endpoint = re.sub(r' \(Status: [0-9]+\)', '', clean_endpoint)  # Remove status
                clean_endpoint = re.sub(r' \[Size: [0-9]+\]', '', clean_endpoint)  # Remove size
                clean_endpoint = clean_endpoint.strip()
                
                if clean_endpoint.startswith('/'):
                    full_url = f"{base_url}{clean_endpoint}"
                elif clean_endpoint.startswith('http'):
                    full_url = clean_endpoint
                else:
                    full_url = f"{base_url}/{clean_endpoint}"
                content.append(full_url)
            (outdir/f"sensitive_{level}.txt").write_text("\n".join(content)+"\n")
    
    # Write exposed endpoints by category
    for category, endpoints in result["exposed_endpoints"].items():
        if endpoints:
            filename = f"exposed_{category}.txt"
            content = []
            for endpoint in endpoints:
                # Clean up the URL by removing ANSI color codes
                clean_url = re.sub(r'\[[0-9;]*m', '', endpoint['full_url']).strip()
                content.append(f"{clean_url}")
            (outdir/filename).write_text("\n".join(content)+"\n")

    # machine-readable export for pipeline
    Path("worklists").mkdir(exist_ok=True, parents=True)
    (outdir/"aggregate.json").write_text(json.dumps(result, indent=2))

    print(f"[+] Aggregated → {outdir}")
    print(f"[+] Sensitive endpoints found:")
    for level, endpoints in result["sensitive_endpoints"].items():
        if endpoints:
            print(f"    {level.upper()}: {len(endpoints)} endpoints")
    
    print(f"[+] Exposed endpoints found:")
    total_exposed = sum(len(endpoints) for endpoints in result["exposed_endpoints"].values())
    print(f"    TOTAL EXPOSED: {total_exposed} endpoints")
    for category, endpoints in result["exposed_endpoints"].items():
        if endpoints:
            print(f"    {category.upper()}: {len(endpoints)} endpoints")

if __name__=="__main__": main()
