#!/usr/bin/env python3
import re
import json
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

class ExposedEndpointDetector:
    def __init__(self):
        # Response codes that indicate exposure
        self.exposed_codes = {
            '200': 'OK - Fully accessible',
            '201': 'Created - Resource created',
            '202': 'Accepted - Request accepted',
            '204': 'No Content - Success but no content',
            '301': 'Moved Permanently - Redirect',
            '302': 'Found - Temporary redirect',
            '307': 'Temporary Redirect',
            '308': 'Permanent Redirect',
            '401': 'Unauthorized - Authentication required (exposed but protected)',
            '403': 'Forbidden - Access denied (exposed but restricted)',
            '405': 'Method Not Allowed - Endpoint exists but method not allowed'
        }
        
        # Critical response codes that indicate high-risk exposure
        self.critical_codes = ['200', '201', '202', '204']
        
        # Sensitive endpoint patterns for exposure analysis
        self.sensitive_patterns = {
            'admin': r'(admin|administrator|manage|management|control|panel)',
            'auth': r'(login|auth|signin|signon|authenticate)',
            'api': r'(api|rest|graphql|endpoint|service)',
            'config': r'(config|configuration|settings|setup|install)',
            'database': r'(db|database|mysql|postgres|sql|phpmyadmin)',
            'file': r'(upload|download|file|files|backup|backups)',
            'dev': r'(dev|development|test|testing|debug|staging)',
            'git': r'(\.git|git|\.svn|svn|\.cvs|cvs)',
            'log': r'(log|logs|\.log|error|errors|exception)',
            'system': r'(system|sys|root|superuser|shell|cmd)'
        }
    
    def parse_gobuster_results(self, file_path, base_url):
        """Parse GoBuster results and extract response codes"""
        exposed_endpoints = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Parse GoBuster output format: /path [33m (Status: XXX) [0m [Size: YYY]
                    match = re.search(r'^([^\s]+).*?Status:\s*(\d+).*?Size:\s*(\d+)', line)
                    if match:
                        path = match.group(1)
                        status_code = match.group(2)
                        size = int(match.group(3))
                        
                        if status_code in self.exposed_codes:
                            # Create full URL
                            if path.startswith('/'):
                                full_url = f"{base_url}{path}"
                            elif path.startswith('http'):
                                full_url = path
                            else:
                                full_url = f"{base_url}/{path}"
                            
                            exposed_endpoints.append({
                                'path': path,
                                'full_url': full_url,
                                'status_code': status_code,
                                'size': size,
                                'description': self.exposed_codes[status_code],
                                'is_critical': status_code in self.critical_codes
                            })
        
        except Exception as e:
            print(f"[!] Error parsing GoBuster results: {e}")
        
        return exposed_endpoints
    
    def parse_ffuf_results(self, file_path):
        """Parse ffuf JSON results and extract response codes"""
        exposed_endpoints = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for result in data.get('results', []):
                status_code = str(result.get('status', ''))
                url = result.get('url', '')
                size = result.get('length', 0)
                
                if status_code in self.exposed_codes:
                    # Extract path from URL
                    parsed_url = urlparse(url)
                    path = parsed_url.path
                    
                    exposed_endpoints.append({
                        'path': path,
                        'full_url': url,
                        'status_code': status_code,
                        'size': size,
                        'description': self.exposed_codes[status_code],
                        'is_critical': status_code in self.critical_codes
                    })
        
        except Exception as e:
            print(f"[!] Error parsing ffuf results: {e}")
        
        return exposed_endpoints
    
    def categorize_exposed_endpoints(self, endpoints):
        """Categorize exposed endpoints by sensitivity and risk"""
        categorized = {
            'critical_exposed': [],      # Sensitive endpoints with 200 OK
            'high_exposed': [],          # Sensitive endpoints with other exposed codes
            'medium_exposed': [],        # Non-sensitive endpoints with 200 OK
            'low_exposed': [],           # Non-sensitive endpoints with other codes
            'protected_endpoints': []    # 401/403 endpoints (exposed but protected)
        }
        
        for endpoint in endpoints:
            path = endpoint['path'].lower()
            status_code = endpoint['status_code']
            is_critical_code = endpoint['is_critical']
            
            # Check if endpoint matches sensitive patterns
            is_sensitive = False
            for category, pattern in self.sensitive_patterns.items():
                if re.search(pattern, path):
                    is_sensitive = True
                    break
            
            # Categorize based on sensitivity and response code
            if is_sensitive and is_critical_code:
                categorized['critical_exposed'].append(endpoint)
            elif is_sensitive and not is_critical_code:
                categorized['high_exposed'].append(endpoint)
            elif not is_sensitive and is_critical_code:
                categorized['medium_exposed'].append(endpoint)
            elif not is_sensitive and not is_critical_code:
                categorized['low_exposed'].append(endpoint)
            
            # Special handling for protected endpoints
            if status_code in ['401', '403']:
                categorized['protected_endpoints'].append(endpoint)
        
        return categorized
    
    def generate_exposure_report(self, categorized_endpoints, target_url):
        """Generate a detailed exposure report"""
        report = {
            'target': target_url,
            'summary': {
                'total_exposed': sum(len(endpoints) for endpoints in categorized_endpoints.values()),
                'critical_exposed': len(categorized_endpoints['critical_exposed']),
                'high_exposed': len(categorized_endpoints['high_exposed']),
                'medium_exposed': len(categorized_endpoints['medium_exposed']),
                'low_exposed': len(categorized_endpoints['low_exposed']),
                'protected_endpoints': len(categorized_endpoints['protected_endpoints'])
            },
            'endpoints': categorized_endpoints,
            'risk_assessment': self._assess_exposure_risk(categorized_endpoints)
        }
        
        return report
    
    def _assess_exposure_risk(self, categorized_endpoints):
        """Assess the overall risk of exposed endpoints"""
        risk_factors = []
        
        critical_count = len(categorized_endpoints['critical_exposed'])
        high_count = len(categorized_endpoints['high_exposed'])
        protected_count = len(categorized_endpoints['protected_endpoints'])
        
        if critical_count > 0:
            risk_factors.append(f"🚨 CRITICAL: {critical_count} sensitive endpoints fully exposed (200 OK)")
        
        if high_count > 0:
            risk_factors.append(f"🟠 HIGH: {high_count} sensitive endpoints partially exposed")
        
        if protected_count > 0:
            risk_factors.append(f"🔒 PROTECTED: {protected_count} endpoints require authentication")
        
        if not risk_factors:
            risk_factors.append("✅ No significant exposure risks detected")
        
        return risk_factors
    
    def save_exposure_report(self, report, output_dir):
        """Save exposure report to files"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Save JSON report
        json_file = output_path / "exposure_report.json"
        with open(json_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Save categorized endpoints to separate files
        for category, endpoints in report['endpoints'].items():
            if endpoints:
                filename = f"exposed_{category}.txt"
                file_path = output_path / filename
                with open(file_path, 'w') as f:
                    for endpoint in endpoints:
                        f.write(f"{endpoint['full_url']} (Status: {endpoint['status_code']}, Size: {endpoint['size']})\n")
        
        return json_file

def main():
    if len(sys.argv) != 3:
        print("Usage: exposed_endpoints.py <reports_directory> <target_url>")
        print("Example: exposed_endpoints.py reports/www.example.com-20240101_120000 https://www.example.com")
        sys.exit(1)
    
    reports_dir = Path(sys.argv[1])
    target_url = sys.argv[2]
    
    if not reports_dir.exists():
        print(f"[!] Reports directory not found: {reports_dir}")
        sys.exit(1)
    
    detector = ExposedEndpointDetector()
    all_exposed = []
    
    # Parse GoBuster results
    gobuster_file = next(reports_dir.glob("*gobuster*.txt"), None)
    if gobuster_file:
        print(f"[*] Parsing GoBuster results: {gobuster_file}")
        gobuster_endpoints = detector.parse_gobuster_results(gobuster_file, target_url)
        all_exposed.extend(gobuster_endpoints)
        print(f"[+] Found {len(gobuster_endpoints)} exposed endpoints in GoBuster results")
    
    # Parse ffuf results
    ffuf_file = next(reports_dir.glob("ffuf*.json"), None)
    if ffuf_file:
        print(f"[*] Parsing ffuf results: {ffuf_file}")
        ffuf_endpoints = detector.parse_ffuf_results(ffuf_file)
        all_exposed.extend(ffuf_endpoints)
        print(f"[+] Found {len(ffuf_endpoints)} exposed endpoints in ffuf results")
    
    if not all_exposed:
        print("[!] No exposed endpoints found in scan results")
        sys.exit(1)
    
    # Remove duplicates
    unique_endpoints = []
    seen_paths = set()
    for endpoint in all_exposed:
        if endpoint['path'] not in seen_paths:
            unique_endpoints.append(endpoint)
            seen_paths.add(endpoint['path'])
    
    print(f"[+] Total unique exposed endpoints: {len(unique_endpoints)}")
    
    # Categorize endpoints
    categorized = detector.categorize_exposed_endpoints(unique_endpoints)
    
    # Generate report
    report = detector.generate_exposure_report(categorized, target_url)
    
    # Save report
    worklist_dir = Path("worklists") / reports_dir.name
    json_file = detector.save_exposure_report(report, worklist_dir)
    
    print(f"\n[+] Exposure analysis complete!")
    print(f"[+] Report saved to: {json_file}")
    print(f"[+] Categorized endpoints saved to: {worklist_dir}/exposed_*.txt")
    
    # Print summary
    print(f"\n📊 EXPOSURE SUMMARY:")
    print(f"   • Total exposed endpoints: {report['summary']['total_exposed']}")
    print(f"   • Critical exposed: {report['summary']['critical_exposed']}")
    print(f"   • High risk exposed: {report['summary']['high_exposed']}")
    print(f"   • Medium risk exposed: {report['summary']['medium_exposed']}")
    print(f"   • Low risk exposed: {report['summary']['low_exposed']}")
    print(f"   • Protected endpoints: {report['summary']['protected_endpoints']}")
    
    # Print risk assessment
    print(f"\n🎯 RISK ASSESSMENT:")
    for risk_factor in report['risk_assessment']:
        print(f"   {risk_factor}")

if __name__ == "__main__":
    main()
