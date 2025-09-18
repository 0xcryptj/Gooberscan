#!/usr/bin/env python3
import json
import sys
from pathlib import Path

def print_security_summary(worklist_dir):
    """Print a comprehensive security summary"""
    
    worklist_path = Path(worklist_dir)
    if not worklist_path.exists():
        print(f"[!] Worklist directory not found: {worklist_dir}")
        return
    
    # Load aggregate data
    aggregate_file = worklist_path / "aggregate.json"
    if aggregate_file.exists():
        with open(aggregate_file) as f:
            data = json.load(f)
    else:
        print(f"[!] Aggregate data not found: {aggregate_file}")
        return
    
    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║                                                                              ║")
    print("║                    🔍 GOOBERSCAN SECURITY SUMMARY 🔍                        ║")
    print("║                                                                              ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝")
    print()
    
    # Target information
    print(f"🎯 Target: {data.get('run', 'Unknown')}")
    print(f"📅 Scan Date: {data.get('run', '').split('-')[-1] if '-' in data.get('run', '') else 'Unknown'}")
    print()
    
    # Hosts and ports
    hosts = data.get('hosts', [])
    if hosts:
        print("🖥️  DISCOVERED HOSTS:")
        for host in hosts:
            ip = host.get('ip', 'Unknown')
            ports = host.get('open_ports', [])
            if ports:
                port_list = ", ".join([f"{p['port']}/{p['service']}" for p in ports])
                print(f"   • {ip}: {port_list}")
            else:
                print(f"   • {ip}: No open ports")
        print()
    
    # CVEs
    cves = data.get('cves', [])
    if cves:
        print("🚨 VULNERABILITIES DETECTED:")
        for cve in cves:
            print(f"   • {cve}")
        print()
    else:
        print("✅ No CVEs detected")
        print()
    
    # Exposed endpoints (with response codes)
    exposed = data.get('exposed_endpoints', {})
    total_exposed = sum(len(endpoints) for endpoints in exposed.values())
    
    if total_exposed > 0:
        print("🚨 EXPOSED ENDPOINTS DISCOVERED:")
        
        # Critical exposed endpoints (sensitive + 200 OK)
        critical_exposed = exposed.get('critical_exposed', [])
        if critical_exposed:
            print(f"   🔴 CRITICAL EXPOSED ({len(critical_exposed)} endpoints):")
            for endpoint in critical_exposed[:5]:
                print(f"      • {endpoint['full_url']} (Status: {endpoint['status_code']}, Size: {endpoint['size']})")
            if len(critical_exposed) > 5:
                print(f"      ... and {len(critical_exposed) - 5} more")
            print()
        
        # High exposed endpoints (sensitive + other codes)
        high_exposed = exposed.get('high_exposed', [])
        if high_exposed:
            print(f"   🟠 HIGH EXPOSED ({len(high_exposed)} endpoints):")
            for endpoint in high_exposed[:5]:
                print(f"      • {endpoint['full_url']} (Status: {endpoint['status_code']}, Size: {endpoint['size']})")
            if len(high_exposed) > 5:
                print(f"      ... and {len(high_exposed) - 5} more")
            print()
        
        # Medium exposed endpoints (non-sensitive + 200 OK)
        medium_exposed = exposed.get('medium_exposed', [])
        if medium_exposed:
            print(f"   🟡 MEDIUM EXPOSED ({len(medium_exposed)} endpoints):")
            for endpoint in medium_exposed[:5]:
                print(f"      • {endpoint['full_url']} (Status: {endpoint['status_code']}, Size: {endpoint['size']})")
            if len(medium_exposed) > 5:
                print(f"      ... and {len(medium_exposed) - 5} more")
            print()
        
        # Protected endpoints (401/403)
        protected = exposed.get('protected_endpoints', [])
        if protected:
            print(f"   🔒 PROTECTED ENDPOINTS ({len(protected)} endpoints):")
            for endpoint in protected[:5]:
                print(f"      • {endpoint['full_url']} (Status: {endpoint['status_code']}, Size: {endpoint['size']})")
            if len(protected) > 5:
                print(f"      ... and {len(protected) - 5} more")
            print()
    else:
        print("✅ No exposed endpoints detected")
        print()
    
    # Sensitive endpoints (all discovered, regardless of response code)
    sensitive = data.get('sensitive_endpoints', {})
    total_sensitive = sum(len(endpoints) for endpoints in sensitive.values())
    
    if total_sensitive > 0:
        print("🔍 SENSITIVE ENDPOINTS DISCOVERED:")
        
        for level in ['critical', 'high', 'medium', 'low']:
            endpoints = sensitive.get(level, [])
            if endpoints:
                level_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}
                print(f"   {level_emoji[level]} {level.upper()} RISK ({len(endpoints)} endpoints):")
                for endpoint in endpoints[:5]:  # Show first 5
                    print(f"      • {endpoint}")
                if len(endpoints) > 5:
                    print(f"      ... and {len(endpoints) - 5} more")
                print()
    else:
        print("✅ No sensitive endpoints detected")
        print()
    
    # URLs summary
    urls = data.get('urls', [])
    params = data.get('params', [])
    
    print("📊 SCAN STATISTICS:")
    print(f"   • Total URLs discovered: {len(urls)}")
    print(f"   • Parameterized URLs: {len(params)}")
    print(f"   • Sensitive endpoints: {total_sensitive}")
    print(f"   • Exposed endpoints: {total_exposed}")
    print(f"   • CVEs detected: {len(cves)}")
    print()
    
    # Recommendations
    print("💡 SECURITY RECOMMENDATIONS:")
    
    # Critical exposed endpoints (highest priority)
    if exposed.get('critical_exposed'):
        print("   🚨 CRITICAL EXPOSED:")
        print("      • IMMEDIATE ACTION: Sensitive endpoints are fully accessible (200 OK)")
        print("      • Secure or remove these endpoints immediately")
        print("      • Implement authentication and access controls")
        print("      • Test for unauthorized access")
    
    # High exposed endpoints
    if exposed.get('high_exposed'):
        print("   🔴 HIGH EXPOSED:")
        print("      • Sensitive endpoints partially exposed (redirects/auth required)")
        print("      • Review authentication mechanisms")
        print("      • Test for authentication bypass")
    
    # Sensitive endpoints (regardless of exposure)
    if sensitive.get('critical'):
        print("   🔴 CRITICAL SENSITIVE:")
        print("      • Immediately secure or remove admin/management interfaces")
        print("      • Implement strong authentication for sensitive endpoints")
        print("      • Review database access controls")
    
    if sensitive.get('high'):
        print("   🟠 HIGH SENSITIVE:")
        print("      • Secure API endpoints with proper authentication")
        print("      • Implement file upload restrictions")
        print("      • Review configuration file access")
    
    # Protected endpoints
    if exposed.get('protected_endpoints'):
        print("   🔒 PROTECTED ENDPOINTS:")
        print("      • Endpoints require authentication (401/403)")
        print("      • Verify authentication mechanisms are secure")
        print("      • Test for authentication bypass vulnerabilities")
    
    if cves:
        print("   🚨 VULNERABILITIES:")
        print("      • Update affected software immediately")
        print("      • Apply security patches")
        print("      • Consider using Metasploit RC for targeted testing")
    
    if not cves and not exposed.get('critical_exposed') and not sensitive.get('critical'):
        print("   ✅ No critical issues detected")
        print("      • Continue monitoring for new vulnerabilities")
        print("      • Regular security scans recommended")
    
    print()
    print("📁 Generated Files:")
    print(f"   • Worklists: {worklist_dir}")
    print(f"   • Sensitive endpoints: {worklist_dir}/sensitive_*.txt")
    print(f"   • Exposed endpoints: {worklist_dir}/exposed_*.txt")
    print(f"   • CVEs: {worklist_dir}/cves.txt")
    print(f"   • URLs: {worklist_dir}/urls.txt")
    print(f"   • Parameters: {worklist_dir}/params.txt")
    
    # Check for generated tools
    audit_dir = Path("audit")
    if audit_dir.exists():
        target_name = data.get('run', '').split('-')[0] if '-' in data.get('run', '') else 'unknown'
        msf_rc = audit_dir / f"{target_name}-auto.rc"
        if msf_rc.exists():
            print(f"   • Metasploit RC: {msf_rc}")
        
        burp_config = Path("burp") / f"{target_name}_config.json"
        if burp_config.exists():
            print(f"   • BurpSuite config: {burp_config}")
    
    print()
    print("🎯 Next Steps:")
    if cves:
        print("   1. Review detected CVEs and apply patches")
        print("   2. Use generated Metasploit RC for targeted testing")
    if sensitive.get('critical') or sensitive.get('high'):
        print("   3. Manually test sensitive endpoints for authentication bypass")
        print("   4. Use BurpSuite with generated configuration")
    print("   5. Run additional targeted scans as needed")
    print("   6. Document findings and remediation steps")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: security_summary.py <worklist-directory>")
        print("Example: security_summary.py worklists/www.example.com-20240101_120000")
        sys.exit(1)
    
    worklist_dir = sys.argv[1]
    print_security_summary(worklist_dir)
