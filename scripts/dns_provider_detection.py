#!/usr/bin/env python3
"""
DNS Provider Detection Script
Identifies DNS providers, nameservers, and DNS infrastructure for a target domain
"""

import argparse
import json
import socket
import subprocess
import sys
from pathlib import Path
import dns.resolver
import dns.reversename

# DNS Provider signatures
DNS_PROVIDERS = {
    'Cloudflare': ['cloudflare.com', 'cloudflare-dns.com'],
    'Google DNS': ['google.com', 'google-public-dns-a.google.com'],
    'Amazon Route 53': ['amazonaws.com', 'awsdns-'],
    'GoDaddy': ['godaddy.com', 'secureserver.net'],
    'Namecheap': ['namecheap.com', 'registrar-servers.com'],
    'DigitalOcean': ['digitalocean.com', 'do-dns.com'],
    'Linode': ['linode.com', 'linode-dns.com'],
    'OVH': ['ovh.com', 'ovh.net'],
    'Hetzner': ['hetzner.com', 'hetzner-dns.com'],
    'DNSimple': ['dnsimple.com'],
    'EasyDNS': ['easydns.com'],
    'Dyn': ['dyn.com', 'dynect.net'],
    'UltraDNS': ['ultradns.com', 'ultradns.net'],
    'Akamai': ['akamai.com', 'akamai.net'],
    'Fastly': ['fastly.com', 'fastlylb.net'],
    'KeyCDN': ['keycdn.com'],
    'MaxCDN': ['maxcdn.com'],
    'Incapsula': ['incapsula.com'],
    'Sucuri': ['sucuri.net'],
    'SiteLock': ['sitelock.com'],
    'WordPress.com': ['wordpress.com'],
    'Squarespace': ['squarespace.com'],
    'Wix': ['wix.com', 'wixdns.net'],
    'Shopify': ['shopify.com'],
    'Bluehost': ['bluehost.com'],
    'HostGator': ['hostgator.com'],
    'SiteGround': ['siteground.com'],
    'DreamHost': ['dreamhost.com'],
    'InMotion': ['inmotionhosting.com'],
    'A2 Hosting': ['a2hosting.com'],
    'GreenGeeks': ['greengeeks.com'],
    'WP Engine': ['wpengine.com'],
    'Kinsta': ['kinsta.com'],
    'Pantheon': ['pantheon.io'],
    'Netlify': ['netlify.com'],
    'Vercel': ['vercel.com'],
    'GitHub Pages': ['github.io', 'github.com'],
    'GitLab Pages': ['gitlab.io', 'gitlab.com'],
    'Firebase': ['firebase.com'],
    'Heroku': ['heroku.com'],
    'Railway': ['railway.app'],
    'Render': ['render.com'],
    'Fly.io': ['fly.io'],
    'DigitalOcean App Platform': ['ondigitalocean.app'],
    'AWS Amplify': ['amplifyapp.com'],
    'Azure Static Web Apps': ['azurestaticapps.net'],
    'Cloudflare Pages': ['pages.dev'],
    'Vercel': ['vercel.app'],
    'Netlify': ['netlify.app']
}

def get_nameservers(domain):
    """Get nameservers for a domain"""
    try:
        # Remove www. prefix if present
        clean_domain = domain.replace('www.', '')
        
        # Query for NS records
        ns_records = dns.resolver.resolve(clean_domain, 'NS')
        nameservers = [str(ns).rstrip('.') for ns in ns_records]
        
        return nameservers
    except Exception as e:
        print(f"[!] Error getting nameservers for {domain}: {e}")
        return []

def get_mx_records(domain):
    """Get MX records for a domain"""
    try:
        clean_domain = domain.replace('www.', '')
        mx_records = dns.resolver.resolve(clean_domain, 'MX')
        mx_servers = []
        for mx in mx_records:
            mx_servers.append({
                'priority': mx.preference,
                'server': str(mx.exchange).rstrip('.')
            })
        return mx_servers
    except Exception as e:
        print(f"[!] Error getting MX records for {domain}: {e}")
        return []

def get_a_records(domain):
    """Get A records for a domain"""
    try:
        clean_domain = domain.replace('www.', '')
        a_records = dns.resolver.resolve(clean_domain, 'A')
        ip_addresses = [str(ip) for ip in a_records]
        return ip_addresses
    except Exception as e:
        print(f"[!] Error getting A records for {domain}: {e}")
        return []

def get_aaaa_records(domain):
    """Get AAAA records for a domain"""
    try:
        clean_domain = domain.replace('www.', '')
        aaaa_records = dns.resolver.resolve(clean_domain, 'AAAA')
        ipv6_addresses = [str(ip) for ip in aaaa_records]
        return ipv6_addresses
    except Exception as e:
        print(f"[!] Error getting AAAA records for {domain}: {e}")
        return []

def get_txt_records(domain):
    """Get TXT records for a domain"""
    try:
        clean_domain = domain.replace('www.', '')
        txt_records = dns.resolver.resolve(clean_domain, 'TXT')
        txt_values = []
        for txt in txt_records:
            txt_values.append(str(txt).strip('"'))
        return txt_values
    except Exception as e:
        print(f"[!] Error getting TXT records for {domain}: {e}")
        return []

def identify_dns_provider(nameserver):
    """Identify DNS provider based on nameserver"""
    nameserver_lower = nameserver.lower()
    
    for provider, signatures in DNS_PROVIDERS.items():
        for signature in signatures:
            if signature.lower() in nameserver_lower:
                return provider
    
    return "Unknown"

def get_whois_info(domain):
    """Get WHOIS information for a domain"""
    try:
        clean_domain = domain.replace('www.', '')
        result = subprocess.run(['whois', clean_domain], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            return result.stdout
        else:
            return None
    except Exception as e:
        print(f"[!] Error getting WHOIS info for {domain}: {e}")
        return None

def analyze_dns_infrastructure(domain):
    """Analyze DNS infrastructure for a domain"""
    print(f"[*] Analyzing DNS infrastructure for: {domain}")
    
    # Get DNS records
    nameservers = get_nameservers(domain)
    mx_records = get_mx_records(domain)
    a_records = get_a_records(domain)
    aaaa_records = get_aaaa_records(domain)
    txt_records = get_txt_records(domain)
    
    # Identify DNS providers
    dns_providers = []
    for ns in nameservers:
        provider = identify_dns_provider(ns)
        dns_providers.append({
            'nameserver': ns,
            'provider': provider
        })
    
    # Get WHOIS info
    whois_info = get_whois_info(domain)
    
    # Compile results
    dns_info = {
        'domain': domain,
        'nameservers': nameservers,
        'dns_providers': dns_providers,
        'mx_records': mx_records,
        'a_records': a_records,
        'aaaa_records': aaaa_records,
        'txt_records': txt_records,
        'whois_info': whois_info
    }
    
    return dns_info

def print_dns_summary(dns_info):
    """Print a summary of DNS information"""
    print(f"\n🌐 DNS INFRASTRUCTURE ANALYSIS")
    print(f"Domain: {dns_info['domain']}")
    print("=" * 50)
    
    # Nameservers and Providers
    if dns_info['nameservers']:
        print(f"\n📡 NAMESERVERS:")
        for provider_info in dns_info['dns_providers']:
            ns = provider_info['nameserver']
            provider = provider_info['provider']
            print(f"   • {ns} ({provider})")
    else:
        print(f"\n📡 NAMESERVERS: None found")
    
    # IP Addresses
    if dns_info['a_records']:
        print(f"\n🖥️  IP ADDRESSES (A):")
        for ip in dns_info['a_records']:
            print(f"   • {ip}")
    
    if dns_info['aaaa_records']:
        print(f"\n🖥️  IPV6 ADDRESSES (AAAA):")
        for ip in dns_info['aaaa_records']:
            print(f"   • {ip}")
    
    # MX Records
    if dns_info['mx_records']:
        print(f"\n📧 MAIL SERVERS (MX):")
        for mx in dns_info['mx_records']:
            print(f"   • {mx['server']} (Priority: {mx['priority']})")
    
    # TXT Records
    if dns_info['txt_records']:
        print(f"\n📝 TXT RECORDS:")
        for txt in dns_info['txt_records'][:5]:  # Show first 5
            if len(txt) > 80:
                txt = txt[:80] + "..."
            print(f"   • {txt}")
        if len(dns_info['txt_records']) > 5:
            print(f"   ... and {len(dns_info['txt_records']) - 5} more")
    
    # DNS Provider Summary
    providers = set([p['provider'] for p in dns_info['dns_providers']])
    if providers:
        print(f"\n🏢 DNS PROVIDERS:")
        for provider in sorted(providers):
            print(f"   • {provider}")

def main():
    parser = argparse.ArgumentParser(description='DNS Provider Detection')
    parser.add_argument('domain', help='Domain to analyze')
    parser.add_argument('--output', '-o', help='Output file for JSON results')
    parser.add_argument('--quiet', '-q', action='store_true', help='Quiet mode (JSON only)')
    
    args = parser.parse_args()
    
    try:
        # Analyze DNS infrastructure
        dns_info = analyze_dns_infrastructure(args.domain)
        
        if not args.quiet:
            print_dns_summary(dns_info)
        
        # Save results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(dns_info, f, indent=2)
            print(f"\n[+] Results saved to: {args.output}")
        
        return dns_info
        
    except KeyboardInterrupt:
        print("\n[!] Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error during analysis: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
