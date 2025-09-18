#!/usr/bin/env python3
import json
import pathlib
import sys

def create_burp_config(urls_file, target_domain):
    """Create BurpSuite configuration with target URLs"""
    
    # Create burp directory
    burp_dir = pathlib.Path("burp")
    burp_dir.mkdir(exist_ok=True)
    
    # Read URLs
    urls = []
    if pathlib.Path(urls_file).exists():
        with open(urls_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    
    # Create Burp project configuration
    config = {
        "project_name": f"{target_domain}_gooberscan",
        "target_urls": urls,
        "scan_config": {
            "active_scan": True,
            "passive_scan": True,
            "crawl_depth": 3,
            "scan_speed": "normal"
        },
        "scope": {
            "include": urls,
            "exclude": []
        }
    }
    
    # Write config file
    config_file = burp_dir / f"{target_domain}_config.json"
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)
    
    # Create URL list file for Burp
    url_list_file = burp_dir / f"{target_domain}_urls.txt"
    with open(url_list_file, 'w') as f:
        for url in urls:
            f.write(f"{url}\n")
    
    print(f"[+] Created BurpSuite config: {config_file}")
    print(f"[+] Created URL list: {url_list_file}")
    print(f"[+] Found {len(urls)} URLs for BurpSuite scanning")
    
    return config_file, url_list_file

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: burp_integration.py <urls.txt> <target-domain>")
        sys.exit(1)
    
    urls_file, target_domain = sys.argv[1], sys.argv[2]
    create_burp_config(urls_file, target_domain)
