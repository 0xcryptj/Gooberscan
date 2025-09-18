#!/usr/bin/env bash
set -e

# Enhanced Red ASCII Alert Box Function
print_alert_box() {
  local title="$1"
  local content="$2"
  local max_width=80
  
  echo -e "\033[1;31m" # bright red
  echo "╔══════════════════════════════════════════════════════════════════════════════╗"
  echo "║                                                                              ║"
  printf "║ %-76s ║\n" "$title"
  echo "║                                                                              ║"
  
  if [ -n "$content" ]; then
    echo "$content" | while IFS= read -r line; do
      printf "║ %-76s ║\n" "$line"
    done
    echo "║                                                                              ║"
  fi
  
  echo "╚══════════════════════════════════════════════════════════════════════════════╝"
  echo -e "\033[0m"
}

# Enhanced Critical Finding Detection Function
detect_critical_findings() {
  local worklist_dir="$1"
  local critical_found=false
  local alert_content=""
  
  # Check for CVEs
  if [ -s "$worklist_dir/cves.txt" ]; then
    alert_content+="🚨 CVEs DETECTED:\n"
    while read -r line; do
      if [[ "$line" =~ CVE-[0-9]{4}-[0-9]+ ]]; then
        alert_content+="   • $line\n"
        critical_found=true
      fi
    done < "$worklist_dir/cves.txt"
    alert_content+="\n"
  fi
  
  # Check for critical exposed endpoints (highest priority)
  if [ -s "$worklist_dir/exposed_critical_exposed.txt" ]; then
    alert_content+="🚨 CRITICAL EXPOSED ENDPOINTS:\n"
    while read -r endpoint; do
      # Clean up the endpoint line and extract just the URL
      clean_url=$(echo "$endpoint" | sed 's/ (Status:.*//' | sed 's/\[[0-9;]*m//g')
      alert_content+="   • $clean_url\n"
      critical_found=true
    done < "$worklist_dir/exposed_critical_exposed.txt"
    alert_content+="\n"
  fi
  
  # Check for critical sensitive endpoints - convert to full URLs
  if [ -s "$worklist_dir/sensitive_critical.txt" ]; then
    alert_content+="🔴 CRITICAL SENSITIVE ENDPOINTS:\n"
    # Extract domain from worklist directory name
    domain=$(basename "$worklist_dir" | cut -d'-' -f1)
    base_url="https://$domain"
    
    while read -r path; do
      # Clean up the path and create full URL
      clean_path=$(echo "$path" | sed 's/ (Status:.*//' | sed 's/\[[0-9;]*m//g')
      if [[ "$clean_path" =~ ^https?:// ]]; then
        full_url="$clean_path"
      elif [[ "$clean_path" =~ ^/ ]]; then
        full_url="$base_url$clean_path"
      else
        full_url="$base_url/$clean_path"
      fi
      alert_content+="   • $full_url\n"
      critical_found=true
    done < "$worklist_dir/sensitive_critical.txt"
    alert_content+="\n"
  fi
  
  # Check for high-risk sensitive endpoints
  if [ -s "$worklist_dir/sensitive_high.txt" ]; then
    alert_content+="🟠 HIGH-RISK ENDPOINTS:\n"
    # Extract domain from worklist directory name
    domain=$(basename "$worklist_dir" | cut -d'-' -f1)
    base_url="https://$domain"
    
    count=0
    while read -r path && [ $count -lt 5 ]; do
      # Clean up the path and create full URL
      clean_path=$(echo "$path" | sed 's/ (Status:.*//' | sed 's/\[[0-9;]*m//g')
      if [[ "$clean_path" =~ ^https?:// ]]; then
        full_url="$clean_path"
      elif [[ "$clean_path" =~ ^/ ]]; then
        full_url="$base_url$clean_path"
      else
        full_url="$base_url/$clean_path"
      fi
      alert_content+="   • $full_url\n"
      count=$((count + 1))
    done < "$worklist_dir/sensitive_high.txt"
    
    if [ "$(wc -l < "$worklist_dir/sensitive_high.txt")" -gt 5 ]; then
      alert_content+="   ... and $(( $(wc -l < "$worklist_dir/sensitive_high.txt") - 5 )) more\n"
    fi
    alert_content+="\n"
  fi
  
  if [ "$critical_found" = true ]; then
    # Clean ANSI codes from alert content
    clean_alert_content=$(echo "$alert_content" | sed 's/\[[0-9;]*m//g')
    print_alert_box "🚨 CRITICAL SECURITY FINDINGS DETECTED 🚨" "$clean_alert_content"
  fi
  
  if [ "$critical_found" = true ]; then
    return 0
  else
    return 1
  fi
}

TARGET_RUN="${1:-}"
if [ -z "$TARGET_RUN" ]; then
  TARGET_RUN=$(ls -td reports/* 2>/dev/null | head -n1 || true)
fi
[ -z "$TARGET_RUN" ] && { echo "No reports/ run found. Provide path: scripts/pipeline.sh reports/<domain-timestamp>"; exit 1; }

echo "🔍 Processing: $(basename "$TARGET_RUN")"

# Extract domain and show basic info
DOMAIN=$(basename "$TARGET_RUN" | cut -d'-' -f1)
echo "🌐 Target: $DOMAIN"

# Show basic scan info
if [ -f "$TARGET_RUN/nmap.xml" ] || [ -f "$TARGET_RUN/nmap.txt" ]; then
    echo "📡 Nmap scan completed"
fi
if [ -f "$TARGET_RUN/nikto.txt" ]; then
    echo "🔍 Nikto scan completed"
fi
if [ -f "$TARGET_RUN/gobuster.txt" ]; then
    echo "📂 Directory enumeration completed"
fi
if [ -f "$TARGET_RUN/ffuf.txt" ]; then
    echo "🔍 ffuf scan completed"
fi

echo "⚙️  Processing scan results..."

# 1) Aggregate with enhanced sensitive endpoint detection (silent)
python3 scripts/enhanced_aggregate_reports.py --reports "$TARGET_RUN" >/dev/null 2>&1

WL="worklists/$(basename "$TARGET_RUN")"
mkdir -p "$WL" audit

# Show useful information
echo ""
echo "📊 SCAN SUMMARY:"
echo "================"

# Show hosts and ports
if [ -f "$WL/hosts.txt" ] && [ -s "$WL/hosts.txt" ]; then
    echo "🖥️  HOSTS & PORTS:"
    cat "$WL/hosts.txt" | head -10
    if [ "$(wc -l < "$WL/hosts.txt")" -gt 10 ]; then
        echo "   ... and $(( $(wc -l < "$WL/hosts.txt") - 10 )) more hosts"
    fi
    echo ""
else
    echo "🖥️  HOSTS & PORTS: No nmap data available"
    echo ""
fi

# Show CVEs
if [ -f "$WL/cves.txt" ] && [ -s "$WL/cves.txt" ]; then
    echo "🚨 VULNERABILITIES FOUND:"
    cat "$WL/cves.txt" | head -5
    if [ "$(wc -l < "$WL/cves.txt")" -gt 5 ]; then
        echo "   ... and $(( $(wc -l < "$WL/cves.txt") - 5 )) more CVEs"
    fi
    echo ""
fi

# Show server info from nikto
if [ -f "$TARGET_RUN/nikto.txt" ]; then
    echo "🖥️  SERVER INFORMATION:"
    grep -E "(Server:|OSVDB-|CVE-)" "$TARGET_RUN/nikto.txt" | head -5
    echo ""
fi

# Show DNS provider information
echo "🌐 DNS INFRASTRUCTURE:"
python3 scripts/dns_provider_detection.py "$DOMAIN" --quiet --output "$WL/dns_info.json" 2>/dev/null
if [ -f "$WL/dns_info.json" ]; then
    # Extract key DNS info
    nameservers=$(python3 -c "
import json
try:
    with open('$WL/dns_info.json') as f:
        data = json.load(f)
    providers = set([p['provider'] for p in data['dns_providers']])
    ips = data['a_records'][:3]  # First 3 IPs
    print('Providers:', ', '.join(sorted(providers)))
    print('IPs:', ', '.join(ips))
except:
    pass
")
    echo "   $nameservers"
else
    echo "   DNS analysis failed"
fi
echo ""

# Re-run aggregation to include DNS info
python3 scripts/enhanced_aggregate_reports.py --reports "$TARGET_RUN" >/dev/null 2>&1

# 1.5) Detect Critical Findings
CRITICAL_FOUND=false
if detect_critical_findings "$WL"; then
  CRITICAL_FOUND=true
fi

if [ "$CRITICAL_FOUND" = false ]; then
  echo "[*] No critical findings detected in initial analysis"
fi
echo ""

# 2) ZAP baseline on each discovered URL (skip path-only lines)
ZAP_OUT="audit/$(basename "$TARGET_RUN")-zap"
mkdir -p "$ZAP_OUT"

# Check Docker availability and permissions
check_docker_availability() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "[!] Docker not found; skipping ZAP runs."
    return 1
  fi
  
  # Test Docker permissions
  if ! docker ps >/dev/null 2>&1; then
    echo "[!] Docker permission denied. Attempting to fix..."
    echo "[*] Adding user to docker group..."
    sudo usermod -aG docker "$USER" 2>/dev/null || true
    echo "[*] Starting Docker service..."
    sudo systemctl start docker 2>/dev/null || true
    echo "[!] Please log out and back in, then run: newgrp docker"
    echo "[!] Or run: sudo docker ps to test Docker access"
    return 1
  fi
  
  return 0
}

# Alternative ZAP installation check
check_zap_local() {
  if command -v zaproxy >/dev/null 2>&1; then
    echo "[*] Using local ZAP installation"
    return 0
  fi
  
  echo "[*] Attempting to install ZAP locally..."
  if command -v apt >/dev/null 2>&1; then
    sudo apt update && sudo apt install -y zaproxy 2>/dev/null || true
    if command -v zaproxy >/dev/null 2>&1; then
      echo "[+] ZAP installed locally"
      return 0
    fi
  fi
  
  return 1
}

# Run ZAP scans (silent)
if check_docker_availability >/dev/null 2>&1; then
  echo "🔍 Running ZAP scans..."
  while read -r url; do
    [[ -z "$url" || "$url" =~ ^/ ]] && continue
    safe="$(echo "$url" | sed 's/[:\/]/_/g')"
    docker run --rm -v "$(pwd)":/zap/wrk/ -t owasp/zap2docker-stable \
      zap-baseline.py -t "$url" -r "$ZAP_OUT/${safe}.html" >/dev/null 2>&1 || true
  done < "$WL/urls.txt"
elif check_zap_local >/dev/null 2>&1; then
  echo "🔍 Running ZAP scans..."
  while read -r url; do
    [[ -z "$url" || "$url" =~ ^/ ]] && continue
    safe="$(echo "$url" | sed 's/[:\/]/_/g')"
    zaproxy -cmd -quickurl "$url" -quickout "$ZAP_OUT/${safe}.html" >/dev/null 2>&1 || true
  done < "$WL/urls.txt"
fi

# Skip intrusive scans by default (can be enabled manually)
# Uncomment the following lines if you want to run intrusive scans:
# read -r -p "Run INTRUSIVE scans? (sqlmap on params + ZAP full per URL) [y/N]: " INTR
# INTR=${INTR:-N}
# if [[ "${INTR,,}" =~ ^y ]]; then
#   # Intrusive scans would go here
# fi

# 4) CVE hints → SearchSploit lookup (silent)
EXP_OUT="audit/$(basename "$TARGET_RUN")-exploits.txt"
: > "$EXP_OUT"
if command -v searchsploit >/dev/null 2>&1 && [ -s "$WL/cves.txt" ]; then
  echo "🔍 Searching for exploits..."
  while read -r line; do
    [ -z "$line" ] && continue
    echo -e "\n### $line" >> "$EXP_OUT"
    searchsploit "$line" >> "$EXP_OUT" 2>/dev/null || true
  done < "$WL/cves.txt"
fi

# 5) Generate audit markdown (silent)
MD="audit/$(basename "$TARGET_RUN")-summary.md"
AGG="$WL/aggregate.json"
echo "# GooberScan Follow-up Summary — $(basename "$TARGET_RUN")" > "$MD"
echo >> "$MD"
echo "## Hosts & Open Ports" >> "$MD"
if [ -s "$WL/hosts.txt" ]; then
  sed 's/^/- /' "$WL/hosts.txt" >> "$MD"
else
  echo "_none parsed_" >> "$MD"
fi
echo -e "\n## Discovered URLs (deduped)\n" >> "$MD"
if [ -s "$WL/urls.txt" ]; then
  head -n 100 "$WL/urls.txt" | sed 's/^/- /' >> "$MD"
  echo -e "\n_(truncated if >100)_" >> "$MD"
else
  echo "_none_" >> "$MD"
fi
echo -e "\n## Parameterized URLs (sqlmap candidates)\n" >> "$MD"
if [ -s "$WL/params.txt" ]; then
  sed 's/^/- /' "$WL/params.txt" >> "$MD"
else
  echo "_none_" >> "$MD"
fi
echo -e "\n## CVE / Version Hints\n" >> "$MD"
if [ -s "$WL/cves.txt" ]; then
  sed 's/^/- /' "$WL/cves.txt" >> "$MD"
else
  echo "_none_" >> "$MD"
fi
echo -e "\n## Artifacts\n" >> "$MD"
echo "- ZAP reports: \`$ZAP_OUT/\`" >> "$MD"
echo "- SearchSploit results: \`$EXP_OUT\`" >> "$MD"

# 6) Auto-Chain Critical Findings
# Extract target domain from run name
TARGET_DOMAIN=$(basename "$TARGET_RUN" | cut -d'-' -f1)

# Generate Metasploit RC if CVEs found
if [ -s "$WL/cves.txt" ]; then
  echo "🎯 Generating targeted Metasploit RC..."
  python3 scripts/gen_msf_rc.py "$WL" "$TARGET_DOMAIN" >/dev/null 2>&1
  MSF_RC="audit/${TARGET_DOMAIN}-auto.rc"
  if [ -f "$MSF_RC" ]; then
    print_alert_box "🎯 TARGETED METASPLOIT RC GENERATED" "File: $MSF_RC\nOnly includes modules for detected CVEs\nTo run: msfconsole -r $MSF_RC"
  fi
fi

# Generate BurpSuite config if URLs found
if [ -s "$WL/urls.txt" ]; then
  echo "🔧 Generating BurpSuite configuration..."
  python3 scripts/burp_integration.py "$WL/urls.txt" "$TARGET_DOMAIN" >/dev/null 2>&1
fi

# Generate comprehensive security summary
echo "📋 Generating security summary..."
python3 scripts/security_summary.py "$WL" >/dev/null 2>&1

# Final Summary
echo ""
echo "✅ ANALYSIS COMPLETE"
echo "==================="
echo "📁 Results: worklists/$(basename "$WL")/"
echo "📋 Report: audit/$(basename "$WL")-summary.md"
if [ -f "audit/${TARGET_DOMAIN}-auto.rc" ]; then
  echo "🎯 Metasploit: audit/${TARGET_DOMAIN}-auto.rc"
fi
if [ -f "burp/${TARGET_DOMAIN}_config.json" ]; then
  echo "🔧 BurpSuite: burp/${TARGET_DOMAIN}_config.json"
fi
echo "🔍 ZAP Results: audit/$(basename "$WL")-zap/"
echo ""
echo "🚀 Ready for manual testing!"
