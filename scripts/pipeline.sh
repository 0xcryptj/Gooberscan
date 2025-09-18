#!/usr/bin/env bash
set -euo pipefail

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
      alert_content+="   • $endpoint\n"
      critical_found=true
    done < "$worklist_dir/exposed_critical_exposed.txt"
    alert_content+="\n"
  fi
  
  # Check for critical sensitive endpoints
  if [ -s "$worklist_dir/sensitive_critical.txt" ]; then
    alert_content+="🔴 CRITICAL SENSITIVE ENDPOINTS:\n"
    while read -r url; do
      alert_content+="   • $url\n"
      critical_found=true
    done < "$worklist_dir/sensitive_critical.txt"
    alert_content+="\n"
  fi
  
  # Check for high-risk sensitive endpoints
  if [ -s "$worklist_dir/sensitive_high.txt" ]; then
    alert_content+="🟠 HIGH-RISK ENDPOINTS:\n"
    head -5 "$worklist_dir/sensitive_high.txt" | while read -r url; do
      alert_content+="   • $url\n"
    done
    if [ "$(wc -l < "$worklist_dir/sensitive_high.txt")" -gt 5 ]; then
      alert_content+="   ... and $(( $(wc -l < "$worklist_dir/sensitive_high.txt") - 5 )) more\n"
    fi
    alert_content+="\n"
  fi
  
  if [ "$critical_found" = true ]; then
    print_alert_box "🚨 CRITICAL SECURITY FINDINGS DETECTED 🚨" "$alert_content"
  fi
  
  return $critical_found
}

TARGET_RUN="${1:-}"
if [ -z "$TARGET_RUN" ]; then
  TARGET_RUN=$(ls -td reports/* 2>/dev/null | head -n1 || true)
fi
[ -z "$TARGET_RUN" ] && { echo "No reports/ run found. Provide path: scripts/pipeline.sh reports/<domain-timestamp>"; exit 1; }

echo "[*] Using reports: $TARGET_RUN"

# 1) Aggregate with enhanced sensitive endpoint detection
python3 scripts/enhanced_aggregate_reports.py --reports "$TARGET_RUN"

WL="worklists/$(basename "$TARGET_RUN")"
mkdir -p "$WL" audit

# 1.5) Detect Critical Findings
echo ""
echo "=== Critical Finding Analysis ==="
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

# Run ZAP scans
if check_docker_availability; then
  echo "[*] Running ZAP baseline scans with Docker..."
  while read -r url; do
    [[ -z "$url" || "$url" =~ ^/ ]] && continue
    safe="$(echo "$url" | sed 's/[:\/]/_/g')"
    echo "[*] ZAP baseline: $url"
    docker run --rm -v "$(pwd)":/zap/wrk/ -t owasp/zap2docker-stable \
      zap-baseline.py -t "$url" -r "$ZAP_OUT/${safe}.html" || true
  done < "$WL/urls.txt"
elif check_zap_local; then
  echo "[*] Running ZAP baseline scans with local installation..."
  while read -r url; do
    [[ -z "$url" || "$url" =~ ^/ ]] && continue
    safe="$(echo "$url" | sed 's/[:\/]/_/g')"
    echo "[*] ZAP baseline: $url"
    zaproxy -cmd -quickurl "$url" -quickout "$ZAP_OUT/${safe}.html" || true
  done < "$WL/urls.txt"
else
  echo "[!] Neither Docker nor local ZAP available; skipping ZAP runs."
  echo "[*] To fix Docker: sudo usermod -aG docker \$USER && newgrp docker"
  echo "[*] To install ZAP locally: sudo apt install zaproxy"
fi

# 3) Optional intrusive steps (guarded)
read -r -p "Run INTRUSIVE scans? (sqlmap on params + ZAP full per URL) [y/N]: " INTR
INTR=${INTR:-N}

if [[ "${INTR,,}" =~ ^y ]]; then
  # ZAP full (intrusive)
  if command -v docker >/dev/null 2>&1; then
    while read -r url; do
      [[ -z "$url" || "$url" =~ ^/ ]] && continue
      safe="$(echo "$url" | sed 's/[:\/]/_/g')"
      echo "[*] ZAP full: $url"
      docker run --rm -v "$(pwd)":/zap/wrk/ -t owasp/zap2docker-stable \
        zap-full-scan.py -t "$url" -r "$ZAP_OUT/${safe}-full.html" || true
    done < "$WL/urls.txt"
  fi

  # sqlmap on parameterized URLs
  SQL_OUT="audit/$(basename "$TARGET_RUN")-sqlmap"
  mkdir -p "$SQL_OUT"
  if [ -s "$WL/params.txt" ]; then
    while read -r purl; do
      [ -z "$purl" ] && continue
      safe="$(echo "$purl" | sed 's/[:\/?&=]/_/g')"
      echo "[*] sqlmap: $purl"
      sqlmap -u "$purl" --batch --level=3 --risk=2 -o --output-dir="$SQL_OUT/$safe" || true
    done < "$WL/params.txt"
  else
    echo "[*] No parameterized URLs found for sqlmap."
  fi
fi

# 4) CVE hints → SearchSploit lookup (non-intrusive)
EXP_OUT="audit/$(basename "$TARGET_RUN")-exploits.txt"
: > "$EXP_OUT"
if command -v searchsploit >/dev/null 2>&1 && [ -s "$WL/cves.txt" ]; then
  echo "[*] SearchSploit lookup…" | tee -a "$EXP_OUT"
  while read -r line; do
    [ -z "$line" ] && continue
    echo -e "\n### $line" | tee -a "$EXP_OUT"
    searchsploit "$line" | tee -a "$EXP_OUT" || true
  done < "$WL/cves.txt"
else
  echo "[*] SearchSploit not available or no CVEs captured; skipping." | tee -a "$EXP_OUT"
fi

# 5) Minimal audit markdown
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
echo "- sqlmap outputs: \`${SQL_OUT:-N/A}\`" >> "$MD"
echo "- SearchSploit results: \`$EXP_OUT\`" >> "$MD"

# 6) Auto-Chain Critical Findings
echo ""
echo "=== Auto-Chaining Critical Findings ==="

# Extract target domain from run name
TARGET_DOMAIN=$(basename "$TARGET_RUN" | cut -d'-' -f1)

# Generate Metasploit RC if CVEs found
if [ -s "$WL/cves.txt" ]; then
  echo "[*] Generating targeted Metasploit RC file..."
  python3 scripts/gen_msf_rc.py "$WL" "$TARGET_DOMAIN"
  MSF_RC="audit/${TARGET_DOMAIN}-auto.rc"
  if [ -f "$MSF_RC" ]; then
    print_alert_box "🎯 TARGETED METASPLOIT RC GENERATED" "File: $MSF_RC\nOnly includes modules for detected CVEs\nTo run: msfconsole -r $MSF_RC"
    echo "[*] To run: msfconsole -r $MSF_RC"
  fi
else
  echo "[*] No CVEs detected - skipping Metasploit RC generation"
fi

# Generate BurpSuite config if URLs found
if [ -s "$WL/urls.txt" ]; then
  echo "[*] Generating BurpSuite configuration..."
  python3 scripts/burp_integration.py "$WL/urls.txt" "$TARGET_DOMAIN"
  BURP_CONFIG="burp/${TARGET_DOMAIN}_config.json"
  if [ -f "$BURP_CONFIG" ]; then
    echo "[+] BurpSuite config created: $BURP_CONFIG"
    echo "[*] Import URLs from: burp/${TARGET_DOMAIN}_urls.txt"
  fi
fi

# Generate comprehensive security summary
echo ""
echo "=== Generating Security Summary ==="
python3 scripts/security_summary.py "$WL"

# Final Summary
echo ""
echo "[✓] Pipeline complete."
echo "Worklists: $WL"
echo "Audit: $MD"

if [ "$CRITICAL_FOUND" = true ]; then
  echo ""
  print_alert_box "CRITICAL FINDINGS DETECTED - REVIEW REQUIRED"
  echo "[*] Check audit summary: $MD"
  echo "[*] Review worklists for manual testing"
  if [ -f "audit/${TARGET_DOMAIN}-auto.rc" ]; then
    echo "[*] Metasploit RC ready: audit/${TARGET_DOMAIN}-auto.rc"
  fi
  if [ -f "burp/${TARGET_DOMAIN}_config.json" ]; then
    echo "[*] BurpSuite config ready: burp/${TARGET_DOMAIN}_config.json"
  fi
fi
