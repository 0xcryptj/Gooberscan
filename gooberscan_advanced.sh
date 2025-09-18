#!/usr/bin/env bash
set -euo pipefail

# Gooberscan Advanced Post-Processing Script
# Usage: ./gooberscan_advanced.sh [reports_directory]

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                              ║"
echo "║                    Gooberscan Advanced Post-Processing                     ║"
echo "║                                                                              ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

# Determine reports directory
if [ $# -eq 1 ]; then
    REPORTS_DIR="$1"
else
    # Use the latest reports directory
    REPORTS_DIR=$(ls -td reports/* 2>/dev/null | head -n1 || echo "")
fi

if [ -z "$REPORTS_DIR" ] || [ ! -d "$REPORTS_DIR" ]; then
    echo "[!] No reports directory found."
    echo "[!] Usage: $0 [reports_directory]"
    echo "[!] Or run Gooberscan first to generate reports."
    exit 1
fi

echo "[*] Using reports directory: $REPORTS_DIR"
echo ""

# Step 1: Aggregate reports
echo "=== Step 1: Aggregating Reports ==="
python3 aggregate_reports.py --reports "$REPORTS_DIR"
echo ""

# Step 2: ZAP Follow-up Scanning
echo "=== Step 2: ZAP Follow-up Scanning ==="
WL_DIR="worklists/$(basename "$REPORTS_DIR")"
if [ -f "$WL_DIR/urls.txt" ]; then
    echo "[*] Running ZAP baseline scans on discovered URLs..."
    ./zap_followup.sh "$WL_DIR"
else
    echo "[!] No URLs found for ZAP scanning"
fi
echo ""

# Step 3: SearchSploit Analysis
echo "=== Step 3: SearchSploit Analysis ==="
if [ -f "$WL_DIR/cves.txt" ]; then
    echo "[*] Searching for exploits..."
    ./searchsploit_integration.sh "$WL_DIR"
else
    echo "[!] No CVEs found for exploit search"
fi
echo ""

# Step 4: Summary
echo "=== Summary ==="
echo "[+] Reports processed: $REPORTS_DIR"
echo "[+] Worklists created: $WL_DIR"
echo "[+] Files generated:"
echo "    - hosts.txt: $(wc -l < "$WL_DIR/hosts.txt" 2>/dev/null || echo "0") hosts"
echo "    - urls.txt: $(wc -l < "$WL_DIR/urls.txt" 2>/dev/null || echo "0") URLs"
echo "    - params.txt: $(wc -l < "$WL_DIR/params.txt" 2>/dev/null || echo "0") parameterized URLs"
echo "    - cves.txt: $(wc -l < "$WL_DIR/cves.txt" 2>/dev/null || echo "0") CVE/vulnerability hints"
echo ""

if [ -d "goober-zap-results/$(basename "$REPORTS_DIR")" ]; then
    echo "[+] ZAP reports: goober-zap-results/$(basename "$REPORTS_DIR")"
fi

if [ -d "exploit-results/$(basename "$REPORTS_DIR")" ]; then
    echo "[+] Exploit search results: exploit-results/$(basename "$REPORTS_DIR")"
fi

echo ""
echo "🎉 Advanced post-processing completed!"
echo ""
echo "Next steps:"
echo "1. Review worklists for interesting targets"
echo "2. Use Burp Suite with urls.txt and params.txt"
echo "3. Manually test exploits found in exploit-results/"
echo "4. Run additional targeted scans as needed"
