#!/usr/bin/env bash
set -euo pipefail

# ZAP Follow-up Scanning Script
# Usage: ./zap_followup.sh <worklists_directory>

if [ $# -ne 1 ]; then
    echo "Usage: $0 <worklists_directory>"
    echo "Example: $0 worklists/example.com-20250917_123456"
    exit 1
fi

WL_DIR="$1"
URLS_FILE="$WL_DIR/urls.txt"
OUT_DIR="goober-zap-results/$(basename "$WL_DIR")"

if [ ! -f "$URLS_FILE" ]; then
    echo "[!] URLs file not found: $URLS_FILE"
    exit 1
fi

echo "[*] Starting ZAP follow-up scans..."
echo "[*] Input: $URLS_FILE"
echo "[*] Output: $OUT_DIR"
echo ""

mkdir -p "$OUT_DIR"

# Count total URLs
TOTAL_URLS=$(grep -c "^https\?://" "$URLS_FILE" || echo "0")
echo "[*] Found $TOTAL_URLS URLs to scan"
echo ""

# Scan each URL with ZAP baseline
COUNT=0
while read -r url; do
    # Skip blank lines and paths starting with "/"
    if [[ -z "$url" || "$url" =~ ^/ ]]; then 
        continue
    fi
    
    COUNT=$((COUNT + 1))
    echo "[$COUNT/$TOTAL_URLS] ZAP baseline for $url"
    
    # Create safe filename
    SAFE_NAME=$(echo "$url" | sed 's/[:\/]/_/g' | sed 's/[^a-zA-Z0-9._-]//g')
    
    # Run ZAP baseline scan
    docker run --rm -v "$(pwd)":/zap/wrk/:rw -t owasp/zap2docker-stable \
        zap-baseline.py -t "$url" -r "$OUT_DIR/${SAFE_NAME}.html" || echo "  [!] Scan failed for $url"
    
    echo "  [+] Report saved: $OUT_DIR/${SAFE_NAME}.html"
    echo ""
    
done < "$URLS_FILE"

echo "[+] ZAP follow-up scanning completed!"
echo "[+] Reports saved to: $OUT_DIR"
echo ""
echo "To run intrusive active scans (WARNING: Only on authorized targets):"
echo "  ./zap_active.sh $WL_DIR"
