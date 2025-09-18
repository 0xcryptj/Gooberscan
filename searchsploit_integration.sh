#!/usr/bin/env bash
set -euo pipefail

# SearchSploit Integration Script
# Usage: ./searchsploit_integration.sh <worklists_directory>

if [ $# -ne 1 ]; then
    echo "Usage: $0 <worklists_directory>"
    echo "Example: $0 worklists/example.com-20250917_123456"
    exit 1
fi

WL_DIR="$1"
CVES_FILE="$WL_DIR/cves.txt"

if [ ! -f "$CVES_FILE" ]; then
    echo "[!] CVEs file not found: $CVES_FILE"
    exit 1
fi

echo "[*] Searching exploit-db for CVEs and vulnerabilities..."
echo "[*] Input: $CVES_FILE"
echo ""

# Check if searchsploit is available
if ! command -v searchsploit >/dev/null 2>&1; then
    echo "[!] searchsploit not found. Installing exploitdb..."
    sudo apt update && sudo apt install -y exploitdb
fi

# Create output directory
OUT_DIR="exploit-results/$(basename "$WL_DIR")"
mkdir -p "$OUT_DIR"

echo "[*] Searching for exploits..."
echo ""

COUNT=0
while read -r line; do
    if [[ -z "$line" ]]; then
        continue
    fi
    
    COUNT=$((COUNT + 1))
    echo "[$COUNT] Searching: $line"
    
    # Extract potential search terms
    SEARCH_TERMS=()
    
    # Look for CVE numbers
    if [[ "$line" =~ CVE-[0-9]{4}-[0-9]+ ]]; then
        SEARCH_TERMS+=("$BASH_REMATCH")
    fi
    
    # Look for version numbers
    if [[ "$line" =~ [0-9]+\.[0-9]+(\.[0-9]+)? ]]; then
        SEARCH_TERMS+=("$BASH_REMATCH")
    fi
    
    # Look for software names
    if [[ "$line" =~ (Apache|nginx|WordPress|PHP|MySQL|PostgreSQL|OpenSSH|OpenSSL) ]]; then
        SEARCH_TERMS+=("$BASH_REMATCH")
    fi
    
    # Search for each term
    for term in "${SEARCH_TERMS[@]}"; do
        echo "  [+] Searching: $term"
        searchsploit "$term" > "$OUT_DIR/search_${term//[^a-zA-Z0-9]/_}.txt" 2>/dev/null || true
        
        # Check if any results found
        if [ -s "$OUT_DIR/search_${term//[^a-zA-Z0-9]/_}.txt" ]; then
            echo "    [!] Potential exploits found for: $term"
        else
            echo "    [-] No exploits found for: $term"
        fi
    done
    
    echo ""
    
done < "$CVES_FILE"

echo "[+] SearchSploit analysis completed!"
echo "[+] Results saved to: $OUT_DIR"
echo ""
echo "To manually test exploits (WARNING: Only on authorized targets):"
echo "  msfconsole -q"
echo "  # Then use: use exploit/... and set appropriate options"
