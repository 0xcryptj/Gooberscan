#!/usr/bin/env bash
set -euo pipefail

# Demo script for GooberScan Enhanced Security Features
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                              ║"
echo "║                    🚀 GOOBERSCAN ENHANCED FEATURES DEMO 🚀                   ║"
echo "║                                                                              ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

echo "🎯 This demo showcases the new GooberScan security enhancements:"
echo ""
echo "1. 🔍 Sensitive Endpoint Detection & Categorization"
echo "2. 🚨 Enhanced ASCII Alert System"
echo "3. 🐳 Docker Permission Fixes"
echo "4. 🎯 Targeted Metasploit Integration"
echo "5. 📊 Comprehensive Security Summary"
echo ""

# Check if we have existing scan results
LATEST_SCAN=$(ls -td reports/* 2>/dev/null | head -n1 || echo "")
if [ -z "$LATEST_SCAN" ]; then
    echo "[!] No scan results found. Please run GooberScan first:"
    echo "    ./gooberscan"
    echo ""
    echo "Or use existing results:"
    echo "    scripts/pipeline.sh reports/<domain-timestamp>"
    exit 1
fi

echo "[*] Using latest scan results: $LATEST_SCAN"
echo ""

# Demo 1: Enhanced Aggregation
echo "=== Demo 1: Enhanced Sensitive Endpoint Detection ==="
echo "[*] Running enhanced aggregation with sensitive endpoint categorization..."
python3 scripts/enhanced_aggregate_reports.py --reports "$LATEST_SCAN"
echo ""

# Demo 2: Security Summary
echo "=== Demo 2: Comprehensive Security Summary ==="
WL_DIR="worklists/$(basename "$LATEST_SCAN")"
if [ -d "$WL_DIR" ]; then
    python3 scripts/security_summary.py "$WL_DIR"
else
    echo "[!] Worklist directory not found: $WL_DIR"
fi
echo ""

# Demo 3: Check for sensitive endpoint files
echo "=== Demo 3: Sensitive Endpoint Files ==="
if [ -d "$WL_DIR" ]; then
    echo "[*] Generated sensitive endpoint files:"
    for level in critical high medium low; do
        file="$WL_DIR/sensitive_${level}.txt"
        if [ -f "$file" ]; then
            count=$(wc -l < "$file")
            echo "   • sensitive_${level}.txt: $count endpoints"
        fi
    done
    echo ""
    
    # Show sample critical endpoints
    if [ -f "$WL_DIR/sensitive_critical.txt" ]; then
        echo "[*] Sample critical endpoints (first 5):"
        head -5 "$WL_DIR/sensitive_critical.txt" | while read -r endpoint; do
            echo "   🔴 $endpoint"
        done
    fi
else
    echo "[!] Worklist directory not found"
fi
echo ""

# Demo 4: Docker fix demonstration
echo "=== Demo 4: Docker Fix Script ==="
echo "[*] Docker fix script available: ./fix-docker.sh"
echo "[*] This script will:"
echo "   • Check Docker installation and permissions"
echo "   • Add user to docker group"
echo "   • Start Docker service"
echo "   • Install ZAP locally as backup"
echo "   • Test Docker functionality"
echo ""

# Demo 5: Enhanced pipeline
echo "=== Demo 5: Enhanced Pipeline ==="
echo "[*] Run the enhanced pipeline:"
echo "    scripts/pipeline.sh $LATEST_SCAN"
echo ""
echo "[*] The enhanced pipeline will:"
echo "   • Detect and categorize sensitive endpoints"
echo "   • Display critical findings in ASCII alert boxes"
echo "   • Fix Docker permissions automatically"
echo "   • Generate targeted Metasploit RC (only if CVEs found)"
echo "   • Create comprehensive security summary"
echo ""

# Demo 6: Show available tools
echo "=== Demo 6: Available Enhanced Tools ==="
echo "[*] New scripts available:"
echo "   • scripts/enhanced_aggregate_reports.py - Sensitive endpoint detection"
echo "   • scripts/security_summary.py - Comprehensive security analysis"
echo "   • fix-docker.sh - Docker permission fixes"
echo "   • scripts/gen_msf_rc.py - Targeted Metasploit RC generation"
echo ""

# Demo 7: Show configuration options
echo "=== Demo 7: Configuration Options ==="
echo "[*] Customize sensitive endpoint patterns in:"
echo "   scripts/enhanced_aggregate_reports.py (SENSITIVE_PATTERNS)"
echo ""
echo "[*] Add CVE-to-module mappings in:"
echo "   scripts/gen_msf_rc.py (CVE_MODULE_MAP)"
echo ""

echo "🎉 Enhanced GooberScan Features Demo Complete!"
echo ""
echo "📋 Next Steps:"
echo "1. Run enhanced pipeline: scripts/pipeline.sh $LATEST_SCAN"
echo "2. Review sensitive endpoints in worklists/"
echo "3. Fix Docker issues: ./fix-docker.sh"
echo "4. Use generated tools for manual testing"
echo "5. Apply security recommendations"
echo ""
echo "📖 Documentation: SECURITY_ENHANCEMENTS.md"
echo "🚀 Ready for enterprise-grade security analysis!"
