#!/usr/bin/env bash
set -euo pipefail

# Demo script for GooberScan Exposed Endpoints Feature
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                              ║"
echo "║                    🚨 EXPOSED ENDPOINTS FEATURE DEMO 🚨                      ║"
echo "║                                                                              ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

echo "🎯 This demo showcases the new Exposed Endpoints detection feature:"
echo ""
echo "1. 🔍 Response Code Analysis - Identifies endpoints with 200 OK, 301, 401, 403, etc."
echo "2. 🚨 Critical Exposure Detection - Sensitive endpoints that are fully accessible"
echo "3. 🟠 Risk Categorization - Categorizes exposure by sensitivity and response code"
echo "4. 📊 Comprehensive Reporting - Detailed analysis with response codes and sizes"
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

# Demo 1: Standalone Exposed Endpoints Analysis
echo "=== Demo 1: Standalone Exposed Endpoints Analysis ==="
echo "[*] Running standalone exposed endpoints detection..."
TARGET_DOMAIN=$(basename "$LATEST_SCAN" | cut -d'-' -f1)
python3 scripts/exposed_endpoints.py "$LATEST_SCAN" "https://$TARGET_DOMAIN"
echo ""

# Demo 2: Enhanced Aggregate Reports with Exposure Analysis
echo "=== Demo 2: Enhanced Aggregate Reports with Exposure Analysis ==="
echo "[*] Running enhanced aggregation with exposed endpoint detection..."
python3 scripts/enhanced_aggregate_reports.py --reports "$LATEST_SCAN"
echo ""

# Demo 3: Check Generated Files
echo "=== Demo 3: Generated Exposed Endpoint Files ==="
WL_DIR="worklists/$(basename "$LATEST_SCAN")"
if [ -d "$WL_DIR" ]; then
    echo "[*] Generated exposed endpoint files:"
    for file in "$WL_DIR"/exposed_*.txt; do
        if [ -f "$file" ]; then
            filename=$(basename "$file")
            count=$(wc -l < "$file")
            echo "   • $filename: $count endpoints"
        fi
    done
    echo ""
    
    # Show sample critical exposed endpoints
    if [ -f "$WL_DIR/exposed_critical_exposed.txt" ]; then
        echo "[*] Sample critical exposed endpoints:"
        while read -r endpoint; do
            echo "   🚨 $endpoint"
        done < "$WL_DIR/exposed_critical_exposed.txt"
    fi
    
    # Show sample high exposed endpoints
    if [ -f "$WL_DIR/exposed_high_exposed.txt" ]; then
        echo ""
        echo "[*] Sample high exposed endpoints:"
        head -3 "$WL_DIR/exposed_high_exposed.txt" | while read -r endpoint; do
            echo "   🟠 $endpoint"
        done
    fi
    
    # Show sample protected endpoints
    if [ -f "$WL_DIR/exposed_protected_endpoints.txt" ]; then
        echo ""
        echo "[*] Sample protected endpoints (401/403):"
        head -3 "$WL_DIR/exposed_protected_endpoints.txt" | while read -r endpoint; do
            echo "   🔒 $endpoint"
        done
    fi
else
    echo "[!] Worklist directory not found"
fi
echo ""

# Demo 4: Enhanced Security Summary
echo "=== Demo 4: Enhanced Security Summary with Exposure Analysis ==="
if [ -d "$WL_DIR" ]; then
    python3 scripts/security_summary.py "$WL_DIR"
else
    echo "[!] Worklist directory not found"
fi
echo ""

# Demo 5: Show Response Code Categories
echo "=== Demo 5: Response Code Categories ==="
echo "[*] Exposed endpoint detection categorizes by response codes:"
echo ""
echo "🚨 CRITICAL EXPOSED (Sensitive + 200 OK):"
echo "   • Fully accessible sensitive endpoints"
echo "   • Immediate security risk"
echo "   • Requires immediate action"
echo ""
echo "🟠 HIGH EXPOSED (Sensitive + Other Codes):"
echo "   • Sensitive endpoints with redirects/auth"
echo "   • May be exploitable with bypass techniques"
echo "   • Requires authentication testing"
echo ""
echo "🟡 MEDIUM EXPOSED (Non-sensitive + 200 OK):"
echo "   • Accessible but not inherently sensitive"
echo "   • May contain useful information"
echo "   • Lower priority for immediate action"
echo ""
echo "🔒 PROTECTED ENDPOINTS (401/403):"
echo "   • Require authentication"
echo "   • May be exploitable with auth bypass"
echo "   • Test authentication mechanisms"
echo ""

# Demo 6: Show Configuration Options
echo "=== Demo 6: Configuration Options ==="
echo "[*] Customize exposed endpoint detection in:"
echo "   scripts/enhanced_aggregate_reports.py"
echo ""
echo "[*] Response codes considered 'exposed':"
echo "   • 200, 201, 202, 204 (Critical - fully accessible)"
echo "   • 301, 302, 307, 308 (Redirects)"
echo "   • 401, 403 (Authentication required)"
echo "   • 405 (Method not allowed)"
echo ""
echo "[*] Sensitive endpoint patterns:"
echo "   • admin, login, auth, manage"
echo "   • api, config, database, phpmyadmin"
echo "   • upload, backup, dev, test"
echo "   • .git, .svn, logs, system"
echo ""

# Demo 7: Show Usage Examples
echo "=== Demo 7: Usage Examples ==="
echo "[*] Run standalone exposed endpoint analysis:"
echo "    python3 scripts/exposed_endpoints.py reports/<domain-timestamp> https://domain.com"
echo ""
echo "[*] Run enhanced aggregation with exposure analysis:"
echo "    python3 scripts/enhanced_aggregate_reports.py --reports reports/<domain-timestamp>"
echo ""
echo "[*] Generate comprehensive security summary:"
echo "    python3 scripts/security_summary.py worklists/<domain-timestamp>"
echo ""
echo "[*] Run full enhanced pipeline:"
echo "    scripts/pipeline.sh reports/<domain-timestamp>"
echo ""

echo "🎉 Exposed Endpoints Feature Demo Complete!"
echo ""
echo "📋 Key Benefits:"
echo "1. 🎯 Prioritized Risk Assessment - Focus on actually accessible endpoints"
echo "2. 🚨 Critical Exposure Detection - Identify sensitive endpoints with 200 OK"
echo "3. 📊 Response Code Analysis - Understand endpoint accessibility"
echo "4. 🔍 Comprehensive Categorization - Separate sensitive from exposed"
echo "5. 📁 Organized Output Files - Easy access to categorized endpoints"
echo ""
echo "🚀 Next Steps:"
echo "1. Review critical exposed endpoints for immediate action"
echo "2. Test protected endpoints for authentication bypass"
echo "3. Use exposed endpoint lists for manual testing"
echo "4. Apply security recommendations based on exposure analysis"
echo ""
echo "📖 Documentation: SECURITY_ENHANCEMENTS.md"
echo "🔍 Ready for advanced endpoint exposure analysis!"
