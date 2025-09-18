#!/bin/bash
#
# Nmap Intense Scan Script
# Performs comprehensive port discovery using multiple scan techniques
#

TARGET="$1"
OUTPUT_DIR="$2"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target> [output_dir]"
    echo "Example: $0 example.com /tmp/nmap_results"
    exit 1
fi

if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="./nmap_intense_$(date +%Y%m%d_%H%M%S)"
fi

mkdir -p "$OUTPUT_DIR"

echo "🎯 Starting Nmap Intense Scan"
echo "Target: $TARGET"
echo "Output: $OUTPUT_DIR"
echo "=================================="

# Phase 1: Quick scan of top 1000 ports
echo ""
echo "📡 Phase 1: Quick scan of top 1000 ports..."
nmap -T4 -sT -sV -O --top-ports 1000 "$TARGET" \
    -oN "$OUTPUT_DIR/nmap-quick.txt" \
    -oX "$OUTPUT_DIR/nmap-quick.xml" \
    -oG "$OUTPUT_DIR/nmap-quick.grep" \
    2>/dev/null || echo "Quick scan completed with warnings"

# Phase 2: Full port scan (all 65535 ports)
echo "📡 Phase 2: Full port scan (all 65535 ports)..."
nmap -T4 -sT -sV -O -p- "$TARGET" \
    -oN "$OUTPUT_DIR/nmap-full.txt" \
    -oX "$OUTPUT_DIR/nmap-full.xml" \
    -oG "$OUTPUT_DIR/nmap-full.grep" \
    2>/dev/null || echo "Full scan completed with warnings"

# Phase 3: Aggressive scan with scripts
echo "📡 Phase 3: Aggressive scan with scripts..."
nmap -T4 -sT -sV -O -A --script vuln,discovery,auth "$TARGET" \
    -oN "$OUTPUT_DIR/nmap-aggressive.txt" \
    -oX "$OUTPUT_DIR/nmap-aggressive.xml" \
    -oG "$OUTPUT_DIR/nmap-aggressive.grep" \
    2>/dev/null || echo "Aggressive scan completed with warnings"

# Phase 4: UDP scan of common ports
echo "📡 Phase 4: UDP scan of common ports..."
nmap -T4 -sU --top-ports 1000 "$TARGET" \
    -oN "$OUTPUT_DIR/nmap-udp.txt" \
    -oX "$OUTPUT_DIR/nmap-udp.xml" \
    -oG "$OUTPUT_DIR/nmap-udp.grep" \
    2>/dev/null || echo "UDP scan completed with warnings"

# Phase 5: Service detection on open ports
echo "📡 Phase 5: Service detection on open ports..."
# Extract open ports from previous scans
OPEN_PORTS=$(grep -h "open" "$OUTPUT_DIR"/nmap-*.txt | grep -o "[0-9]*/tcp" | sort -u | tr '\n' ',' | sed 's/,$//')
if [ -n "$OPEN_PORTS" ]; then
    nmap -T4 -sV -sC -O --script vuln "$TARGET" -p "$OPEN_PORTS" \
        -oN "$OUTPUT_DIR/nmap-services.txt" \
        -oX "$OUTPUT_DIR/nmap-services.xml" \
        2>/dev/null || echo "Service detection completed with warnings"
fi

# Combine results
echo "📡 Combining scan results..."
cat "$OUTPUT_DIR"/nmap-*.txt > "$OUTPUT_DIR/nmap-combined.txt" 2>/dev/null || true
cp "$OUTPUT_DIR/nmap-aggressive.xml" "$OUTPUT_DIR/nmap.xml" 2>/dev/null || true

# Generate summary
echo ""
echo "📊 SCAN SUMMARY"
echo "==============="
echo "Target: $TARGET"
echo "Scan completed: $(date)"
echo ""
echo "📁 Generated files:"
ls -la "$OUTPUT_DIR"/nmap-*.txt "$OUTPUT_DIR"/nmap-*.xml 2>/dev/null | while read -r line; do
    echo "   $line"
done

# Show open ports summary
echo ""
echo "🔍 OPEN PORTS DISCOVERED:"
if [ -f "$OUTPUT_DIR/nmap.xml" ]; then
    python3 -c "
import xml.etree.ElementTree as ET
try:
    tree = ET.parse('$OUTPUT_DIR/nmap.xml')
    root = tree.getroot()
    for host in root.findall('host'):
        addr = None
        for a in host.findall('address'):
            if a.get('addrtype') in ('ipv4', 'ipv6'):
                addr = a.get('addr')
                break
        if addr:
            ports = []
            for ports_el in host.findall('ports'):
                for p in ports_el.findall('port'):
                    state = p.find('state')
                    if state is not None and state.get('state') == 'open':
                        portnum = p.get('portid')
                        proto = p.get('protocol')
                        service = p.find('service')
                        svc = service.get('name') if service is not None else ''
                        product = service.get('product') if service is not None else ''
                        version = service.get('version') if service is not None else ''
                        if product and version:
                            svc += f' ({product} {version})'
                        elif product:
                            svc += f' ({product})'
                        ports.append(f'{portnum}/{proto}/{svc}')
            if ports:
                print(f'   {addr}:')
                for port in ports:
                    print(f'     • {port}')
            else:
                print(f'   {addr}: No open ports')
except Exception as e:
    print(f'   Error parsing nmap XML: {e}')
" 2>/dev/null || echo "   Error parsing nmap results"
else
    echo "   No nmap XML results available"
fi

echo ""
echo "✅ Nmap intense scan completed!"
echo "📁 Results saved to: $OUTPUT_DIR"
