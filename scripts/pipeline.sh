#!/usr/bin/env bash
set -euo pipefail

TARGET_RUN="${1:-}"
if [ -z "$TARGET_RUN" ]; then
  TARGET_RUN=$(ls -td reports/* 2>/dev/null | head -n1 || true)
fi
[ -z "$TARGET_RUN" ] && { echo "No reports/ run found. Provide path: scripts/pipeline.sh reports/<domain-timestamp>"; exit 1; }

echo "[*] Using reports: $TARGET_RUN"

# 1) Aggregate
python3 scripts/aggregate_reports.py --reports "$TARGET_RUN"

WL="worklists/$(basename "$TARGET_RUN")"
mkdir -p "$WL" audit

# 2) ZAP baseline on each discovered URL (skip path-only lines)
ZAP_OUT="audit/$(basename "$TARGET_RUN")-zap"
mkdir -p "$ZAP_OUT"
if command -v docker >/dev/null 2>&1; then
  while read -r url; do
    [[ -z "$url" || "$url" =~ ^/ ]] && continue
    safe="$(echo "$url" | sed 's/[:\/]/_/g')"
    echo "[*] ZAP baseline: $url"
    docker run --rm -v "$(pwd)":/zap/wrk/ -t owasp/zap2docker-stable \
      zap-baseline.py -t "$url" -r "$ZAP_OUT/${safe}.html" || true
  done < "$WL/urls.txt"
else
  echo "[!] docker not found; skipping ZAP runs."
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

echo "[✓] Pipeline complete."
echo "Worklists: $WL"
echo "Audit: $MD"
