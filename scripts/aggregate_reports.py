#!/usr/bin/env python3
import argparse, json, re, sys
from pathlib import Path
import xml.etree.ElementTree as ET

URL_RE   = re.compile(r"https?://[^\s'\"<>]+")
PARAM_RE = re.compile(r"[?&][^=]+=[^&\s]+")

def parse_nmap_xml(p):
    hosts=[]
    try:
        root=ET.parse(p).getroot()
    except Exception as e:
        print(f"[!] nmap xml parse failed: {p} -> {e}")
        return hosts
    for h in root.findall('host'):
        ip=None
        for a in h.findall('address'):
            if a.get('addrtype') in ('ipv4','ipv6'): ip=a.get('addr')
        if not ip: continue
        openp=[]
        for ps in h.findall('ports'):
            for pt in ps.findall('port'):
                st=pt.find('state')
                if st is not None and st.get('state')=='open':
                    svc=pt.find('service')
                    openp.append({
                      "port": int(pt.get('portid')),
                      "proto": pt.get('protocol','tcp'),
                      "service": (svc.get('name') if svc is not None else ""),
                      "product": (svc.get('product') if svc is not None else ""),
                      "version": (svc.get('version') if svc is not None else "")
                    })
        hosts.append({"ip":ip,"open_ports":openp})
    return hosts

def read_text(path):
    try:
        return Path(path).read_text(errors='ignore')
    except: return ""

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--reports", required=True, help="reports/<domain-timestamp> folder")
    args=ap.parse_args()
    rpt=Path(args.reports)
    if not rpt.exists(): sys.exit(f"missing {rpt}")

    outdir = Path("worklists")/rpt.name
    outdir.mkdir(parents=True, exist_ok=True)

    # Collect inputs
    nmap_xml = next(iter(rpt.glob("*.xml")), None)
    gob_txt  = next(iter(rpt.glob("*gobuster*.txt")), None)
    ffuf_json= next(iter(rpt.glob("ffuf*.json")), None)
    nikto_txt= next(iter(rpt.glob("nikto*.txt")), None)
    wpscan_txt= next(iter(rpt.glob("wpscan*.txt")), None)
    zap_html = list(rpt.glob("zap-*.html"))  # optional baseline/full reports

    result = {"run": rpt.name, "hosts": [], "urls": [], "params": [], "cves": [], "notes": []}

    # nmap
    if nmap_xml:
        result["hosts"]=parse_nmap_xml(nmap_xml)

    # gobuster urls
    if gob_txt:
        for line in read_text(gob_txt).splitlines():
            m = URL_RE.search(line)
            if m: result["urls"].append(m.group(0))
            elif line.startswith("/"): result["urls"].append(line.strip())

    # ffuf urls
    if ffuf_json and ffuf_json.exists():
        try:
            data=json.loads(read_text(ffuf_json))
            for it in data.get("results",[]):
                url = it.get("url") or it.get("input",{}).get("url") or it.get("input")
                if url: result["urls"].append(url)
        except Exception as e:
            result["notes"].append(f"ffuf parse error: {e}")

    # nikto & wpscan: collect URLs/CVEs/versions
    def harvest_txt(fp):
        txt=read_text(fp)
        for l in txt.splitlines():
            if "CVE-" in l.upper(): result["cves"].append(l.strip())
            m=URL_RE.search(l)
            if m: result["urls"].append(m.group(0))
    if nikto_txt:  harvest_txt(nikto_txt)
    if wpscan_txt: harvest_txt(wpscan_txt)

    # de-dupe
    urls=sorted(set([u.strip() for u in result["urls"] if u.strip()]))
    result["urls"]=urls
    # params
    params=sorted(set([u for u in urls if PARAM_RE.search(u)]))
    result["params"]=params
    # cves dedupe
    result["cves"]=sorted(set([c.strip() for c in result["cves"] if c.strip()]))

    # write worklists
    (outdir/"hosts.txt").write_text(
        "\n".join([f"{h['ip']} "+" ".join([f"{p['port']}/{p['service']}" for p in h['open_ports']]) for h in result["hosts"]])+"\n" if result["hosts"] else ""
    )
    (outdir/"urls.txt").write_text("\n".join(urls)+"\n" if urls else "")
    (outdir/"params.txt").write_text("\n".join(params)+"\n" if params else "")
    (outdir/"cves.txt").write_text("\n".join(result["cves"])+"\n" if result["cves"] else "")

    # machine-readable export for pipeline
    Path("worklists").mkdir(exist_ok=True, parents=True)
    (outdir/"aggregate.json").write_text(json.dumps(result, indent=2))

    print(f"[+] Aggregated → {outdir}")
if __name__=="__main__": main()
