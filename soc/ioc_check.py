#!/usr/bin/env python3
"""
Bulk IOC lookup against VirusTotal (v3) and AbuseIPDB.
Accepts IPs, domains, and file hashes (MD5/SHA1/SHA256).
Auto-detects IOC type. Writes JSON report on completion.

Prerequisites:
    export VT_API_KEY=your_vt_key
    export ABUSEIPDB_KEY=your_abuseipdb_key

Usage:
    ./ioc_check.py 1.2.3.4 evil.com d41d8cd98f00b204e9800998ecf8427e
    ./ioc_check.py -f ioc_list.txt
"""

import os
import sys
import time
import json
import argparse
import ipaddress
import urllib.request
import urllib.error
from datetime import datetime

VT_KEY    = os.environ.get("VT_API_KEY", "")
ABUSE_KEY = os.environ.get("ABUSEIPDB_KEY", "")
REPORT    = f"ioc_results_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
results   = []


def vt_lookup(ioc_type: str, value: str) -> dict | None:
    endpoints = {
        "ip":     f"https://www.virustotal.com/api/v3/ip_addresses/{value}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{value}",
        "hash":   f"https://www.virustotal.com/api/v3/files/{value}",
    }
    url = endpoints.get(ioc_type)
    if not url or not VT_KEY:
        return None
    req = urllib.request.Request(url, headers={"x-apikey": VT_KEY})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            data  = json.loads(r.read())
            stats = data.get("data", {}).get("attributes", {}) \
                        .get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total     = sum(stats.values()) if stats else 0
            return {"source": "virustotal", "malicious": malicious, "total": total,
                    "verdict": "MALICIOUS" if malicious > 3 else
                               "SUSPICIOUS" if malicious > 0 else "CLEAN"}
    except urllib.error.HTTPError as e:
        return {"source": "virustotal", "error": str(e)}


def abuse_lookup(ip: str) -> dict | None:
    if not ABUSE_KEY:
        return None
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=30"
    req = urllib.request.Request(
        url, headers={"Key": ABUSE_KEY, "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            d = json.loads(r.read()).get("data", {})
            score = d.get("abuseConfidenceScore", 0)
            return {
                "source":    "abuseipdb",
                "score":     score,
                "reports":   d.get("totalReports", 0),
                "country":   d.get("countryCode", "?"),
                "usage":     d.get("usageType", "?"),
                "isp":       d.get("isp", "?"),
                "verdict":   "MALICIOUS" if score > 75 else
                             "SUSPICIOUS" if score > 25 else "CLEAN",
            }
    except urllib.error.HTTPError as e:
        return {"source": "abuseipdb", "error": str(e)}


def detect_type(ioc: str) -> str:
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError:
        pass
    if len(ioc) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in ioc):
        return "hash"
    if "." in ioc and not ioc.startswith("http"):
        return "domain"
    return "unknown"


def check_ioc(ioc: str):
    ioc = ioc.strip()
    if not ioc or ioc.startswith("#"):
        return

    ioc_type = detect_type(ioc)
    if ioc_type == "unknown":
        print(f"[?] Skipping unrecognised IOC: {ioc}")
        return

    print(f"[*] {ioc_type.upper()}: {ioc}")
    entry = {"ioc": ioc, "type": ioc_type, "findings": [], "overall": "UNKNOWN"}

    vt = vt_lookup(ioc_type, ioc)
    if vt:
        entry["findings"].append(vt)
        if "error" not in vt:
            print(f"    VT: {vt['malicious']}/{vt['total']} engines | {vt['verdict']}")

    if ioc_type == "ip":
        ab = abuse_lookup(ioc)
        if ab:
            entry["findings"].append(ab)
            if "error" not in ab:
                print(f"    AbuseIPDB: score={ab['score']} | {ab['reports']} reports "
                      f"| {ab['country']} | {ab['verdict']}")

    # roll up overall verdict
    verdicts = [f.get("verdict", "UNKNOWN") for f in entry["findings"]]
    if "MALICIOUS" in verdicts:
        entry["overall"] = "MALICIOUS"
    elif "SUSPICIOUS" in verdicts:
        entry["overall"] = "SUSPICIOUS"
    elif verdicts:
        entry["overall"] = "CLEAN"

    results.append(entry)
    time.sleep(0.5)


def summary():
    counts = {"MALICIOUS": 0, "SUSPICIOUS": 0, "CLEAN": 0, "UNKNOWN": 0}
    for r in results:
        counts[r.get("overall", "UNKNOWN")] = counts.get(r.get("overall", "UNKNOWN"), 0) + 1
    print(f"\n[+] Summary: {counts}")


def main():
    parser = argparse.ArgumentParser(description="Bulk IOC checker (VT + AbuseIPDB)")
    parser.add_argument("iocs", nargs="*", help="IOCs: IPs, domains, hashes")
    parser.add_argument("-f", "--file", help="File with one IOC per line")
    args = parser.parse_args()

    ioc_list = list(args.iocs)
    if args.file:
        with open(args.file) as fh:
            ioc_list += [line.strip() for line in fh if line.strip()]

    if not ioc_list:
        parser.print_help()
        sys.exit(1)

    if not VT_KEY and not ABUSE_KEY:
        print("[!] No API keys set. Export VT_API_KEY and/or ABUSEIPDB_KEY.")

    for ioc in ioc_list:
        check_ioc(ioc)

    summary()

    with open(REPORT, "w") as fh:
        json.dump(results, fh, indent=2)
    print(f"[+] Report saved: {REPORT}")


if __name__ == "__main__":
    main()
