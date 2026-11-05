#!/usr/bin/env python3
"""Read-only audit of CDN DNS A records for real website HTTPS compatibility.

Run from GitHub Actions (not a mainland-China latency probe). No DNS writes.
The published gray-cloud A pool is audited as-is. Only an empty or
inconsistent pool is rejected before the HTTPS checks.
"""
import concurrent.futures
import os
import sys
from collections import Counter

import requests

from dnscf import audit_site_https, dns_records


HOSTS = ("www.jia.nz", "cook.jia.nz")
CDN_NAME = "cdn.yigeyao.com"
# Same bounds as CF_DNS_RECORD_COUNT in dnscf.py. The configured target lives
# in dns_cf.yml and is intentionally not repeated here.
POOL_MIN = 1
POOL_MAX = 100


def consistent_gray_cloud_ips(records):
    """Sorted unique DNS-only addresses, or None when the pool is not auditable.

    A consistent pool is entirely gray-cloud, has one address per A record,
    and stays inside the updater's 1-100 record limit. The audit follows
    whatever size that updater last published.
    """
    if not isinstance(records, list) or not POOL_MIN <= len(records) <= POOL_MAX:
        return None
    contents = []
    for record in records:
        if not isinstance(record, dict) or record.get("proxied") is not False:
            return None
        content = record.get("content")
        if not isinstance(content, str) or not content:
            return None
        contents.append(content)
    unique = sorted(set(contents))
    if len(unique) != len(records):
        return None
    return unique


def main():
    token = os.environ.get("CF_API_TOKEN")
    zone_id = os.environ.get("CF_ZONE_ID")
    if not token or not zone_id:
        print("Missing CF_API_TOKEN / CF_ZONE_ID (DNS read-only access required)")
        return 2

    with requests.Session() as session:
        records = dns_records(session, zone_id, CDN_NAME, token)
    ips = consistent_gray_cloud_ips(records)
    if ips is None:
        gray = {
            record.get("content")
            for record in records
            if isinstance(record, dict)
            and record.get("proxied") is False
            and isinstance(record.get("content"), str)
            and record.get("content")
        }
        print(
            f"Unexpected {CDN_NAME} A pool: {len(records)} entries, "
            f"{len(gray)} unique gray-cloud IPs "
            f"(need {POOL_MIN}-{POOL_MAX} unique DNS-only A records)"
        )
        return 2

    print(f"Auditing {len(ips)} CDN IPs x {len(HOSTS)} HTTPS sites.")
    print("Values are measured from a GitHub runner, NOT from mainland China.")
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        jobs = {
            executor.submit(audit_site_https, ip, host, "/", 5.0): (host, ip)
            for host in HOSTS for ip in ips
        }
        for future in concurrent.futures.as_completed(jobs):
            host, ip = jobs[future]
            try:
                data = future.result()
            except Exception as exc:
                data = {"ip": ip, "ok": False, "error": type(exc).__name__}
            results[(host, ip)] = data

    failures = 0
    for host in HOSTS:
        good = sorted((v for (h, _), v in results.items() if h == host and v["ok"]),
                      key=lambda v: v["response_header_ms"])
        bad = sorted((v for (h, _), v in results.items() if h == host and not v["ok"]),
                     key=lambda v: v["ip"])
        failures += len(bad)
        metrics = [v["response_header_ms"] for v in good]
        if metrics:
            print(f"{host}: {len(good)}/{len(ips)} HTTPS valid, "
                  f"response-header time min={min(metrics):.0f}ms, "
                  f"median={sorted(metrics)[len(metrics) // 2]:.0f}ms, max={max(metrics):.0f}ms")
        else:
            print(f"{host}: 0/{len(ips)} HTTPS valid")
        for v in bad:
            print(f"  FAILED {host} {v['ip']}: {v.get('status', v.get('error'))}")
        print("  HTTP statuses:", dict(Counter(v.get("status", "network-error") for
                                           (h, _), v in results.items() if h == host)))

    print(f"All-site compatible IPs: "
          f"{sum(all(results[(host, ip)]['ok'] for host in HOSTS) for ip in ips)}/{len(ips)}")
    if failures:
        print("Some currently published IPs failed HTTPS checks; see details above.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
