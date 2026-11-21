#!/usr/bin/env python3
"""Sync validated, carrier-balanced Cloudflare IPs into DNS A records.

The upstream pools supply the carrier rankings. Connectivity checks from a
GitHub runner are only an availability guard, not a China-network speed test.
"""

import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from aggregate_ips import fetch_cf_networks

ROOT = Path(__file__).resolve().parent
API_ROOT = "https://api.cloudflare.com/client/v4"
REQUEST_TIMEOUT = 20


class DnsSyncError(RuntimeError):
    pass


def cf_api(session, method, endpoint, token, **kwargs):
    url = API_ROOT + endpoint
    try:
        response = session.request(
            method, url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=REQUEST_TIMEOUT, **kwargs,
        )
        payload = response.json()
    except (requests.RequestException, ValueError) as exc:
        raise DnsSyncError(f"Cloudflare API request failed ({method} {endpoint}): {exc}") from exc
    if not isinstance(payload, dict):
        raise DnsSyncError(f"Unexpected Cloudflare API response ({method} {endpoint})")
    if response.status_code >= 400 or payload.get("success") is not True:
        errors = payload.get("errors", []) if isinstance(payload, dict) else []
        raise DnsSyncError(f"Cloudflare API rejected {method} {endpoint}: HTTP {response.status_code}; {errors}")
    return payload


def dns_records(session, zone_id, dns_name, token):
    """Query exact A records, across all pages (not the first zone page)."""
    found = []
    page = 1
    while True:
        payload = cf_api(
            session, "GET", f"/zones/{zone_id}/dns_records", token,
            params={"name.exact": dns_name, "type": "A", "page": page, "per_page": 100},
        )
        found.extend(
            rec for rec in payload.get("result", [])
            if rec.get("name") == dns_name and rec.get("type") == "A"
        )
        total_pages = int(payload.get("result_info", {}).get("total_pages", 1))
        if page >= total_pages:
            break
        page += 1
    # Keep the API record intact. limit_rotation reads modified_on / created_on
    # from these objects; dropping them would freeze eviction on record ID.
    return sorted(found, key=lambda rec: rec["id"])


def load_status(root=ROOT):
    path = root / "data" / "status.json"
    try:
        status = json.loads(path.read_text(encoding="utf-8"))
        updated = datetime.strptime(status["generated_at"], "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise DnsSyncError(f"IP pool status is missing or invalid: {exc}") from exc
    age = datetime.now(timezone.utc) - updated
    if not -timedelta(minutes=5) <= age <= timedelta(hours=2):
        raise DnsSyncError(f"IP pool is stale: generated at {updated.isoformat()}")
    if int(status.get("healthy_sources", 0)) <= 0:
        raise DnsSyncError("No working upstream IP sources; DNS records were not changed")
    return status


def load_pool(group, root=ROOT):
    path = root / "api" / f"{group}.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        items = payload["items"]
        if not isinstance(items, list):
            raise ValueError("items is not an array")
        return items
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise DnsSyncError(f"IP pool {group} is missing or invalid: {exc}") from exc


def valid_cf_ip(item, networks):
    try:
        if int(item.get("port", 443)) != 443:
            return None
        address = ipaddress.ip_address(item["ip"])
        if address.version != 4 or not address.is_global:
            return None
        if not any(address in network for network in networks):
            return None
        return str(address)
    except (AttributeError, KeyError, TypeError, ValueError):
        return None



def reported_metrics(item):
    """Read upstream-reported RTT and throughput from descriptive IP tags."""
    tag = str(item.get("tag", ""))
    latency = re.search(r"(?<!\d)(\d+(?:\.\d+)?)\s*ms\b", tag, re.IGNORECASE)
    speed = re.search(r"(?<!\d)(\d+(?:\.\d+)?)\s*mb/s\b", tag, re.IGNORECASE)
    rtt_ms = float(latency.group(1)) if latency else None
    speed_mb = float(speed.group(1)) if speed else None
    return rtt_ms, speed_mb


def candidate_rank(item, index):
    """Prefer measured, usable low RTT; then geographically plausible CN routes.

    Missing RTT is not treated as zero RTT. Upstream measurements come from
    their own probes, not GitHub Actions runners or the end user's network.
    """
    rtt, speed = reported_metrics(item)
    if speed is not None and speed < 1.0:
        return None  # A low RTT with almost no throughput is not a good endpoint.
    if rtt is not None and 0 < rtt <= 300:
        # Chinese carrier/source measurements matter more than US runner latency.
        # A bounded throughput bonus avoids choosing a slow-download IP solely
        # because it advertises a slightly lower RTT. Unknown speed earns no bonus.
        throughput_bonus = 3.0 * min(max(speed, 0.0), 25.0) if speed is not None else 0.0
        return (0, round(rtt - throughput_bonus, 3), index)
    if speed is not None:
        # A verified download figure without RTT is better evidence than geography.
        return (1, -min(speed, 100.0), index)
    label = (str(item.get("tag", "")) + " " + str(item.get("source", ""))).upper()
    if any(token in label for token in ("HKG", "HONG KONG", "香港")):
        region = 0
    elif any(token in label for token in ("TPE", "TWN", "TAIPEI", "台湾")):
        region = 1
    elif any(token in label for token in ("NRT", "TYO", "TOKYO", "日本", "东京")):
        region = 2
    elif any(token in label for token in ("SIN", "SINGAPORE", "新加坡")):
        region = 3
    elif any(token in label for token in ("LAX", "SJC", "SFO", "FRA", "LHR")):
        region = 6
    else:
        region = 4
    return (2, region, index)


def pick_ips(pools, count, networks, probe=None, max_reported_rtt=None, require_reported_rtt=False):
    """Select candidates, optionally requiring a hard upstream-reported RTT ceiling."""
    carriers = ("ct", "cu", "cmcc")
    quota = {carrier: count // 3 + (i < count % 3)
             for i, carrier in enumerate(carriers)}
    ordered = {}
    for group in (*carriers, "all"):
        candidates = []
        for index, item in enumerate(pools[group]):
            if require_reported_rtt or max_reported_rtt is not None:
                rtt, _ = reported_metrics(item)
                if rtt is None or rtt <= 0:
                    continue
                if max_reported_rtt is not None and rtt > max_reported_rtt:
                    continue
                # Strict latency mode deliberately ranks by RTT only. This is
                # an upstream measurement, not a claim about every CN city.
                rank = (0, rtt, index)
            else:
                rank = candidate_rank(item, index)
            if rank is not None:
                candidates.append((rank, item))
        ordered[group] = [item for _, item in sorted(candidates, key=lambda p: p[0])]

    selected = []
    seen = set()
    checked = {}
    chosen_by_carrier = dict.fromkeys(carriers, 0)
    cursors = dict.fromkeys(carriers, 0)

    def try_add(item, carrier=None):
        ip = valid_cf_ip(item, networks)
        if not ip or ip in seen:
            return False
        if ip not in checked:
            checked[ip] = bool(probe(ip)) if probe is not None else True
        if not checked[ip]:
            return False
        seen.add(ip)
        selected.append(ip)
        if carrier:
            chosen_by_carrier[carrier] += 1
        return True

    # Interleave low-RTT candidates across CT / CU / CMCC to avoid single-network bias.
    while len(selected) < count and any(chosen_by_carrier[g] < quota[g] for g in carriers):
        advanced = False
        for group in carriers:
            if chosen_by_carrier[group] >= quota[group]:
                continue
            while cursors[group] < len(ordered[group]):
                item = ordered[group][cursors[group]]
                cursors[group] += 1
                if try_add(item, group):
                    advanced = True
                    break
            if len(selected) >= count:
                break
        if not advanced:
            break

    # A carrier may have fewer usable IPs; borrow from other carrier pools and all.
    for group in (*carriers, "all"):
        for item in ordered[group]:
            if len(selected) >= count:
                break
            try_add(item)
        if len(selected) >= count:
            break

    if len(selected) < count:
        raise DnsSyncError(
            f"Only {len(selected)} validated IPs for a target of {count}; DNS unchanged"
        )
    if require_reported_rtt or max_reported_rtt is not None:
        ceiling = f" <= {max_reported_rtt:g} ms" if max_reported_rtt is not None else ""
        print(f"Strict RTT pool: {len(selected)} selected with explicit upstream RTT{ceiling}; "
              f"carrier contributions {chosen_by_carrier}")
    else:
        print(f"Carrier priorities: {chosen_by_carrier}; unknown RTT stays unscored")
    return selected


def tcp_reachable(ip, timeout=2.0):
    try:
        with socket.create_connection((ip, 443), timeout=timeout):
            return True
    except OSError:
        return False



def _parse_cf_time(value):
    """Parse a Cloudflare RFC3339 timestamp. Unparseable values count as missing."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    if "." in text:
        head, tail = text.split(".", 1)
        frac, sign, tz = tail, "", ""
        for marker in ("+", "-"):
            if marker in tail:
                frac, tz = tail.split(marker, 1)
                sign = marker
                break
        frac = (frac[:6]).ljust(6, "0")
        text = f"{head}.{frac}{sign}{tz}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _rotation_age_key(rec):
    """Oldest first: modified_on, otherwise created_on, otherwise record ID.

    PATCHed rows keep their Cloudflare ID and only move forward in modified_on,
    so ID order must not decide which stale address stays.
    """
    modified = _parse_cf_time(rec.get("modified_on"))
    created = _parse_cf_time(rec.get("created_on"))
    when = modified or created or datetime.min.replace(tzinfo=timezone.utc)
    return (when, str(rec.get("id") or ""))


def limit_rotation(records, desired, max_changes=6):
    """Keep a working DNS address pool stable; replace at most N IPs per run.

    Stale addresses (not in the new preferred set) are evicted oldest-first.
    Age is modified_on, then created_on, then record ID. An address that is
    still preferred is never dropped to free a slot for a stale one.
    Initial provisioning, and size repairs, are allowed to complete immediately.
    This is DNS-pool stability, NOT proof that retained IPs work for all visitors.
    """
    if not 0 <= max_changes <= 100:
        raise DnsSyncError("CF_DNS_MAX_ROTATIONS must be between 0 and 100")
    if not records or len(records) != len(desired):
        return desired
    current = [rec["content"] for rec in records]
    current_set = set(current)
    target_set = set(desired)
    incoming = [ip for ip in desired if ip not in current_set]
    if len(incoming) <= max_changes:
        return desired
    age_by_ip = {}
    for rec in records:
        ip = rec["content"]
        key = _rotation_age_key(rec)
        if ip not in age_by_ip or key < age_by_ip[ip]:
            age_by_ip[ip] = key
    stale = [ip for ip in current if ip not in target_set]
    stale.sort(key=lambda ip: age_by_ip[ip])
    kept_stale = stale[max_changes:]
    unchanged = [ip for ip in desired if ip in current_set]
    result = unchanged + incoming[:max_changes] + kept_stale
    if len(result) != len(desired) or len(set(result)) != len(result):
        raise DnsSyncError("DNS rotation produced duplicates or wrong record count")
    print(f"Gradual rollout: {len(incoming)} replacements requested, "
          f"applying up to {max_changes}; {len(kept_stale)} kept until later checks")
    print(f"Replacing oldest stale IPs: {', '.join(stale[:max_changes])}")
    return result


def audit_site_https(ip, hostname, path="/", timeout=4.0):
    """Check a given HTTPS site's TLS SNI, Host and response on a forced IP.

    Only audits compatibility from the GitHub runner; TTFB is NOT a CN-carrier
    benchmark. This audit does not influence production DNS selection.
    """
    hostname = hostname.strip().lower().rstrip(".")
    if not 1 <= len(hostname) <= 253 or not re.fullmatch(r"[a-z0-9.-]+", hostname):
        raise DnsSyncError("Invalid CF_DNS_SITE_AUDIT_HOST")
    if not path.startswith("/") or any(ch in path for ch in (" ", "\r", "\n")):
        raise DnsSyncError("CF_DNS_SITE_AUDIT_PATH must be a safe URL path")
    started = time.monotonic()
    try:
        with socket.create_connection((ip, 443), timeout=timeout) as tcp:
            connected = time.monotonic()
            with ssl.create_default_context().wrap_socket(tcp, server_hostname=hostname) as tls:
                secured = time.monotonic()
                tls.settimeout(timeout)
                request = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {hostname}\r\n"
                    "User-Agent: cook-speed-dns/2.1\r\n"
                    "Accept-Encoding: identity\r\n"
                    "Connection: close\r\n\r\n"
                )
                tls.sendall(request.encode("ascii"))
                response = http.client.HTTPResponse(tls)
                response.begin()
                header_received = time.monotonic()
                status = response.status
                response.close()
                return {
                    "ip": ip, "ok": 200 <= status < 400, "status": status,
                    "tcp_ms": round(1000 * (connected - started), 1),
                    "tls_ms": round(1000 * (secured - connected), 1),
                    "response_header_ms": round(1000 * (header_received - started), 1),
                }
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as exc:
        return {"ip": ip, "ok": False, "error": type(exc).__name__}


def compatible_with_sites(ip, hosts, path="/", checker=None):
    """Gate new CDN IPs on every site's real TLS/SNI/HTTP compatibility.

    This checks function, not mainland-China speed. Never write DNS here.
    """
    checker = checker or audit_site_https
    if not hosts:
        raise DnsSyncError("HTTPS site compatibility check requires a hostname")
    for host in hosts:
        outcome = checker(ip, host, path)
        if not outcome.get("ok"):
            print(f"Rejected candidate {ip}: {host} HTTPS compatibility {outcome}")
            return False
    return True


def sync_dns(session, zone_id, dns_name, token, records, desired):
    """Update, create or remove only exact-name DNS-only A records."""
    if not records and (dns_name != "cdn.yigeyao.com" or not 1 <= len(desired) <= 100):
        raise DnsSyncError("Bootstrapping an empty DNS name is permitted only for cdn.yigeyao.com with 1-100 A records")
    if not desired:
        raise DnsSyncError("No validated IPs; refusing to change DNS")
    if len(set(desired)) != len(desired):
        raise DnsSyncError("Duplicate candidate IPs; refusing to change DNS")
    if any(
        rec.get("proxied") is not False
        or rec.get("name", dns_name) != dns_name
        or rec.get("type", "A") != "A"
        for rec in records
    ):
        raise DnsSyncError("Unexpected record name/type or orange-cloud proxy; DNS untouched")

    matched_ids = set()
    matched_ips = set()
    for ip in desired:
        for rec in records:
            if rec["id"] not in matched_ids and rec.get("content") == ip:
                matched_ids.add(rec["id"])
                matched_ips.add(ip)
                break

    unused = [rec for rec in records if rec["id"] not in matched_ids]
    missing_ips = [ip for ip in desired if ip not in matched_ips]
    changed = []

    # PATCH and POST before DELETE so partial failures cannot shrink the DNS pool.
    for rec, ip in zip(unused, missing_ips):
        cf_api(session, "PATCH", f"/zones/{zone_id}/dns_records/{rec['id']}", token,
               json={"content": ip})
        changed.append((rec.get("content"), ip))
        print(f"Updated {dns_name}: {rec.get('content')} -> {ip}")
    for ip in missing_ips[len(unused):]:
        cf_api(session, "POST", f"/zones/{zone_id}/dns_records", token,
               json={"type": "A", "name": dns_name, "content": ip, "ttl": 1,
                     "proxied": False, "comment": "[CF-IP] cook-speed-dns | 中国大陆三网优选 IP 池 | CDN 主入口 | 自动维护"})
        changed.append((None, ip))
        print(f"Created {dns_name}: {ip}")

    removable = unused[len(missing_ips):]
    for rec in removable:
        cf_api(session, "DELETE", f"/zones/{zone_id}/dns_records/{rec['id']}", token)
        changed.append((rec.get("content"), None))
        print(f"Removed extra A record: {dns_name} -> {rec.get('content')}")
    if not changed:
        print(f"{dns_name}: {len(desired)} IPs are already current; no DNS changes")
    return changed


def pushplus(message):
    token = os.environ.get("PUSHPLUS_TOKEN")
    if not token:
        return
    try:
        response = requests.post(
            "https://www.pushplus.plus/send",
            json={"token": token, "title": "Cloudflare 优选 DNS", "content": message,
                  "template": "markdown", "channel": "wechat"},
            timeout=10,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        print(f"Optional PushPlus notification failed: {exc}")


def main():
    token = os.environ.get("CF_API_TOKEN")
    zone_id = os.environ.get("CF_ZONE_ID")
    dns_name = os.environ.get("CF_DNS_NAME", "").strip().lower().rstrip(".")
    if not all((token, zone_id, dns_name)):
        raise DnsSyncError("Required secrets: CF_API_TOKEN, CF_ZONE_ID, CF_DNS_NAME")
    if "." not in dns_name or "*" in dns_name:
        raise DnsSyncError("CF_DNS_NAME must be a fully qualified DNS hostname")

    session = requests.Session()
    records = dns_records(session, zone_id, dns_name, token)
    target = os.environ.get("CF_DNS_RECORD_COUNT", "").strip()
    try:
        count = int(target) if target else len(records)
    except ValueError as exc:
        raise DnsSyncError("CF_DNS_RECORD_COUNT must be an integer") from exc
    if not 1 <= count <= 100:
        raise DnsSyncError("CF_DNS_RECORD_COUNT must be between 1 and 100")
    print(f"Checking {len(records)} existing A records for {dns_name}, target={count}")

    load_status()
    networks, source = fetch_cf_networks(session, 10)
    print(f"Cloudflare CIDR source: {source}")
    pools = {group: load_pool(group) for group in ("ct", "cu", "cmcc", "all")}
    check_enabled = os.environ.get("CF_DNS_TCP_CHECK", "1") not in ("0", "false", "no")
    audit_host = os.environ.get("CF_DNS_SITE_AUDIT_HOST", "").strip()
    audit_path = os.environ.get("CF_DNS_SITE_AUDIT_PATH", "/")
    extra_hosts = [
        host.strip() for host in os.environ.get("CF_DNS_SITE_VERIFY_EXTRA_HOSTS", "").split(",")
        if host.strip()
    ]
    site_hosts = list(dict.fromkeys(([audit_host] if audit_host else []) + extra_hosts))
    site_verify = os.environ.get("CF_DNS_SITE_VERIFY", "0").lower() in ("1", "true", "yes")
    if site_verify and not audit_host:
        raise DnsSyncError("CF_DNS_SITE_VERIFY requires CF_DNS_SITE_AUDIT_HOST")
    if site_verify:
        # Verify TLS/Host and web response for ALL sites using the shared CDN.
        # If too few compatible candidates remain, abort without DNS edits.
        probe = lambda ip: compatible_with_sites(ip, site_hosts, audit_path)
    else:
        probe = tcp_reachable if check_enabled else None

    require_reported_rtt = os.environ.get(
        "CF_DNS_REQUIRE_REPORTED_RTT", "0"
    ).lower() in ("1", "true", "yes")
    max_rtt_text = os.environ.get("CF_DNS_MAX_RTT_MS", "").strip()
    max_reported_rtt = None
    if max_rtt_text:
        try:
            max_reported_rtt = float(max_rtt_text)
        except ValueError as exc:
            raise DnsSyncError("CF_DNS_MAX_RTT_MS must be numeric") from exc
        if not 1 <= max_reported_rtt <= 1000:
            raise DnsSyncError("CF_DNS_MAX_RTT_MS must be between 1 and 1000")
        require_reported_rtt = True
    if require_reported_rtt:
        print("Strict latency mode enabled: unmeasured candidates are forbidden")
    desired = pick_ips(
        pools, count, networks, probe=probe,
        max_reported_rtt=max_reported_rtt,
        require_reported_rtt=require_reported_rtt,
    )
    print(f"Selected IPs (CT/CU/CMCC first): {', '.join(desired)}")
    # Diagnostic TTFB is collected from GitHub; NEVER rank Chinese carrier
    # candidates by a US runner's response time.
    if audit_host:
        try:
            audit_count = int(os.environ.get("CF_DNS_SITE_AUDIT_COUNT", "3"))
        except ValueError as exc:
            raise DnsSyncError("CF_DNS_SITE_AUDIT_COUNT must be an integer") from exc
        if not 1 <= audit_count <= 6:
            raise DnsSyncError("CF_DNS_SITE_AUDIT_COUNT must be between 1 and 6")
        for host in site_hosts:
            for ip in desired[:audit_count]:
                print(f"Website HTTPS audit (GitHub runner; not CN speed): "
                      f"{host} via {audit_site_https(ip, host, audit_path)}")
    try:
        max_changes = int(os.environ.get("CF_DNS_MAX_ROTATIONS", "6"))
    except ValueError as exc:
        raise DnsSyncError("CF_DNS_MAX_ROTATIONS must be an integer") from exc
    desired = limit_rotation(records, desired, max_changes=max_changes)
    updates = sync_dns(session, zone_id, dns_name, token, records, desired)
    pushplus(f"{dns_name}: {len(updates)} DNS changes, {count - len(updates)} unchanged. IPs: {', '.join(desired)}")


if __name__ == "__main__":
    try:
        main()
    except DnsSyncError as exc:
        print(f"DNS sync failed: {exc}", file=sys.stderr)
        sys.exit(1)
