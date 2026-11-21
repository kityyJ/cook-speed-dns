import ipaddress
import unittest
from unittest.mock import patch

from dnscf import DnsSyncError, audit_site_https, candidate_rank, compatible_with_sites, dns_records, limit_rotation, pick_ips, sync_dns

NETWORKS = [ipaddress.ip_network("104.16.0.0/13"), ipaddress.ip_network("162.158.0.0/15")]


class FakeResponse:
    status_code = 200

    def __init__(self, result, success=True):
        self.data = {"success": success, "result": result}

    def json(self):
        return self.data


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)


def row(ip):
    return {"ip": ip, "port": 443}


class DNSTests(unittest.TestCase):
    def test_carrier_selection_and_reachability(self):
        pools = {
            "ct": [row("104.17.1.1"), row("104.17.1.2")],
            "cu": [row("104.17.1.2"), row("104.17.1.3")],
            "cmcc": [row("162.159.1.2")],
            "all": [row("1.1.1.1"), row("104.17.1.4")],
        }
        selected = pick_ips(pools, 3, NETWORKS, probe=lambda ip: ip != "104.17.1.1")
        self.assertEqual(selected, ["104.17.1.2", "104.17.1.3", "162.159.1.2"])

    def test_insufficient_ips_aborts(self):
        pools = {group: [] for group in ("ct", "cu", "cmcc", "all")}
        with self.assertRaises(DnsSyncError):
            pick_ips(pools, 3, NETWORKS)

    def test_exact_dns_pagination(self):
        sess = FakeSession([
            FakeResponse([{"id": "b", "name": "cdn.yigeyao.com", "type": "A", "content": "104.17.1.1"}]),
            FakeResponse([{"id": "a", "name": "cdn.yigeyao.com", "type": "A", "content": "104.17.1.2"}]),
        ])
        sess.responses[0].data["result_info"] = {"total_pages": 2}
        sess.responses[1].data["result_info"] = {"total_pages": 2}
        found = dns_records(sess, "zone", "cdn.yigeyao.com", "token")
        self.assertEqual([record["id"] for record in found], ["a", "b"])
        self.assertEqual(sess.calls[1][2]["params"]["page"], 2)

    def test_unchanged_records_are_not_shuffled(self):
        records = [
            {"id": "a", "content": "104.17.1.2", "proxied": False},
            {"id": "b", "content": "104.17.1.1", "proxied": False},
        ]
        sess = FakeSession([])
        self.assertEqual(sync_dns(sess, "zone", "cdn.yigeyao.com", "token", records,
                                  ["104.17.1.1", "104.17.1.2"]), [])
        self.assertFalse(sess.calls)

    def test_patch_only_changes_address(self):
        records = [{"id": "a", "content": "104.17.1.1", "proxied": False}]
        sess = FakeSession([FakeResponse({})])
        sync_dns(sess, "zone", "cdn.yigeyao.com", "token", records, ["104.17.1.2"])
        self.assertEqual(sess.calls[0][0], "PATCH")
        self.assertEqual(sess.calls[0][2]["json"], {"content": "104.17.1.2"})

    def test_cloudflare_rejects_update(self):
        records = [{"id": "a", "content": "104.17.1.1", "proxied": False}]
        with self.assertRaises(DnsSyncError):
            sync_dns(FakeSession([FakeResponse({}, False)]),
                     "zone", "cdn.yigeyao.com", "token", records, ["104.17.1.2"])

    def test_creates_missing_records(self):
        records = [{"id": "a", "content": "104.17.1.1", "proxied": False}]
        sess = FakeSession([FakeResponse({}), FakeResponse({})])
        changes = sync_dns(sess, "zone", "cdn.yigeyao.com", "token", records,
                           ["104.17.1.2", "104.17.1.3"])
        self.assertEqual(len(changes), 2)
        self.assertEqual([call[0] for call in sess.calls], ["PATCH", "POST"])
        self.assertEqual(sess.calls[1][2]["json"]["proxied"], False)
        self.assertEqual(sess.calls[1][2]["json"]["content"], "104.17.1.3")

    def test_sixty_carrier_balanced_candidates(self):
        ips = [f"104.17.{n // 250}.{n % 250 + 1}" for n in range(180)]
        pools = {
            "ct": [row(ip) for ip in ips[:60]],
            "cu": [row(ip) for ip in ips[60:120]],
            "cmcc": [row(ip) for ip in ips[120:180]],
            "all": [],
        }
        result = pick_ips(pools, 60, NETWORKS, probe=lambda ip: True)
        self.assertEqual(len(set(result)), 60)
        self.assertEqual(result[:3], [ips[0], ips[60], ips[120]])

    def test_reported_low_speed_is_rejected(self):
        item = {"ip": "104.17.1.1", "port": 443,
                "tag": "50ms | 0.1mb/s"}
        self.assertIsNone(candidate_rank(item, 0))

    def test_low_latency_ranks_ahead_of_unknown(self):
        measured = {"ip": "104.17.1.2", "port": 443,
                    "tag": "48.2ms | 30mb/s"}
        unknown = {"ip": "104.17.1.3", "port": 443, "tag": "HKG"}
        self.assertLess(candidate_rank(measured, 5), candidate_rank(unknown, 0))

    def test_fast_download_can_outweigh_small_latency_advantage(self):
        slow = {"ip": "104.17.1.1", "port": 443, "tag": "65ms | 1mb/s"}
        fast = {"ip": "104.17.1.2", "port": 443, "tag": "108ms | 25mb/s"}
        self.assertLess(candidate_rank(fast, 1), candidate_rank(slow, 0))

    def test_reported_speed_without_rtt_beats_geo_only(self):
        measured = {"tag": "20mb/s"}
        unmeasured = {"tag": "HKG"}
        self.assertLess(candidate_rank(measured, 1), candidate_rank(unmeasured, 0))

    def test_dns_rotation_limits_replacements(self):
        old = [f"104.17.1.{i + 1}" for i in range(30)]
        desired = [f"104.17.2.{i + 1}" for i in range(30)]
        records = [{"content": ip} for ip in old]
        result = limit_rotation(records, desired, max_changes=6)
        self.assertEqual(len(result), 30)
        self.assertEqual(len(set(result)), 30)
        self.assertEqual(len(set(result) - set(old)), 6)
        self.assertEqual(len(set(result) & set(old)), 24)
        self.assertEqual(len(set(result) & set(desired)), 6)

    def test_dns_rotation_skips_incomplete_pool(self):
        records = [{"content": "104.17.1.1"}]
        desired = ["104.17.1.1", "104.17.1.2"]
        self.assertEqual(limit_rotation(records, desired, max_changes=0), desired)

    def test_dns_rotation_rejects_invalid_limit(self):
        with self.assertRaises(DnsSyncError):
            limit_rotation([], ["104.17.1.1"], max_changes=101)

    def test_dns_rotation_replaces_oldest_stale_by_modified_on(self):
        # ID order matches dns_records(). The oldest stale row is the head, which
        # the previous ID-order cap would keep forever.
        records = [
            {"id": "id-00", "content": "104.17.1.4",
             "modified_on": "2026-01-01T00:00:00Z", "created_on": "2026-01-01T00:00:00Z"},
            {"id": "id-01", "content": "104.17.1.2",
             "modified_on": "2026-10-14T00:00:00Z", "created_on": "2026-10-14T00:00:00Z"},
            {"id": "id-02", "content": "104.17.1.3",
             "modified_on": "2026-11-01T00:00:00Z", "created_on": "2026-10-14T00:00:00Z"},
            {"id": "id-03", "content": "104.17.1.1",
             "modified_on": "2026-11-20T00:00:00.900000Z", "created_on": "2026-11-20T00:00:00Z"},
        ]
        desired = ["104.17.9.1", "104.17.9.2", "104.17.9.3", "104.17.1.4"]
        replaced_one = limit_rotation(records, desired, max_changes=1)
        self.assertIn("104.17.1.4", replaced_one)
        self.assertNotIn("104.17.1.2", replaced_one)
        self.assertIn("104.17.1.3", replaced_one)
        self.assertIn("104.17.1.1", replaced_one)
        self.assertEqual(len(set(replaced_one) & set(desired[:3])), 1)

        replaced_two = limit_rotation(records, desired, max_changes=2)
        self.assertIn("104.17.1.4", replaced_two)
        self.assertNotIn("104.17.1.2", replaced_two)
        self.assertNotIn("104.17.1.3", replaced_two)
        self.assertIn("104.17.1.1", replaced_two)
        self.assertEqual(len(set(replaced_two) & set(desired[:3])), 2)

    def test_dns_rotation_drains_oldest_batch_without_churning_fresh_ips(self):
        count = 18
        records = [
            {"id": f"id-{i:02d}", "content": f"104.17.1.{i + 1}",
             "modified_on": f"2026-10-14T00:{i:02d}:00Z", "created_on": "2026-10-14T00:00:00Z"}
            for i in range(count)
        ]
        written = []
        for run in range(3):
            desired = [f"104.17.{run + 2}.{i + 1}" for i in range(count)]
            result = limit_rotation(records, desired, max_changes=6)
            pool = {rec["content"] for rec in records}
            evicted = pool - set(result)
            expected = {f"104.17.1.{i}" for i in range(run * 6 + 1, run * 6 + 7)}
            self.assertEqual(evicted, expected)
            for batch in written:
                self.assertTrue(batch <= set(result))
            added = [ip for ip in result if ip not in pool]
            self.assertEqual(added, desired[:6])
            pending = list(added)
            for rec in records:
                if rec["content"] not in result:
                    rec["content"] = pending.pop(0)
                    rec["modified_on"] = f"2026-11-2{run}T01:00:00Z"
            self.assertEqual(pending, [])
            records.sort(key=lambda rec: rec["id"])
            written.append(set(added))
        self.assertFalse(any(ip.startswith("104.17.1.") for ip in (rec["content"] for rec in records)))
        for batch in written:
            self.assertTrue(batch <= {rec["content"] for rec in records})

    def test_dns_listing_passes_timestamps_into_rotation(self):
        payload = [
            {"id": "b", "name": "cdn.yigeyao.com", "type": "A", "content": "104.17.1.1",
             "proxied": False, "modified_on": "2026-11-20T00:00:00Z", "created_on": "2026-10-01T00:00:00Z"},
            {"id": "a", "name": "cdn.yigeyao.com", "type": "A", "content": "104.17.1.2",
             "proxied": False, "modified_on": "2026-10-14T00:00:00Z", "created_on": "2026-10-14T00:00:00Z"},
        ]
        sess = FakeSession([FakeResponse(payload)])
        records = dns_records(sess, "zone", "cdn.yigeyao.com", "token")
        self.assertEqual(
            [(rec["id"], rec["content"], rec["modified_on"], rec["created_on"]) for rec in records],
            [
                ("a", "104.17.1.2", "2026-10-14T00:00:00Z", "2026-10-14T00:00:00Z"),
                ("b", "104.17.1.1", "2026-11-20T00:00:00Z", "2026-10-01T00:00:00Z"),
            ],
        )
        result = limit_rotation(records, ["104.17.9.1", "104.17.9.2"], max_changes=1)
        self.assertNotIn("104.17.1.2", result)
        self.assertIn("104.17.1.1", result)

    def test_dns_rotation_age_falls_back_to_created_on_then_id(self):
        # Head rows are the ones an ID-order cap would keep. Fallback keys must
        # still evict them when they are the older stale addresses.
        by_created = [
            {"id": "aaa", "content": "104.17.1.2", "created_on": "2026-10-14T00:00:00Z"},
            {"id": "zzz", "content": "104.17.1.1", "created_on": "2026-11-20T00:00:00Z"},
        ]
        created_result = limit_rotation(by_created, ["104.17.9.1", "104.17.9.2"], max_changes=1)
        self.assertNotIn("104.17.1.2", created_result)
        self.assertIn("104.17.1.1", created_result)

        by_id = [
            {"id": "aaa", "content": "104.17.1.2"},
            {"id": "zzz", "content": "104.17.1.1"},
        ]
        id_result = limit_rotation(by_id, ["104.17.9.1", "104.17.9.2"], max_changes=1)
        self.assertNotIn("104.17.1.2", id_result)
        self.assertIn("104.17.1.1", id_result)

        modified_over_created = [
            {"id": "aaa", "content": "104.17.1.2", "created_on": "2026-10-14T00:00:00Z"},
            {"id": "zzz", "content": "104.17.1.1",
             "modified_on": "2026-11-20T00:00:00Z", "created_on": "2020-01-01T00:00:00Z"},
        ]
        modified_result = limit_rotation(
            modified_over_created, ["104.17.9.1", "104.17.9.2"], max_changes=1)
        self.assertNotIn("104.17.1.2", modified_result)
        self.assertIn("104.17.1.1", modified_result)

    def test_strict_rtt_pool_excludes_unmeasured_and_over_limit(self):
        pools = {
            "ct": [
                {"ip": "104.17.1.1", "port": 443, "tag": "49ms | 0.1mb/s"},
                {"ip": "104.17.1.2", "port": 443, "tag": "HKG"},
            ],
            "cu": [
                {"ip": "104.17.1.3", "port": 443, "tag": "80ms | 0.1mb/s"},
                {"ip": "104.17.1.4", "port": 443, "tag": "221ms | 30mb/s"},
            ],
            "cmcc": [
                {"ip": "162.159.1.2", "port": 443, "tag": "99ms | 0.1mb/s"},
            ],
            "all": [],
        }
        result = pick_ips(
            pools, 3, NETWORKS, probe=lambda ip: True,
            max_reported_rtt=220, require_reported_rtt=True,
        )
        self.assertEqual(result, ["104.17.1.1", "104.17.1.3", "162.159.1.2"])

    def test_strict_rtt_pool_aborts_instead_of_using_unmeasured_fallback(self):
        pools = {
            "ct": [{"ip": "104.17.1.1", "port": 443, "tag": "49ms"}],
            "cu": [{"ip": "104.17.1.2", "port": 443, "tag": "HKG"}],
            "cmcc": [],
            "all": [],
        }
        with self.assertRaises(DnsSyncError):
            pick_ips(
                pools, 2, NETWORKS, probe=lambda ip: True,
                max_reported_rtt=220, require_reported_rtt=True,
            )

    def test_https_audit_rejects_unsafe_host_or_path(self):
        with self.assertRaises(DnsSyncError):
            audit_site_https("104.17.1.1", "example.com\r\nX: injected")
        with self.assertRaises(DnsSyncError):
            audit_site_https("104.17.1.1", "example.com", "/\r\nHost: injected")

    def test_https_audit_network_failure_is_nonfatal(self):
        with patch("dnscf.socket.create_connection", side_effect=OSError("offline")):
            result = audit_site_https("104.17.1.1", "cook.jia.nz")
        self.assertEqual(result, {"ip": "104.17.1.1", "ok": False, "error": "OSError"})

    def test_https_audit_preserves_tls_sni_and_http_host(self):
        with patch("dnscf.socket.create_connection") as connect, \
             patch("dnscf.ssl.create_default_context") as context, \
             patch("dnscf.http.client.HTTPResponse") as reply:
            raw = connect.return_value.__enter__.return_value
            secure = context.return_value.wrap_socket.return_value.__enter__.return_value
            reply.return_value.status = 200
            result = audit_site_https("104.17.1.1", "cook.jia.nz", "/")
            context.return_value.wrap_socket.assert_called_once_with(
                raw, server_hostname="cook.jia.nz")
            sent = secure.sendall.call_args.args[0]
            self.assertIn(b"Host: cook.jia.nz\r\n", sent)
            self.assertIn(b"GET / HTTP/1.1\r\n", sent)
            self.assertTrue(result["ok"])
            self.assertEqual(result["status"], 200)

    def test_multi_site_verifier_accepts_both_sites(self):
        checked = []
        def checker(ip, host, path):
            checked.append((ip, host, path))
            return {"ok": True, "status": 200}
        self.assertTrue(compatible_with_sites("104.17.1.1",
                                             ["cook.jia.nz", "www.jia.nz"],
                                             "/", checker))
        self.assertEqual(checked,
                         [("104.17.1.1", "cook.jia.nz", "/"),
                          ("104.17.1.1", "www.jia.nz", "/")])

    def test_multi_site_verifier_rejects_broken_www(self):
        checked = []
        def checker(ip, host, path):
            checked.append(host)
            return {"ok": host != "www.jia.nz", "status": 403 if host == "www.jia.nz" else 200}
        self.assertFalse(compatible_with_sites("104.17.1.1",
                                               ["cook.jia.nz", "www.jia.nz"],
                                               "/", checker))
        self.assertEqual(checked, ["cook.jia.nz", "www.jia.nz"])

    def test_multi_site_verifier_rejects_missing_hosts(self):
        with self.assertRaises(DnsSyncError):
            compatible_with_sites("104.17.1.1", [], "/")

    def test_shrink_to_thirty_dns_records(self):
        records = [
            {"id": str(i), "name": "cdn.yigeyao.com", "type": "A",
             "content": f"104.17.1.{i + 1}", "proxied": False}
            for i in range(32)
        ]
        desired = [r["content"] for r in records[:30]]
        sess = FakeSession([FakeResponse({}), FakeResponse({})])
        changes = sync_dns(sess, "zone", "cdn.yigeyao.com", "token", records, desired)
        self.assertEqual(len(changes), 2)
        self.assertEqual([call[0] for call in sess.calls], ["DELETE", "DELETE"])

    def test_bootstrap_empty_cdn_with_thirty_records(self):
        desired = [f"104.17.1.{i + 1}" for i in range(30)]
        session = FakeSession([FakeResponse({}) for _ in desired])
        changes = sync_dns(session, "zone", "cdn.yigeyao.com", "token", [], desired)
        self.assertEqual(len(changes), 30)
        self.assertEqual([method for method, _, _ in session.calls], ["POST"] * 30)
        self.assertTrue(all(call[2]["json"]["proxied"] is False for call in session.calls))
        self.assertTrue(all(call[2]["json"]["ttl"] == 1 for call in session.calls))

    def test_bootstrap_empty_unexpected_domain_is_blocked(self):
        session = FakeSession([])
        desired = [f"104.17.1.{i + 1}" for i in range(30)]
        with self.assertRaises(DnsSyncError):
            sync_dns(session, "zone", "cook.jia.nz", "token", [], desired)
        self.assertEqual(session.calls, [])

    def test_proxy_mode_is_protected(self):
        records = [{"id": "a", "content": "104.17.1.1", "proxied": True}]
        with self.assertRaises(DnsSyncError):
            sync_dns(FakeSession([]), "zone", "cdn.yigeyao.com", "token", records, ["104.17.1.2"])


if __name__ == "__main__":
    unittest.main()
