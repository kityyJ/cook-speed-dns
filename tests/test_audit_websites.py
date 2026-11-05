import contextlib
import io
import os
import unittest
from unittest.mock import patch

import audit_websites


def records(count, proxied=False, duplicate=False):
    items = []
    for index in range(count):
        items.append({
            "name": audit_websites.CDN_NAME,
            "type": "A",
            "content": f"104.17.{index // 200}.{(index % 200) + 1}",
            "proxied": proxied,
        })
    if duplicate and items:
        items[-1] = {**items[-1], "content": items[0]["content"]}
    return items


class PoolGateTests(unittest.TestCase):
    def test_accepts_published_sizes_including_the_old_and_current_pools(self):
        for count in (1, 30, 66, 100):
            ips = audit_websites.consistent_gray_cloud_ips(records(count))
            self.assertEqual(len(ips), count)
            self.assertEqual(len(set(ips)), count)

    def test_rejects_empty_oversized_duplicate_and_proxied_pools(self):
        self.assertIsNone(audit_websites.consistent_gray_cloud_ips([]))
        self.assertIsNone(audit_websites.consistent_gray_cloud_ips(records(101)))
        self.assertIsNone(audit_websites.consistent_gray_cloud_ips(records(66, duplicate=True)))
        self.assertIsNone(audit_websites.consistent_gray_cloud_ips(records(66, proxied=True)))
        mixed = records(66)
        mixed[0] = {**mixed[0], "proxied": True}
        self.assertIsNone(audit_websites.consistent_gray_cloud_ips(mixed))
        blank = records(2)
        blank[1] = {**blank[1], "content": ""}
        self.assertIsNone(audit_websites.consistent_gray_cloud_ips(blank))

    def _run(self, found, audit_result=None):
        buffer = io.StringIO()
        audit_result = audit_result or {
            "ok": True, "status": 200, "response_header_ms": 20.0,
        }

        def audit(ip, host, path, timeout):
            return {**audit_result, "ip": ip}

        env = {"CF_API_TOKEN": "token", "CF_ZONE_ID": "zone"}
        with patch.dict(os.environ, env), \
                patch("audit_websites.dns_records", return_value=found), \
                patch("audit_websites.audit_site_https", side_effect=audit) as mocked, \
                contextlib.redirect_stdout(buffer):
            code = audit_websites.main()
        return code, buffer.getvalue(), mocked

    def test_sixty_six_gray_cloud_records_reach_https_checks(self):
        code, output, mocked = self._run(records(66))
        self.assertEqual(code, 0)
        self.assertEqual(mocked.call_count, 66 * len(audit_websites.HOSTS))
        hosts = {call.args[1] for call in mocked.call_args_list}
        self.assertEqual(hosts, set(audit_websites.HOSTS))
        self.assertIn("Auditing 66 CDN IPs x 2 HTTPS sites.", output)

    def test_https_failures_are_reported_after_the_pool_gate(self):
        code, output, mocked = self._run(
            records(66),
            {"ok": False, "status": 403, "response_header_ms": 20.0},
        )
        self.assertEqual(code, 1)
        self.assertEqual(mocked.call_count, 66 * len(audit_websites.HOSTS))
        self.assertIn("Some currently published IPs failed HTTPS checks", output)

    def test_inconsistent_pool_stops_before_https(self):
        code, output, mocked = self._run([])
        self.assertEqual(code, 2)
        mocked.assert_not_called()
        self.assertIn(
            "Unexpected cdn.yigeyao.com A pool: 0 entries, 0 unique gray-cloud IPs",
            output,
        )

    def test_missing_credentials_do_not_query_dns(self):
        with patch.dict(os.environ, {}, clear=True), \
                patch("audit_websites.dns_records") as dns:
            code = audit_websites.main()
        self.assertEqual(code, 2)
        dns.assert_not_called()


if __name__ == "__main__":
    unittest.main()
