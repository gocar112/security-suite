import http.client
import json
import tempfile
import threading
import unittest
import errno
from pathlib import Path
from unittest.mock import patch

from core.web_server import SecuritySuiteApp, create_server, create_available_server


class WebServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parent.parent
        cls.app = SecuritySuiteApp(root=root, version="test")
        cls.server = create_server(port=0, app=cls.app)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        request_headers = dict(headers or {})
        encoded = None
        if body is not None:
            encoded = json.dumps(body)
            request_headers.setdefault("Content-Type", "application/json")
        connection.request(method, path, body=encoded, headers=request_headers)
        response = connection.getresponse()
        payload = response.read()
        result = (response.status, dict(response.getheaders()), payload)
        connection.close()
        return result

    def test_bootstrap_has_security_headers(self):
        status, headers, body = self.request("GET", "/api/bootstrap")
        self.assertEqual(status, 200)
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        payload = json.loads(body)
        self.assertEqual(payload["version"], "test")
        self.assertTrue(payload["csrfToken"])

    def test_health_identifies_project_without_csrf(self):
        status, _, body = self.request("GET", "/api/health")
        self.assertEqual(status, 200)
        health = json.loads(body)
        self.assertEqual(health["name"], "Security Suite")
        self.assertEqual(health["instanceId"], self.app.instance_id)
        self.assertNotIn("csrfToken", health)

    def test_port_conflict_falls_back_without_closing_existing_server(self):
        with patch("core.web_server.create_server", side_effect=[OSError(errno.EADDRINUSE, "busy"), self.server]) as create:
            self.assertIs(create_available_server("127.0.0.1", 8766, self.app), self.server)
            self.assertEqual([call.kwargs["port"] for call in create.call_args_list], [8766, 8767])

    def test_post_requires_csrf_token(self):
        status, _, body = self.request("POST", "/api/intel/sync", {})
        self.assertEqual(status, 403)
        self.assertIn("CSRF", json.loads(body)["error"])

    def test_cross_origin_post_is_rejected(self):
        status, _, body = self.request(
            "POST",
            "/api/intel/sync",
            {},
            {"X-CSRF-Token": self.app.csrf_token, "Origin": "https://attacker.example"},
        )
        self.assertEqual(status, 403)
        self.assertIn("Cross-origin", json.loads(body)["error"])

    def test_static_path_is_allowlisted(self):
        status, _, _ = self.request("GET", "/assets/../core/web_server.py")
        self.assertEqual(status, 404)

    def test_patch_bundle_uses_completed_scan_findings(self):
        job_id = "completed-test-job"
        with self.app.jobs.lock:
            self.app.jobs.jobs[job_id] = {
                "id": job_id,
                "kind": "system",
                "status": "completed",
                "created_at": "2026-01-01T00:00:00+00:00",
                "started_at": "2026-01-01T00:00:00+00:00",
                "completed_at": "2026-01-01T00:00:01+00:00",
                "result": {"checks": [{"id": "llmnr", "status": "warn", "patch_id": "disable_llmnr"}]},
                "error": None,
            }
        status, headers, body = self.request(
            "POST",
            "/api/patches/build",
            {"jobId": job_id, "findingIds": ["llmnr"]},
            {"X-CSRF-Token": self.app.csrf_token, "Origin": f"http://127.0.0.1:{self.port}"},
        )
        self.assertEqual(status, 200)
        self.assertIn("security-suite-patches.ps1", headers["Content-Disposition"])
        self.assertIn(b"EnableMulticast", body)

    def test_patch_rejects_unchecked_passed_and_non_system_findings(self):
        with self.app.jobs.lock:
            self.app.jobs.jobs["ineligible"] = {
                "id": "ineligible", "kind": "system", "status": "completed",
                "created_at": "2026-01-01", "completed_at": "2026-01-01",
                "result": {"checks": [{"id": "llmnr", "status": "error", "patch_id": "disable_llmnr"}]},
            }
        for status in ["error", "pass"]:
            self.app.jobs.jobs["ineligible"]["result"]["checks"][0]["status"] = status
            response, _, body = self.request("POST", "/api/patches/build", {"jobId": "ineligible", "findingIds": ["llmnr"]}, {"X-CSRF-Token": self.app.csrf_token})
            self.assertEqual(response, 400)
            self.assertIn("not patchable", json.loads(body)["error"])
        self.app.jobs.jobs["ineligible"]["kind"] = "website"
        with self.assertRaisesRegex(ValueError, "system scan"):
            self.app.build_patch_bundle("ineligible", ["llmnr"])

    def test_latest_report_restores_across_page_loads(self):
        job = {"id": "restore-test", "kind": "system", "status": "completed",
               "created_at": "2026-09-11", "completed_at": "2026-09-11", "result": {"checks": [], "score": 90}}
        with self.app.jobs.lock:
            self.app.jobs.jobs[job["id"]] = job
        latest = self.app.jobs.latest_report()
        self.assertEqual(latest["id"], job["id"])
        _, _, body = self.request("GET", "/api/bootstrap")
        self.assertEqual(json.loads(body)["latestReport"]["result"]["score"], 90)

    def use_temp_clients(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        original = self.app.clients_root
        self.app.clients_root = Path(directory.name)
        self.addCleanup(setattr, self.app, "clients_root", original)
        for name in ("internal-training", "_template", "Bad Name"):
            (self.app.clients_root / name).mkdir()
        return self.app.clients_root

    def post(self, path, body):
        return self.request("POST", path, body, {"X-CSRF-Token": self.app.csrf_token})

    def test_bootstrap_lists_only_client_slugs(self):
        self.use_temp_clients()
        _, _, body = self.request("GET", "/api/bootstrap")
        self.assertEqual(json.loads(body)["clients"], ["internal-training"])

    def test_brief_endpoint_returns_full_markdown(self):
        status, _, body = self.post("/api/intel/brief", {"cve": "cve-2021-44228", "live": False})
        self.assertEqual(status, 200)
        brief = json.loads(body)
        self.assertEqual(brief["cve"], "CVE-2021-44228")
        self.assertEqual(brief["missingSections"], [])
        self.assertTrue(brief["markdown"].startswith("# CVE-2021-44228 - "))

    def test_brief_endpoint_rejects_bad_cve(self):
        status, _, body = self.post("/api/intel/brief", {"cve": "../etc", "live": False})
        self.assertEqual(status, 400)
        self.assertIn("CVE IDs", json.loads(body)["error"])

    def test_brief_save_writes_once_and_refuses_overwrite(self):
        clients = self.use_temp_clients()
        request = {"cve": "CVE-2021-44228", "client": "internal-training", "live": False}
        status, _, body = self.post("/api/intel/brief/save", request)
        self.assertEqual(status, 200)
        saved = clients / "internal-training" / "CVE-2021-44228.md"
        self.assertEqual(Path(json.loads(body)["path"]), saved)
        self.assertIn("**Remediation**", saved.read_text(encoding="utf-8"))
        status, _, body = self.post("/api/intel/brief/save", request)
        self.assertEqual(status, 409)
        self.assertIn("already exists", json.loads(body)["error"])
        status, _, _ = self.post("/api/intel/brief/save", {**request, "overwrite": True})
        self.assertEqual(status, 200)

    def test_brief_save_only_targets_listed_clients(self):
        clients = self.use_temp_clients()
        for client in ("_template", "Bad Name", "../outside", "missing-client"):
            status, _, body = self.post("/api/intel/brief/save", {"cve": "CVE-2021-44228", "client": client, "live": False})
            self.assertEqual(status, 400, client)
            self.assertIn("existing client folder", json.loads(body)["error"])
        self.assertFalse(any(clients.rglob("*.md")))

    def test_brief_save_requires_csrf(self):
        status, _, _ = self.request("POST", "/api/intel/brief/save", {"cve": "CVE-2021-44228", "client": "internal-training"})
        self.assertEqual(status, 403)

    def test_non_loopback_bind_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "loopback"):
            create_server("0.0.0.0", 0, self.app)


if __name__ == "__main__":
    unittest.main()
