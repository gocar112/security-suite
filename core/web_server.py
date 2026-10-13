"""Local-only HTTP dashboard for Security Suite."""

from __future__ import annotations

import copy
import errno
import json
import logging
import os
import re
import secrets
import threading
import traceback
import urllib.parse
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Callable, Dict

from .malware_scanner import MalwareScanner
from .launcher import project_id
from .patch_manager import build_patch_script, list_patches
from .system_scanner import SystemScanner
from .threat_intel import CISA_KEV_FEED, NVD_CVE_API, ThreatIntelligence
from .vuln_scanner import VulnerabilityScanner
from .website_scanner import WebsiteScanner

logger = logging.getLogger(__name__)
# Lowercase slugs only; this also excludes clients\_template.
CLIENT_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


class JobManager:
    """Keep a small in-memory queue for scans that may take several minutes."""

    def __init__(self, max_workers: int = 2, max_jobs: int = 50) -> None:
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="security-suite")
        self.max_jobs = max_jobs
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()

    def submit(self, kind: str, task: Callable[[], Dict[str, Any]]) -> Dict[str, Any]:
        job_id = secrets.token_urlsafe(12)
        now = datetime.now(timezone.utc).isoformat()
        record = {
            "id": job_id,
            "kind": kind,
            "status": "queued",
            "created_at": now,
            "started_at": None,
            "completed_at": None,
            "result": None,
            "error": None,
        }
        with self.lock:
            self._trim_locked()
            self.jobs[job_id] = record
        self.executor.submit(self._execute, job_id, task)
        return self.get(job_id)

    def get(self, job_id: str) -> Dict[str, Any] | None:
        with self.lock:
            record = self.jobs.get(job_id)
            return copy.deepcopy(record) if record else None

    def latest_report(self) -> Dict[str, Any] | None:
        with self.lock:
            rows = [job for job in self.jobs.values() if job["status"] == "completed"
                    and job["kind"] in {"system", "website", "network"}]
            return copy.deepcopy(max(rows, key=lambda row: row["completed_at"])) if rows else None

    def _execute(self, job_id: str, task: Callable[[], Dict[str, Any]]) -> None:
        with self.lock:
            record = self.jobs[job_id]
            record["status"] = "running"
            record["started_at"] = datetime.now(timezone.utc).isoformat()
        try:
            result = task()
        except Exception as exc:  # The API returns a bounded message; details stay in logs.
            logger.error("Job %s failed: %s\n%s", job_id, exc, traceback.format_exc())
            with self.lock:
                record = self.jobs[job_id]
                record["status"] = "failed"
                record["error"] = str(exc)[:2000]
                record["completed_at"] = datetime.now(timezone.utc).isoformat()
            return
        with self.lock:
            record = self.jobs[job_id]
            record["status"] = "completed"
            record["result"] = result
            record["completed_at"] = datetime.now(timezone.utc).isoformat()

    def _trim_locked(self) -> None:
        if len(self.jobs) < self.max_jobs:
            return
        completed = [row for row in self.jobs.values() if row["status"] in {"completed", "failed"}]
        completed.sort(key=lambda row: row["created_at"])
        for row in completed[: max(1, len(self.jobs) - self.max_jobs + 1)]:
            self.jobs.pop(row["id"], None)


class SecuritySuiteApp:
    """Coordinate scanner services for the local HTTP layer."""

    def __init__(self, root: str | Path | None = None, version: str = "2.0.0",
                 clients_root: str | Path | None = None) -> None:
        self.root = Path(root) if root else Path(__file__).resolve().parent.parent
        self.web_root = self.root / "web"
        # Client deliverable folders live beside the suite: AIOS\clients\<slug>.
        self.clients_root = Path(clients_root) if clients_root else self.root.parent / "clients"
        self.version = version
        self.instance_id = secrets.token_urlsafe(16)
        self.csrf_token = secrets.token_urlsafe(32)
        self.jobs = JobManager()
        self.malware = MalwareScanner()
        self.intel = ThreatIntelligence()

    def bootstrap(self) -> Dict[str, Any]:
        return {
            "name": "Security Suite",
            "version": self.version,
            "latestReport": self.jobs.latest_report(),
            "csrfToken": self.csrf_token,
            "malware": self.malware.status(),
            "kev": self.intel.kev_status(),
            "clients": self.list_clients(),
            "patches": list_patches(),
            "sources": {
                "nvd": NVD_CVE_API,
                "cisa_kev": CISA_KEV_FEED,
            },
            "scope": "This dashboard is bound to loopback and performs defensive checks only.",
        }

    def start_system_scan(self, profile: str) -> Dict[str, Any]:
        return self.jobs.submit("system", lambda: SystemScanner().scan(profile=profile))

    def start_website_scan(self, url: str) -> Dict[str, Any]:
        return self.jobs.submit("website", lambda: WebsiteScanner().scan(url=url))

    def start_network_scan(self, target: str, ports: str | None, quick: bool) -> Dict[str, Any]:
        def task() -> Dict[str, Any]:
            scanner = VulnerabilityScanner(timeout=0.5, max_hosts=256, workers=64, allow_public=False)
            return scanner.scan(target=target, quick=quick, port_range=ports)

        return self.jobs.submit("network", task)

    def start_defender_scan(self, scan_type: str) -> Dict[str, Any]:
        return self.jobs.submit("malware", lambda: self.malware.start_defender_scan(scan_type))

    BRIEF_SECTIONS = ("**What it is**", "**Why it matters**", "**Defensive checks**", "**Remediation**")

    def list_clients(self) -> list[str]:
        try:
            return sorted(
                path.name for path in self.clients_root.iterdir()
                if path.is_dir() and CLIENT_SLUG.fullmatch(path.name)
            )
        except OSError:
            return []

    def build_cve_brief(self, cve: str, live: bool) -> Dict[str, Any]:
        record = self.intel.get_cve_info(cve, live=live)
        markdown = self.intel.format_cve_record(record)
        missing = [section.strip("*") for section in self.BRIEF_SECTIONS if section not in markdown]
        return {
            "cve": record["cve"],
            "found": bool(record.get("found")),
            "markdown": markdown,
            "missingSections": missing if record.get("found") else [],
            "liveError": record.get("live_error"),
        }

    def save_cve_brief(self, cve: str, client: str, live: bool, overwrite: bool) -> Dict[str, Any]:
        if client not in self.list_clients():
            raise ValueError("Choose an existing client folder.")
        brief = self.build_cve_brief(cve, live)
        if not brief["found"]:
            raise ValueError(f"No record was found for {brief['cve']}; nothing was saved.")
        path = self.clients_root / client / f"{brief['cve']}.md"
        if path.exists() and not overwrite:
            raise RuntimeError(f"{client}/{path.name} already exists.")
        path.write_text(brief["markdown"], encoding="utf-8")
        return {**brief, "client": client, "path": str(path)}

    def start_kev_sync(self) -> Dict[str, Any]:
        return self.jobs.submit("intel", self.intel.sync_kev)

    def build_patch_bundle(self, job_id: str, finding_ids: list[str]) -> str:
        job = self.jobs.get(job_id)
        if not job:
            raise KeyError("Scan job not found.")
        if job["status"] != "completed" or not isinstance(job.get("result"), dict):
            raise ValueError("Scan job is not complete.")
        if job["kind"] != "system":
            raise ValueError("PC patches require a completed system scan.")
        rows = job["result"].get("checks") or job["result"].get("findings") or []
        patch_by_finding = {
            str(row.get("id")): row.get("patch_id")
            for row in rows
            if isinstance(row, dict) and row.get("patch_id") and row.get("status") in {"warn", "fail"}
        }
        unknown = [item for item in finding_ids if item not in patch_by_finding]
        if unknown:
            raise ValueError("One or more findings are not patchable in this scan.")
        return build_patch_script(patch_by_finding[item] for item in finding_ids)


class SecuritySuiteHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], app: SecuritySuiteApp) -> None:
        self.app = app
        super().__init__(server_address, SecuritySuiteHandler)


class SecuritySuiteHandler(BaseHTTPRequestHandler):
    """Serve an exact static allowlist and a JSON API with CSRF protection."""

    server_version = "SecuritySuite"
    sys_version = ""
    MAX_JSON_BODY = 16_384
    STATIC_FILES = {
        "/": ("index.html", "text/html; charset=utf-8"),
        "/index.html": ("index.html", "text/html; charset=utf-8"),
        "/assets/styles.css": ("styles.css", "text/css; charset=utf-8"),
        "/assets/app.js": ("app.js", "text/javascript; charset=utf-8"),
    }

    @property
    def app(self) -> SecuritySuiteApp:
        return self.server.app  # type: ignore[attr-defined]

    def do_GET(self) -> None:
        if not self._valid_host():
            self._json_error(421, "Invalid Host header.")
            return
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/api/health":
            self._send_json(200, {"name": "Security Suite", "version": self.app.version,
                                 "projectId": project_id(self.app.root), "instanceId": self.app.instance_id,
                                 "pid": os.getpid()})
            return
        if parsed.path in self.STATIC_FILES:
            filename, content_type = self.STATIC_FILES[parsed.path]
            path = self.app.web_root / filename
            try:
                data = path.read_bytes()
            except OSError:
                self._json_error(500, "Dashboard asset is missing.")
                return
            self._send_bytes(200, data, content_type)
            return
        if parsed.path == "/api/bootstrap":
            self._send_json(200, self.app.bootstrap())
            return
        if parsed.path == "/api/intel":
            query = urllib.parse.parse_qs(parsed.query).get("q", [""])[0]
            self._send_json(200, {"query": query, "results": self.app.intel.search(query, limit=50), "kev": self.app.intel.kev_status()})
            return
        if parsed.path.startswith("/api/jobs/"):
            job_id = parsed.path.removeprefix("/api/jobs/")
            job = self.app.jobs.get(job_id)
            if not job:
                self._json_error(404, "Job not found.")
            else:
                self._send_json(200, job)
            return
        if parsed.path.startswith("/api/reports/"):
            job_id = parsed.path.removeprefix("/api/reports/")
            job = self.app.jobs.get(job_id)
            if not job or job["status"] != "completed":
                self._json_error(404, "Completed report not found.")
                return
            data = json.dumps(job["result"], indent=2).encode("utf-8")
            self._send_bytes(200, data, "application/json; charset=utf-8", f"security-suite-{job_id}.json")
            return
        self._json_error(404, "Route not found.")

    def do_POST(self) -> None:
        if not self._valid_host():
            self._drain_request_body()
            self._json_error(421, "Invalid Host header.")
            return
        if not self._valid_origin():
            self._drain_request_body()
            self._json_error(403, "Cross-origin request rejected.")
            return
        if not secrets.compare_digest(self.headers.get("X-CSRF-Token", ""), self.app.csrf_token):
            self._drain_request_body()
            self._json_error(403, "CSRF token missing or invalid.")
            return
        try:
            body = self._read_json()
            path = urllib.parse.urlsplit(self.path).path
            if path == "/api/scans/system":
                profile = str(body.get("profile", "quick"))
                self._send_json(202, self.app.start_system_scan(profile))
            elif path == "/api/scans/website":
                self._send_json(202, self.app.start_website_scan(str(body.get("url", ""))))
            elif path == "/api/scans/network":
                target = str(body.get("target", ""))
                ports = body.get("ports")
                self._send_json(202, self.app.start_network_scan(target, str(ports) if ports else None, bool(body.get("quick", True))))
            elif path == "/api/scans/defender":
                self._send_json(202, self.app.start_defender_scan(str(body.get("scanType", "quick"))))
            elif path == "/api/malwarebytes/open":
                self._send_json(200, self.app.malware.launch_malwarebytes(scan=bool(body.get("scan", False))))
            elif path == "/api/intel/sync":
                self._send_json(202, self.app.start_kev_sync())
            elif path == "/api/intel/lookup":
                cve = str(body.get("cve", ""))
                live = bool(body.get("live", True))
                self._send_json(200, self.app.intel.get_cve_info(cve, live=live))
            elif path == "/api/intel/brief":
                self._send_json(200, self.app.build_cve_brief(str(body.get("cve", "")), bool(body.get("live", True))))
            elif path == "/api/intel/brief/save":
                self._send_json(200, self.app.save_cve_brief(
                    str(body.get("cve", "")),
                    str(body.get("client", "")),
                    bool(body.get("live", True)),
                    body.get("overwrite") is True,
                ))
            elif path == "/api/patches/build":
                job_id = str(body.get("jobId", ""))
                finding_ids = body.get("findingIds")
                if not isinstance(finding_ids, list) or not all(isinstance(item, str) for item in finding_ids):
                    raise ValueError("findingIds must be a list of finding IDs.")
                script = self.app.build_patch_bundle(job_id, finding_ids)
                self._send_bytes(200, script.encode("utf-8"), "text/plain; charset=utf-8", "security-suite-patches.ps1")
            else:
                self._json_error(404, "Route not found.")
        except (ValueError, KeyError, FileNotFoundError) as exc:
            self._json_error(400, str(exc))
        except RuntimeError as exc:
            self._json_error(409, str(exc))
        except Exception as exc:
            logger.error("Request failed: %s\n%s", exc, traceback.format_exc())
            self._json_error(500, "The request failed. Check the Security Suite log for details.")

    def do_OPTIONS(self) -> None:
        self._json_error(405, "Cross-origin preflight is not supported.")

    def _read_json(self) -> Dict[str, Any]:
        content_type = self.headers.get_content_type()
        if content_type != "application/json":
            raise ValueError("Content-Type must be application/json.")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid Content-Length.") from exc
        if length < 0 or length > self.MAX_JSON_BODY:
            raise ValueError("Request body is too large.")
        data = self.rfile.read(length)
        if not data:
            return {}
        try:
            value = json.loads(data)
        except json.JSONDecodeError as exc:
            raise ValueError("Request body must contain valid JSON.") from exc
        if not isinstance(value, dict):
            raise ValueError("Request body must be a JSON object.")
        return value

    def _drain_request_body(self) -> None:
        """Read a bounded body before early POST rejection responses."""
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return
        if 0 < length <= self.MAX_JSON_BODY:
            self.rfile.read(length)

    def _valid_host(self) -> bool:
        host = self.headers.get("Host", "")
        try:
            parsed = urllib.parse.urlsplit("//" + host)
            hostname = parsed.hostname
            port = parsed.port
        except ValueError:
            return False
        expected_port = self.server.server_address[1]  # type: ignore[attr-defined]
        return hostname in {"localhost", "127.0.0.1", "::1"} and (port is None or port == expected_port)

    def _valid_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        try:
            parsed = urllib.parse.urlsplit(origin)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            return False
        expected_port = self.server.server_address[1]  # type: ignore[attr-defined]
        return parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"} and port == expected_port

    def _send_json(self, status: int, payload: Any) -> None:
        self._send_bytes(status, json.dumps(payload, ensure_ascii=True).encode("utf-8"), "application/json; charset=utf-8")

    def _json_error(self, status: int, message: str) -> None:
        self._send_json(status, {"error": message})

    def _send_bytes(self, status: int, data: bytes, content_type: str, filename: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        if filename:
            safe_name = filename.replace('"', "")
            self.send_header("Content-Disposition", f'attachment; filename="{safe_name}"')
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, message: str, *args: Any) -> None:
        logger.info("dashboard %s - %s", self.client_address[0], message % args)


def create_server(host: str = "127.0.0.1", port: int = 8765, app: SecuritySuiteApp | None = None) -> SecuritySuiteHTTPServer:
    """Create a loopback-only server and reject accidental network exposure."""
    try:
        address = ip_address(host)
        is_loopback = address.is_loopback
    except ValueError:
        is_loopback = host.lower() == "localhost"
    if not is_loopback:
        raise ValueError("The dashboard may bind only to localhost or a loopback IP address.")
    if not 0 <= int(port) <= 65535:
        raise ValueError("Port must be between 0 and 65535.")
    return SecuritySuiteHTTPServer((host, int(port)), app or SecuritySuiteApp())


def create_available_server(host: str, port: int, app: SecuritySuiteApp) -> SecuritySuiteHTTPServer:
    for candidate in ([0] if port == 0 else range(port, min(port + 20, 65536))):
        try:
            return create_server(host=host, port=candidate, app=app)
        except OSError as exc:
            if exc.errno not in {errno.EADDRINUSE, errno.EACCES} and getattr(exc, "winerror", None) not in {10048, 10013}:
                raise
            logger.warning("Local port %s is unavailable; trying the next port.", candidate)
    raise RuntimeError("No local dashboard port is available. Use --port with another port.")


def serve_dashboard(host: str = "127.0.0.1", port: int = 8766, open_browser: bool = True,
                    version: str = "2.0.0", write_runtime: bool = False) -> None:
    app = SecuritySuiteApp(version=version)
    server = create_available_server(host=host, port=port, app=app)
    actual_port = server.server_address[1]
    url = f"http://{host}:{actual_port}/"
    print(f"Security Suite dashboard: {url}")
    print("Press Ctrl+C to stop.")
    if write_runtime:
        runtime = app.root / "runtime"
        runtime.mkdir(exist_ok=True)
        pending = runtime / f"dashboard-{os.getpid()}.tmp"
        pending.write_text(json.dumps({"url": url, "pid": os.getpid(), "instanceId": app.instance_id}), encoding="utf-8")
        pending.replace(runtime / "dashboard.json")
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
