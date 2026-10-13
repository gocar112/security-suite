"""Launch or reopen one persistent local dashboard for this project."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.parse
import webbrowser


def project_id(root: Path) -> str:
    return hashlib.sha256(str(root.resolve()).casefold().encode()).hexdigest()[:24]


def read_running(root: Path) -> dict | None:
    """Trust a saved address only after checking identity on literal loopback."""
    try:
        record = json.loads((root / "runtime" / "dashboard.json").read_text(encoding="utf-8"))
        url = urllib.parse.urlsplit(record["url"])
        if (url.scheme != "http" or url.hostname != "127.0.0.1" or not url.port
                or url.username or url.password or url.path != "/" or url.query or url.fragment):
            return None
        connection = http.client.HTTPConnection("127.0.0.1", url.port, timeout=1)
        try:
            connection.request("GET", "/api/health")
            response = connection.getresponse()
            if response.status != 200:
                return None
            health = json.loads(response.read(4096))
        finally:
            connection.close()
        if (health.get("name") == "Security Suite" and health.get("projectId") == project_id(root)
                and health.get("instanceId") == record.get("instanceId")
                and health.get("pid") == record.get("pid")):
            return record
    except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
        pass
    return None


def launch_dashboard(port: int = 8766, open_browser: bool = True, root: Path | None = None) -> dict:
    root = (root or Path(__file__).resolve().parent.parent).resolve()
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")
    record = read_running(root)
    if record is None:
        runtime = root / "runtime"
        runtime.mkdir(exist_ok=True)
        command = [sys.executable, "-u", str(root / "security_suite.py"), "serve",
                   "--port", str(port), "--no-browser", "--write-runtime"]
        options = {"cwd": str(root), "stdin": subprocess.DEVNULL, "close_fds": True}
        if os.name == "nt":
            options["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
            startup = subprocess.STARTUPINFO()
            startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startup.wShowWindow = subprocess.SW_HIDE
            options["startupinfo"] = startup
        else:
            options["start_new_session"] = True
        log_path = runtime / "dashboard.log"
        with log_path.open("ab") as log:
            process = subprocess.Popen(command, stdout=log, stderr=log, **options)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            record = read_running(root)
            if record:
                break
            if process.poll() is not None:
                raise RuntimeError(f"Dashboard could not start. See {log_path}")
            time.sleep(0.2)
        if not record:
            raise RuntimeError(f"Dashboard did not become ready within 15 seconds. See {log_path}")
    if open_browser:
        webbrowser.open(record["url"])
    return record
