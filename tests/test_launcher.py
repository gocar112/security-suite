import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from core.launcher import launch_dashboard, read_running
from core.web_server import SecuritySuiteApp, create_server


class LauncherTests(unittest.TestCase):
    def test_reopens_verified_server_without_spawning_another(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = SecuritySuiteApp(root=root)
            server = create_server(port=0, app=app)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                import os
                record = {"url": f"http://127.0.0.1:{server.server_address[1]}/", "pid": os.getpid(), "instanceId": app.instance_id}
                (root / "runtime").mkdir()
                state = root / "runtime" / "dashboard.json"
                state.write_text(json.dumps(record), encoding="utf-8")
                with patch("core.launcher.subprocess.Popen") as spawn, patch("core.launcher.webbrowser.open") as browser:
                    self.assertEqual(launch_dashboard(root=root), record)
                    self.assertEqual(launch_dashboard(root=root), record)
                    spawn.assert_not_called()
                    browser.assert_called_with(record["url"])
                record["instanceId"] = "stale"
                state.write_text(json.dumps(record), encoding="utf-8")
                self.assertIsNone(read_running(root))
                record["url"] = "https://example.com/"
                state.write_text(json.dumps(record), encoding="utf-8")
                with patch("core.launcher.http.client.HTTPConnection") as connect:
                    self.assertIsNone(read_running(root))
                    connect.assert_not_called()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
