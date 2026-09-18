import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import main
from scanners.nmap_scanner import run_nmap
from scanners.zap_scanner import _normalize_path_for_docker, run_zap
from scanners.trivy_scanner import _run_trivy_scan
from utils.waiter import wait_for_service


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.output = self.directory.name
        platform = patch("scanners.zap_scanner.platform.system", return_value="Windows")
        platform.start()
        self.addCleanup(platform.stop)

    @patch("scanners.nmap_scanner.subprocess.run")
    def test_external_nmap_uses_bridge_and_hostname(self, run):
        run.return_value.returncode = 0
        self.assertTrue(run_nmap(self.output, "https://example.test:8443/path"))
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("--network") + 1], "bridge")
        self.assertEqual(command[-1], "example.test")

    @patch("scanners.nmap_scanner.get_docker_network", return_value="avap_avap")
    @patch("scanners.nmap_scanner.subprocess.run")
    def test_juice_shop_keeps_compose_network(self, run, network):
        run.return_value.returncode = 0
        self.assertTrue(run_nmap(self.output))
        self.assertIn("avap_avap", run.call_args.args[0])
        network.assert_called_once()

    @patch("scanners.zap_scanner.subprocess.run")
    def test_external_zap_does_not_match_localhost_in_path(self, run):
        run.return_value.returncode = 2
        self.assertTrue(run_zap(self.output, "https://example.test/localhost"))
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("--network") + 1], "bridge")

    @patch("scanners.zap_scanner.subprocess.run")
    def test_local_zap_uses_host_network(self, run):
        run.return_value.returncode = 0
        self.assertTrue(run_zap(self.output, "http://localhost:8080"))
        self.assertIn("host", run.call_args.args[0])

    @patch("scanners.zap_scanner.platform.system", return_value="Windows")
    def test_windows_mount_keeps_drive_letter(self, system):
        self.assertEqual(_normalize_path_for_docker(r"C:\Users\Example Name\reports"),
                         "C:/Users/Example Name/reports")

    @patch("scanners.nmap_scanner.subprocess.run", side_effect=subprocess.TimeoutExpired("docker", 900))
    def test_nmap_timeout_is_a_failure(self, run):
        self.assertFalse(run_nmap(self.output, "https://example.test"))

    @patch("scanners.trivy_scanner.subprocess.run")
    def test_trivy_failure_is_reported(self, run):
        run.return_value = SimpleNamespace(returncode=1, stderr="Image unavailable")
        log = io.StringIO()
        with redirect_stdout(log):
            self.assertFalse(_run_trivy_scan("image", str(Path(self.output) / "trivy.json"), "json"))
        self.assertIn("Image unavailable", log.getvalue())


class AvailabilityTests(unittest.TestCase):
    @patch("utils.waiter.requests.get")
    def test_authentication_required_is_still_available(self, get):
        for code in (200, 204, 301, 401, 403, 404):
            with self.subTest(code=code):
                get.return_value.status_code = code
                self.assertTrue(wait_for_service("https://example.test"))

    @patch("utils.waiter.time.sleep")
    @patch("utils.waiter.WAIT_RETRIES", 2)
    @patch("utils.waiter.requests.get")
    def test_server_error_is_retried(self, get, sleep):
        get.return_value.status_code = 503
        self.assertFalse(wait_for_service("https://example.test"))
        self.assertEqual(get.call_count, 2)


class IntegrationTests(unittest.TestCase):
    def test_external_pipeline_from_scanner_output_to_dashboard(self):
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory) / "reports"
            report_dir.mkdir()
            args = SimpleNamespace(juice_shop=False, target="https://example.test", no_browser=True)

            def docker_run(command, **kwargs):
                if "instrumentisto/nmap" in command:
                    kwargs["stdout"].write("443/tcp open ssl/http Test server\n")
                    return SimpleNamespace(returncode=0)
                if "zap-baseline.py" in command:
                    report = {"site": [{"alerts": [{"name": "Example finding", "riskcode": "3", "confidence": "2"}]}]}
                    (report_dir / "zap.json").write_text(json.dumps(report), encoding="utf-8")
                    return SimpleNamespace(returncode=2)
                self.fail(f"Unexpected Docker invocation: {command}")

            with patch.object(main, "parse_arguments", return_value=args), \
                    patch.object(main, "create_report_dir", return_value=str(report_dir)), \
                    patch.object(main, "wait_for_service", return_value=True), \
                    patch("scanners.zap_scanner.platform.system", return_value="Windows"), \
                    patch("subprocess.run", side_effect=docker_run):
                main.main()

            html = (report_dir / "dashboard.html").read_text(encoding="utf-8")
            self.assertIn("Example finding", html)
            self.assertIn("Test server", html)
            self.assertIn('badge high', html)
            self.assertEqual(json.loads((report_dir / "trivy.json").read_text()), {"Results": []})


if __name__ == "__main__":
    unittest.main()
