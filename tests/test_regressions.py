import copy
import io
import json
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import main
from dashboard.generator import generate_dashboard
from parsers.nmap_parser import parse_nmap
from parsers.trivy_parser import parse_trivy
from parsers.zap_parser import parse_zap


def empty_results():
    return {
        "nmap": {"ports": [], "count": 0},
        "trivy": {"counts": {}, "vulnerabilities": [], "top_critical": [], "total": 0, "packages_affected": 0},
        "zap": {"counts": {}, "alerts": [], "total": 0},
    }


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "report.json"

    def report(self, data):
        self.path.write_text(json.dumps(data), encoding="utf-8")
        return str(self.path)

    def test_zap_native_risk_codes(self):
        result = parse_zap(self.report({"site": [{"alerts": [
            {"name": "High finding", "riskcode": "3", "confidence": "2"},
            {"name": "Medium finding", "riskcode": "2", "confidence": "3"},
        ]}]}))
        self.assertEqual(result["counts"]["High"], 1)
        self.assertEqual(result["counts"]["Medium"], 1)
        self.assertEqual(result["alerts"][0]["confidence"], "Medium")

    def test_zap_legacy_risk_names(self):
        result = parse_zap(self.report({"site": [{"alerts": [{"risk": "High"}]}]}))
        self.assertEqual(result["counts"]["High"], 1)

    def test_missing_reports_are_errors(self):
        for parser in (parse_nmap, parse_trivy, parse_zap):
            with self.subTest(parser=parser.__name__):
                self.assertTrue(parser(str(self.path)).get("error"))

    def test_invalid_json_is_an_error(self):
        self.path.write_text("invalid", encoding="utf-8")
        for parser in (parse_trivy, parse_zap):
            with self.subTest(parser=parser.__name__):
                self.assertTrue(parser(str(self.path)).get("error"))

    def test_unexpected_json_shape_is_an_error(self):
        for parser in (parse_trivy, parse_zap):
            with self.subTest(parser=parser.__name__):
                self.assertTrue(parser(self.report({})).get("error"))

    def test_empty_valid_reports_remain_valid(self):
        self.assertFalse(parse_trivy(self.report({"Results": []})).get("error"))
        self.assertFalse(parse_zap(self.report({"site": []})).get("error"))

    def test_nmap_preserves_service_versions(self):
        self.path.write_text("3000/tcp open http Node.js Express framework\n", encoding="utf-8")
        result = parse_nmap(str(self.path))
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["ports"][0]["version"], "Node.js Express framework")

    def test_empty_nmap_output_is_an_error(self):
        self.path.write_text("", encoding="utf-8")
        self.assertTrue(parse_nmap(str(self.path)).get("error"))

    def test_zap_risk_description_fallback(self):
        result = parse_zap(self.report({"site": [{"alerts": [{"riskdesc": "High (Medium)"}]}]}))
        self.assertEqual(result["counts"]["High"], 1)

    def test_dashboard_rejects_failed_reports(self):
        data = empty_results()
        data["zap"]["error"] = "Scan failed"
        output = Path(self.directory.name) / "dashboard.html"
        self.assertFalse(generate_dashboard(data, str(output)))
        self.assertFalse(output.exists())

    def test_dashboard_escapes_findings_and_script_data(self):
        data = empty_results()
        payload = '</script><script>alert("test")</script>'
        vuln = {"id": "CVE-2026-1234", "severity": "HIGH", "package": payload,
                "installed_version": "1", "fixed_version": "2", "title": payload,
                "description": '\" onmouseover=\"alert(1)', "cvss_score": 8.0}
        data["trivy"].update(vulnerabilities=[vuln], top_critical=[vuln], total=1, packages_affected=1)
        data["nmap"] = {"count": 1, "ports": [{"port": "80/tcp", "service": "http", "version": payload}]}
        original = copy.deepcopy(data)
        output = Path(self.directory.name) / "dashboard.html"
        self.assertTrue(generate_dashboard(data, str(output)))
        html = output.read_text(encoding="utf-8")
        self.assertNotIn(payload, html)
        self.assertNotIn('</script><script>', html)
        self.assertNotIn('title="" onmouseover=', html)
        self.assertIn("&lt;script&gt;", html)
        self.assertEqual(data, original)


class PipelineTests(unittest.TestCase):
    def run_pipeline(self, failed=None, juice_shop=True):
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(redirect_stdout(io.StringIO()))
        args = SimpleNamespace(juice_shop=juice_shop, target=None if juice_shop else "https://example.test", no_browser=True)
        replacements = {"parse_arguments": args, "start_environment": None,
                        "wait_for_service": True, "create_report_dir": "reports/test",
                        "run_nmap": failed != "nmap", "run_zap": failed != "zap",
                        "run_trivy": failed != "trivy", "_create_empty_trivy_report": None,
                        "generate_dashboard": True}
        mocks = {name: stack.enter_context(patch.object(main, name, return_value=value))
                 for name, value in replacements.items()}
        for name, data in empty_results().items():
            stack.enter_context(patch.object(main, "parse_" + name, return_value=data))
        return mocks

    def test_successful_pipeline_still_generates_dashboard(self):
        mocks = self.run_pipeline()
        main.main()
        mocks["generate_dashboard"].assert_called_once()

    def test_external_target_skips_trivy(self):
        mocks = self.run_pipeline(juice_shop=False)
        main.main()
        mocks["run_trivy"].assert_not_called()
        mocks["generate_dashboard"].assert_called_once()

    def test_scanner_failure_stops_success_report(self):
        for scanner in ("nmap", "zap", "trivy"):
            with self.subTest(scanner=scanner):
                mocks = self.run_pipeline(failed=scanner)
                with self.assertRaises(SystemExit) as error:
                    main.main()
                self.assertNotEqual(error.exception.code, 0)
                mocks["generate_dashboard"].assert_not_called()


if __name__ == "__main__":
    unittest.main()
