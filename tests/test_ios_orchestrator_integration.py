from __future__ import annotations

import json
import plistlib
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from src.demo_orchestrator import run_demo


class TestIOSOrchestratorIntegration(unittest.TestCase):
    """End-to-end integration tests for iOS static analysis pipeline via demo_orchestrator."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.ipa_path = self.root / "sample_app.ipa"
        self.output_root = self.root / "output"
        self._create_synthetic_ipa(self.ipa_path)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _create_synthetic_ipa(self, dest: Path) -> None:
        """Constructs a minimal valid IPA with Info.plist, Mach-O executable, and frameworks."""
        plist_data = {
            "CFBundleIdentifier": "com.example.integrationapp",
            "CFBundleName": "IntegrationApp",
            "CFBundleDisplayName": "Integration App",
            "CFBundleExecutable": "IntegrationApp",
            "CFBundleShortVersionString": "2.1.0",
            "CFBundleVersion": "42",
            "MinimumOSVersion": "15.0",
            "CFBundleSupportedPlatforms": ["iPhoneOS"],
            "UIDeviceFamily": [1, 2],
            "CFBundleURLTypes": [
                {
                    "CFBundleURLName": "com.example.customurl",
                    "CFBundleURLSchemes": ["myappscheme"],
                }
            ],
            "NSCameraUsageDescription": "Camera is required for document scanning.",
            "NSLocationWhenInUseUsageDescription": "Location is needed for nearby search.",
            "NSAppTransportSecurity": {
                "NSAllowsArbitraryLoads": False,
                "NSExceptionDomains": {
                    "insecure.example.com": {
                        "NSExceptionAllowsInsecureHTTPLoads": True,
                    }
                },
            },
        }
        plist_bytes = plistlib.dumps(plist_data)

        # 64-bit Little-Endian Mach-O header (MH_MAGIC_64 = 0xfeedfacf)
        # magic(4), cputype(4)=ARM64(0x0100000c), cpusubtype(4)=0, filetype(4)=EXEC(2),
        # ncmds(4)=0, sizeofcmds(4)=0, flags(4)=0x00200085, reserved(4)=0
        macho_bytes = struct.pack("<IIIIIIII", 0xfeedfacf, 0x0100000C, 0, 2, 0, 0, 0x00200085, 0)
        # Append some text strings for network indicators
        macho_bytes += b"\x00" * 32
        macho_bytes += b"https://api.integration.example.com/v2/verify\x00"
        macho_bytes += b"192.168.1.105\x00"
        macho_bytes += b"/api/v1/auth/token\x00"

        with zipfile.ZipFile(dest, "w") as zf:
            zf.writestr("Payload/IntegrationApp.app/Info.plist", plist_bytes)
            zf.writestr("Payload/IntegrationApp.app/IntegrationApp", macho_bytes)
            zf.writestr("Payload/IntegrationApp.app/Frameworks/HelperLib.framework/HelperLib", b"mock binary")
            zf.writestr("Payload/IntegrationApp.app/PlugIns/ShareExt.appex/Info.plist", b"<plist></plist>")
            zf.writestr("Payload/IntegrationApp.app/settings.json", b'{"endpoint": "https://config.example.com/live"}')

    def test_run_demo_ios_pipeline_success(self) -> None:
        """Validates end-to-end execution of iOS static pipeline through run_demo."""
        stages_seen: list[tuple[str, str]] = []

        def callback(stage: str, state: str, message: str, data: dict | None = None) -> None:
            stages_seen.append((stage, state))

        result = run_demo(
            url=str(self.ipa_path),
            output_root=self.output_root,
            platform="ios",
            progress_callback=callback,
        )

        # 1. Verify demo status and platform
        self.assertEqual(result.get("demo_status"), "completed")
        self.assertEqual(result.get("platform"), "ios")

        # 2. Verify application identity facts
        app = result.get("application", {})
        self.assertEqual(app.get("bundle_identifier"), "com.example.integrationapp")
        self.assertEqual(app.get("display_name"), "Integration App")
        self.assertEqual(app.get("executable"), "IntegrationApp")
        self.assertEqual(app.get("version"), "2.1.0")
        self.assertEqual(app.get("build"), "42")
        self.assertEqual(app.get("minimum_os_version"), "15.0")

        # 3. Verify structure facts
        struct_data = result.get("structure", {})
        exe = struct_data.get("executable", {})
        self.assertEqual(exe.get("name"), "IntegrationApp")
        self.assertEqual(exe.get("macho_type"), "Mach-O executable")
        self.assertEqual(exe.get("bitness"), 64)
        self.assertIn("arm64", exe.get("architectures", []))

        frameworks = struct_data.get("frameworks", [])
        self.assertTrue(any(f["name"] == "HelperLib.framework" for f in frameworks))

        extensions = struct_data.get("extensions", [])
        self.assertTrue(any(e["name"] == "ShareExt.appex" for e in extensions))

        # 4. Verify configuration facts
        config = result.get("configuration", {})
        usage_keys = [u["key"] for u in config.get("usage_descriptions", [])]
        self.assertIn("NSCameraUsageDescription", usage_keys)
        self.assertIn("NSLocationWhenInUseUsageDescription", usage_keys)
        schemes = [s.get("scheme") if isinstance(s, dict) else s for s in config.get("url_schemes", [])]
        self.assertIn("myappscheme", schemes)

        # 5. Verify network indicators and empty API candidates
        net = result.get("network_indicators", {})
        self.assertIsInstance(net, dict)
        urls = [u["value"] for u in net.get("network_urls", [])]
        self.assertIn("https://config.example.com/live", urls)
        domains = [d["value"] for d in net.get("domains", [])]
        self.assertIn("insecure.example.com", domains)

        # Ground rule: api_candidates strictly empty in Phase 1
        self.assertEqual(result.get("api_candidates"), [])

        # Ground rule: runtime analysis not implemented
        runtime = result.get("runtime", {})
        self.assertEqual(runtime.get("status"), "not_implemented")

        # Ground rule: iOS vulnerability analysis is not implemented (not_evaluated, NOT CLEAN)
        vulns = result.get("vulnerabilities", {})
        self.assertEqual(vulns.get("status"), "not_evaluated")
        self.assertEqual(vulns.get("reason"), "not_implemented")
        self.assertEqual(vulns.get("risk_score"), "NOT_EVALUATED")
        self.assertEqual(vulns.get("findings"), [])

        # 6. Verify generated reports exist and contain factual content
        report_json_path = self.output_root / "report.json"
        report_html_path = self.output_root / "report.html"
        self.assertTrue(report_json_path.is_file())
        self.assertTrue(report_html_path.is_file())

        with open(report_json_path, encoding="utf-8") as f:
            json_report = json.load(f)
        self.assertEqual(json_report.get("platform"), "ios")
        self.assertEqual(json_report.get("application", {}).get("bundle_identifier"), "com.example.integrationapp")
        self.assertEqual(json_report.get("vulnerabilities", {}).get("status"), "not_evaluated")
        self.assertEqual(json_report.get("vulnerabilities", {}).get("reason"), "not_implemented")

        with open(report_html_path, encoding="utf-8") as f:
            html_report = f.read()
        self.assertIn("com.example.integrationapp", html_report)
        self.assertIn("IntegrationApp", html_report)
        self.assertIn("NSCameraUsageDescription", html_report)
        self.assertIn("Vulnerability Analysis", html_report)
        self.assertIn("Not evaluated", html_report)
        self.assertIn("iOS vulnerability evaluation is not implemented in Phase 1", html_report)
        # Ensure Android-specific terminology does not leak into iOS HTML report
        self.assertNotIn("Launcher Activity", html_report)
        self.assertNotIn("DEX Count", html_report)
        self.assertNotIn("Smali Roots", html_report)

        # 7. Verify stage progress callbacks occurred
        stages = [s[0] for s in stages_seen]
        self.assertIn("acquisition", stages)
        self.assertIn("preprocessing", stages)
        self.assertIn("static_analysis", stages)
        self.assertIn("runtime", stages)
        self.assertIn("demo", stages)


if __name__ == "__main__":
    unittest.main()
