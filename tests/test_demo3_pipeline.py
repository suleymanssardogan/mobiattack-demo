"""Comprehensive Tests for Demo 3 Deterministic Static Analysis Pipeline."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from src.demo3.candidate_model import (
    CandidateOccurrence,
    CanonicalCandidate,
    RawCandidate,
    ScanStatistics,
)
from src.demo3.deduplicator import CandidateDeduplicator
from src.demo3.file_walker import deterministic_walk
from src.demo3.normalizer import (
    clean_extraction_artifacts,
    normalize_candidate,
    normalize_domain,
    normalize_ip,
    normalize_path,
    normalize_url,
)
from src.demo3.pattern_extractor import extract_candidates_from_text
from src.demo3.scanner import scan_artifacts_deterministically
from src.demo3.schema_validator import (
    SchemaValidationError,
    validate_baseline_report,
)
from src.demo3.baseline_reporter import build_baseline_report, save_baseline_report


class TestDemo3Pipeline(unittest.TestCase):
    """Verifies all Demo 3 core requirements."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root_path = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    # --- TEST 1: URL extraction ---
    def test_01_url_extraction(self) -> None:
        sample_line = 'const-string v0, "https://api.example.com/v1/users?token=Secret123"'
        raw_cands = list(extract_candidates_from_text(sample_line, "smali/ApiClient.smali", 42))

        url_cands = [c for c in raw_cands if c.type == "url"]
        self.assertTrue(len(url_cands) >= 1)
        c = url_cands[0]
        self.assertEqual(c.raw_value, "https://api.example.com/v1/users?token=Secret123")
        self.assertEqual(c.source_file, "smali/ApiClient.smali")
        self.assertEqual(c.line_number, 42)
        self.assertEqual(c.extraction_method, "network_url_pattern")
        self.assertIn("https://api.example.com", c.evidence)

    # --- TEST 2: Normalization ---
    def test_02_normalization_preserves_semantics(self) -> None:
        # Case A: URL host lowercasing, path/query case preserved, default port stripped
        raw_url = '  "HTTPS://API.EXAMPLE.COM:443/v1/UserProfile?Token=AbCdEf" ; '
        canon_url, comp = normalize_url(raw_url)
        self.assertEqual(canon_url, "https://api.example.com/v1/UserProfile?Token=AbCdEf")
        self.assertEqual(comp["host"], "api.example.com")
        self.assertEqual(comp["path"], "/v1/UserProfile")
        self.assertEqual(comp["query"], "Token=AbCdEf")

        # Case B: Domain normalization
        canon_dom, _ = normalize_domain("  Api.Example.Com.  ")
        self.assertEqual(canon_dom, "api.example.com")

        # Case C: Path normalization preserves casing
        canon_path, _ = normalize_path("v2/Auth/Login")
        self.assertEqual(canon_path, "/v2/Auth/Login")

        # Case D: IP normalization
        canon_ip, _ = normalize_ip("192.168.01.001")
        self.assertEqual(canon_ip, "192.168.1.1")

    # --- TEST 3: Deduplication ---
    def test_03_deduplication_collapses_equivalent_candidates(self) -> None:
        dedup = CandidateDeduplicator()

        # Same URL formatted with different host casing across 3 files
        dedup.add_raw(RawCandidate(
            type="url",
            raw_value="https://api.example.com/v1/users",
            source_file="FileA.smali",
            line_number=10,
            evidence="FileA line 10",
        ))
        dedup.add_raw(RawCandidate(
            type="url",
            raw_value="HTTPS://API.EXAMPLE.COM/v1/users",
            source_file="FileB.smali",
            line_number=25,
            evidence="FileB line 25",
        ))
        dedup.add_raw(RawCandidate(
            type="url",
            raw_value="https://api.example.com:443/v1/users",
            source_file="config.json",
            line_number=5,
            evidence="config line 5",
        ))

        canonical_list = dedup.get_canonical_candidates()
        # Must collapse into exactly 1 canonical candidate
        self.assertEqual(len(canonical_list), 1)
        cand = canonical_list[0]
        self.assertEqual(cand.value, "https://api.example.com/v1/users")
        self.assertEqual(cand.type, "url")
        self.assertEqual(cand.occurrence_count, 3)

    # --- TEST 4: Multiple occurrences preserved after deduplication ---
    def test_04_multiple_occurrences_preserved(self) -> None:
        dedup = CandidateDeduplicator()
        sources = [("smali/Client.smali", 12), ("smali/Service.smali", 88), ("assets/config.json", 3)]
        for sfile, sline in sources:
            dedup.add_raw(RawCandidate(
                type="url",
                raw_value="https://api.service.io/data",
                source_file=sfile,
                line_number=sline,
                evidence=f"match in {sfile}:{sline}",
            ))

        cand = dedup.get_canonical_candidates()[0]
        self.assertEqual(cand.occurrence_count, 3)
        self.assertEqual(len(cand.occurrences), 3)

        observed_sources = [(occ.source_file, occ.line_number) for occ in cand.occurrences]
        # Occurrences are sorted deterministically
        self.assertEqual(
            observed_sources,
            [("assets/config.json", 3), ("smali/Client.smali", 12), ("smali/Service.smali", 88)],
        )

    # --- TEST 5: Provenance / source preserved ---
    def test_05_provenance_and_evidence_details(self) -> None:
        dedup = CandidateDeduplicator()
        dedup.add_raw(RawCandidate(
            type="url",
            raw_value="https://gateway.internal.net/rpc",
            source_file="smali/com/net/Gateway.smali",
            line_number=145,
            extraction_method="network_url_pattern",
            evidence='const-string v1, "https://gateway.internal.net/rpc"',
        ))
        cand = dedup.get_canonical_candidates()[0]
        occ = cand.occurrences[0]
        self.assertEqual(occ.source_file, "smali/com/net/Gateway.smali")
        self.assertEqual(occ.line_number, 145)
        self.assertEqual(occ.extraction_method, "network_url_pattern")
        self.assertEqual(occ.raw_value, "https://gateway.internal.net/rpc")
        self.assertIn("const-string", occ.evidence)

    # --- TEST 6: JSON report validates against schema ---
    def test_06_baseline_report_validates_against_schema(self) -> None:
        # Create a mock completed scan
        mock_pipeline_result = {
            "demo_status": "completed",
            "acquisition": {
                "filename": "target_app.apk",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "package_name": "com.example.targetapp",
                "size_bytes": 10240,
                "source_type": "direct_apk",
            },
            "static_analysis": {
                "app": {"package_name": "com.example.targetapp"},
                "network_indicators": {
                    "network_urls": [
                        {"value": "https://api.example.com/v1", "source_file": "smali/A.smali", "line_number": 10}
                    ]
                },
                "api_candidates": [],
            },
            "vulnerabilities": {
                "findings": [
                    {
                        "id": "cleartext_traffic",
                        "rule_id": "android-cleartext",
                        "title": "Cleartext traffic permitted",
                        "severity": "HIGH",
                    }
                ]
            },
        }

        report = build_baseline_report(
            run_id="run_test_001",
            pipeline_result=mock_pipeline_result,
        )

        # Validate against schema
        validate_baseline_report(report)
        self.assertEqual(report["schema_version"], "1.0.0")
        self.assertEqual(report["scan"]["status"], "completed")
        self.assertEqual(report["inventory"]["candidate_count"], 1)

        # Save to disk and check file exists and is valid json
        out_path = save_baseline_report(self.root_path, report)
        self.assertTrue(out_path.is_file())
        with open(out_path, "r", encoding="utf-8") as f:
            disk_data = json.load(f)
        self.assertEqual(disk_data["schema_version"], "1.0.0")

    # --- TEST 7: Malformed candidate / report fails validation correctly ---
    def test_07_malformed_report_fails_validation(self) -> None:
        # Invalid schema version
        bad_report: dict = {
            "schema_version": "2.0.0",
            "scan": {"run_id": "r1", "status": "completed", "errors": [], "warnings": []},
            "artifact": {"source": "apk", "filename": "app.apk", "sha256": "123", "package_name": "pkg"},
            "analysis": {"files_discovered": 1, "files_analyzed": 1, "files_skipped": 0, "files_failed": 0},
            "inventory": {"candidate_count": 0, "candidates": []},
            "static_findings": [],
        }
        with self.assertRaises(SchemaValidationError):
            validate_baseline_report(bad_report)

        # Missing required occurrence field
        bad_report["schema_version"] = "1.0.0"
        bad_report["inventory"] = {
            "candidate_count": 1,
            "candidates": [
                {
                    "id": "c-01",
                    "type": "url",
                    "value": "https://api.com",
                    "occurrence_count": 1,
                    "occurrences": [
                        {"source_file": "A.smali"}  # missing raw_value, extraction_method, evidence
                    ],
                }
            ],
        }
        with self.assertRaises(SchemaValidationError):
            validate_baseline_report(bad_report)

    # --- TEST 8: Same fixture produces semantically stable output ---
    def test_08_semantic_stability_on_repeated_runs(self) -> None:
        fixture_dir = self.root_path / "app_fixture"
        smali_dir = fixture_dir / "smali"
        assets_dir = fixture_dir / "assets"
        smali_dir.mkdir(parents=True)
        assets_dir.mkdir(parents=True)

        (smali_dir / "ZClient.smali").write_text('const-string v0, "https://api.example.com/v1/auth"')
        (smali_dir / "AClient.smali").write_text('const-string v0, "https://api.example.com/v1/auth"')
        (assets_dir / "config.json").write_text('{"host": "https://beta.example.com/api", "ip": "10.0.0.5"}')

        run1 = scan_artifacts_deterministically(fixture_dir, include_fuel_smali=False)
        run2 = scan_artifacts_deterministically(fixture_dir, include_fuel_smali=False)

        # Semantics, candidate counts, ordering must be byte-for-byte identical
        self.assertEqual(run1["candidate_count"], run2["candidate_count"])
        self.assertEqual(run1["candidates"], run2["candidates"])
        self.assertEqual(run1["statistics"], run2["statistics"])

    # --- TEST 9: "0 candidates" differs from "analysis failed" ---
    def test_09_completed_vs_partial_vs_failed_distinction(self) -> None:
        # Case A: Completed with 0 candidates
        clean_dir = self.root_path / "clean_app"
        clean_dir.mkdir()
        (clean_dir / "AndroidManifest.xml").write_text("<manifest/>")
        (clean_dir / "empty.txt").write_text("Hello clean world with no endpoints")

        clean_res = scan_artifacts_deterministically(clean_dir, include_fuel_smali=False)
        self.assertEqual(clean_res["status"], "completed")
        self.assertEqual(clean_res["candidate_count"], 0)
        self.assertEqual(clean_res["statistics"]["files_failed"], 0)

        # Case B: Partial analysis (1 valid file, 1 corrupted binary file posing as utf-8)
        partial_dir = self.root_path / "partial_app"
        partial_dir.mkdir()
        (partial_dir / "valid.json").write_text('{"endpoint": "https://api.partial.com"}')
        # Write invalid non-UTF8 bytes to a .json file
        (partial_dir / "corrupted.json").write_bytes(b"\x80\x81\xff\xfe corrupted binary")

        partial_res = scan_artifacts_deterministically(partial_dir, include_fuel_smali=False)
        self.assertEqual(partial_res["status"], "partial")
        self.assertEqual(partial_res["statistics"]["files_analyzed"], 1)
        self.assertEqual(partial_res["statistics"]["files_failed"], 1)
        self.assertEqual(partial_res["candidate_count"], 1)

        # Case C: Failed analysis (0 analyzed, 1 failed)
        failed_dir = self.root_path / "failed_app"
        failed_dir.mkdir()
        (failed_dir / "bad.json").write_bytes(b"\x80\x81\xff\xfe unreadable")

        failed_res = scan_artifacts_deterministically(failed_dir, include_fuel_smali=False)
        self.assertEqual(failed_res["status"], "failed")
        self.assertEqual(failed_res["statistics"]["files_analyzed"], 0)
        self.assertEqual(failed_res["statistics"]["files_failed"], 1)


if __name__ == "__main__":
    unittest.main()
