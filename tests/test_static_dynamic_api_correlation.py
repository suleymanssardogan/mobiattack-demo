"""Comprehensive Unit & Pipeline Integration Tests for Static <-> Dynamic API Correlation (Week 2 — Day 7 Task 7.1)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from src.dynamic.correlation.api_correlator import (
    correlate_static_dynamic_apis,
    match_paths,
    normalize_host,
    normalize_method,
    normalize_path,
)
from src.dynamic.correlation.models import (
    ApiCorrelationEntry,
    ApiCorrelationResult,
    ApiCorrelationSummary,
    MatchConfidence,
    MatchType,
    generate_deterministic_correlation_id,
)
from src.dynamic.traffic.models import (
    ActionTrafficEvidence,
    HttpRequestModel,
    HttpResponseModel,
    TrafficEvidenceArtifact,
    TrafficTransaction,
)


def _make_transaction(
    tx_id: str = "tx_1",
    method: str = "GET",
    host: str = "api.example.com",
    path: str = "/v1/users",
    status_code: int = 200,
    query: dict | None = None,
    timestamp: str = "2026-10-01T12:00:00Z",
) -> TrafficTransaction:
    return TrafficTransaction(
        transaction_id=tx_id,
        request=HttpRequestModel(
            method=method,
            scheme="https", port=443,
            host=host,
            path=path,
            query=query or {},
            timestamp=timestamp,
            headers={"content-type": "application/json"},
        ),
        response=HttpResponseModel(
            status_code=status_code,
            headers={"content-type": "application/json"},
            timestamp=timestamp,
        ),
    )


class TestStaticDynamicApiCorrelation(unittest.TestCase):
    """Verifies all 42 requirements for Task 7.1 Static <-> Dynamic API Correlation."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)
        self.session_id = "test-session-uuid-7100"

    def tearDown(self):
        self.temp_dir.cleanup()

    # 1. exact host/path/method match
    def test_01_exact_host_path_method_match(self):
        static_cands = [
            {
                "id": "cand_1",
                "base_url": "https://api.example.com",
                "path": "/v1/login",
                "method": "POST",
            }
        ]
        tx = _make_transaction(
            tx_id="tx_login_1",
            method="POST",
            host="api.example.com",
            path="/v1/login",
            status_code=200,
        )
        res = correlate_static_dynamic_apis(static_cands, [tx], session_id=self.session_id)
        self.assertEqual(res.summary.correlated_count, 1)
        self.assertEqual(len(res.correlations), 1)
        entry = res.correlations[0]
        self.assertEqual(entry.match_type, MatchType.EXACT.value)
        self.assertEqual(entry.confidence, MatchConfidence.HIGH.value)
        self.assertEqual(entry.static_candidate_id, "cand_1")
        self.assertEqual(entry.transaction_ids, ["tx_login_1"])
        self.assertEqual(entry.observed_methods, ["POST"])
        self.assertEqual(entry.observed_status_codes, [200])

    # 2. host normalization lowercase
    def test_02_host_normalization_lowercase(self):
        self.assertEqual(normalize_host("API.Example.COM."), "api.example.com")
        self.assertEqual(normalize_host("http://API.Example.COM:80/path"), "api.example.com")
        self.assertEqual(normalize_host("https://Sub.Domain.org:443"), "sub.domain.org")

        static_cands = [
            {"id": "c1", "base_url": "https://API.EXAMPLE.COM", "path": "/test", "method": "GET"}
        ]
        tx = _make_transaction(host="api.example.com", path="/test", method="GET")
        res = correlate_static_dynamic_apis(static_cands, [tx])
        self.assertEqual(res.summary.correlated_count, 1)
        self.assertEqual(res.correlations[0].match_type, MatchType.EXACT.value)

    # 3. trailing slash normalization
    def test_03_trailing_slash_normalization(self):
        self.assertEqual(normalize_path("/api/login/"), "/api/login")
        self.assertEqual(normalize_path("/"), "/")

        static_cands = [
            {"id": "c1", "base_url": "https://api.example.com", "path": "/api/login/", "method": "POST"}
        ]
        tx = _make_transaction(host="api.example.com", path="/api/login", method="POST")
        res = correlate_static_dynamic_apis(static_cands, [tx])
        self.assertEqual(res.summary.correlated_count, 1)
        self.assertEqual(res.correlations[0].match_type, MatchType.EXACT.value)

    # 4. duplicate slash normalization
    def test_04_duplicate_slash_normalization(self):
        self.assertEqual(normalize_path("//v1///users//"), "/v1/users")
        static_cands = [
            {"id": "c1", "base_url": "https://api.example.com", "path": "//v1///users", "method": "GET"}
        ]
        tx = _make_transaction(host="api.example.com", path="/v1/users", method="GET")
        res = correlate_static_dynamic_apis(static_cands, [tx])
        self.assertEqual(res.summary.correlated_count, 1)

    # 5. query excluded from path identity
    def test_05_query_excluded_from_path_identity(self):
        self.assertEqual(normalize_path("/search?q=foo&page=2"), "/search")
        static_cands = [
            {"id": "c1", "base_url": "https://api.example.com", "path": "/search", "method": "GET"}
        ]
        tx = _make_transaction(
            host="api.example.com",
            path="/search",
            query={"q": "sensitive_term", "filter": "active"},
            method="GET",
        )
        res = correlate_static_dynamic_apis(static_cands, [tx])
        self.assertEqual(res.summary.correlated_count, 1)
        self.assertEqual(res.correlations[0].path, "/search")
        self.assertEqual(res.correlations[0].observed_query_keys, ["filter", "q"])

    # 6. template {id} matches numeric segment
    def test_06_template_curly_id_matches_numeric_segment(self):
        matched, is_tmpl = match_paths("/users/{id}", "/users/42")
        self.assertTrue(matched)
        self.assertTrue(is_tmpl)

        static_cands = [
            {"id": "c1", "base_url": "https://api.example.com", "path": "/users/{id}", "method": "GET"}
        ]
        tx = _make_transaction(host="api.example.com", path="/users/42", method="GET")
        res = correlate_static_dynamic_apis(static_cands, [tx])
        self.assertEqual(res.summary.correlated_count, 1)
        self.assertEqual(res.correlations[0].match_type, MatchType.TEMPLATE.value)
        self.assertEqual(res.correlations[0].confidence, MatchConfidence.MEDIUM.value)

    # 7. :id matches numeric segment
    def test_07_template_colon_id_matches_numeric_segment(self):
        matched, is_tmpl = match_paths("/users/:id/profile", "/users/999/profile")
        self.assertTrue(matched)
        self.assertTrue(is_tmpl)

        static_cands = [
            {"id": "c1", "base_url": "https://api.example.com", "path": "/users/:id/profile", "method": "GET"}
        ]
        tx = _make_transaction(host="api.example.com", path="/users/999/profile", method="GET")
        res = correlate_static_dynamic_apis(static_cands, [tx])
        self.assertEqual(res.summary.correlated_count, 1)
        self.assertEqual(res.correlations[0].match_type, MatchType.TEMPLATE.value)

    # 8. <id> matches numeric segment
    def test_08_template_angle_id_matches_numeric_segment(self):
        matched, is_tmpl = match_paths("/api/<id>", "/api/1234")
        self.assertTrue(matched)
        self.assertTrue(is_tmpl)

        static_cands = [
            {"id": "c1", "base_url": "https://api.example.com", "path": "/api/<id>", "method": "DELETE"}
        ]
        tx = _make_transaction(host="api.example.com", path="/api/1234", method="DELETE")
        res = correlate_static_dynamic_apis(static_cands, [tx])
        self.assertEqual(res.summary.correlated_count, 1)
        self.assertEqual(res.correlations[0].match_type, MatchType.TEMPLATE.value)

    # 9. UUID segment template match
    def test_09_uuid_segment_template_match(self):
        uuid_str = "550e8400-e29b-41d4-a716-446655440000"
        matched, is_tmpl = match_paths("/orders/{order_id}", f"/orders/{uuid_str}")
        self.assertTrue(matched)
        self.assertTrue(is_tmpl)

        static_cands = [
            {"id": "c1", "base_url": "https://api.example.com", "path": "/orders/{order_id}", "method": "GET"}
        ]
        tx = _make_transaction(host="api.example.com", path=f"/orders/{uuid_str}", method="GET")
        res = correlate_static_dynamic_apis(static_cands, [tx])
        self.assertEqual(res.summary.correlated_count, 1)
        self.assertEqual(res.correlations[0].match_type, MatchType.TEMPLATE.value)

    # 10. unrelated path does not match
    def test_10_unrelated_path_does_not_match(self):
        matched, is_tmpl = match_paths("/users/login", "/orders/checkout")
        self.assertFalse(matched)

        static_cands = [
            {"id": "c1", "base_url": "https://api.example.com", "path": "/users/login", "method": "POST"}
        ]
        tx = _make_transaction(host="api.example.com", path="/orders/checkout", method="POST")
        res = correlate_static_dynamic_apis(static_cands, [tx])
        self.assertEqual(res.summary.correlated_count, 0)
        self.assertEqual(res.summary.static_only_count, 1)
        self.assertEqual(res.summary.dynamic_only_count, 1)

    # 11. unrelated host does not match
    def test_11_unrelated_host_does_not_match(self):
        static_cands = [
            {"id": "c1", "base_url": "https://api.example.com", "path": "/v1/data", "method": "GET"}
        ]
        tx = _make_transaction(host="admin.example.com", path="/v1/data", method="GET")
        res = correlate_static_dynamic_apis(static_cands, [tx])
        self.assertEqual(res.summary.correlated_count, 0)
        self.assertEqual(res.summary.static_only_count, 1)
        self.assertEqual(res.summary.dynamic_only_count, 1)

    # 12. method equality gives high/exact match
    def test_12_method_equality_gives_high_exact_match(self):
        static_cands = [
            {"id": "c1", "base_url": "https://api.example.com", "path": "/v1/profile", "method": "GET"}
        ]
        tx = _make_transaction(host="api.example.com", path="/v1/profile", method="GET")
        res = correlate_static_dynamic_apis(static_cands, [tx])
        self.assertEqual(res.correlations[0].match_type, MatchType.EXACT.value)
        self.assertEqual(res.correlations[0].confidence, MatchConfidence.HIGH.value)

    # 13. unknown static method can correlate
    def test_13_unknown_static_method_can_correlate(self):
        static_cands = [
            {"id": "c1", "base_url": "https://api.example.com", "path": "/v1/settings", "method": None}
        ]
        tx = _make_transaction(host="api.example.com", path="/v1/settings", method="PUT")
        res = correlate_static_dynamic_apis(static_cands, [tx])
        self.assertEqual(res.summary.correlated_count, 1)
        entry = res.correlations[0]
        self.assertEqual(entry.match_type, MatchType.HOST_PATH.value)
        self.assertEqual(entry.confidence, MatchConfidence.MEDIUM.value)
        self.assertEqual(entry.observed_methods, ["PUT"])

    # 14. method mismatch not treated exact
    def test_14_method_mismatch_not_treated_exact(self):
        static_cands = [
            {"id": "c1", "base_url": "https://api.example.com", "path": "/v1/items", "method": "GET"}
        ]
        tx = _make_transaction(host="api.example.com", path="/v1/items", method="POST")
        res = correlate_static_dynamic_apis(static_cands, [tx])
        self.assertEqual(res.summary.correlated_count, 1)
        entry = res.correlations[0]
        self.assertEqual(entry.match_type, MatchType.METHOD_MISMATCH.value)
        self.assertEqual(entry.confidence, MatchConfidence.LOW.value)

    # 15. repeated transactions aggregate
    def test_15_repeated_transactions_aggregate(self):
        static_cands = [
            {"id": "c1", "base_url": "https://api.example.com", "path": "/v1/ping", "method": "GET"}
        ]
        tx1 = _make_transaction(tx_id="tx_1", host="api.example.com", path="/v1/ping", method="GET", status_code=200, timestamp="2026-10-01T12:00:00Z")
        tx2 = _make_transaction(tx_id="tx_2", host="api.example.com", path="/v1/ping", method="GET", status_code=200, timestamp="2026-10-01T12:00:05Z")
        tx3 = _make_transaction(tx_id="tx_3", host="api.example.com", path="/v1/ping", method="GET", status_code=500, timestamp="2026-10-01T12:00:10Z")

        res = correlate_static_dynamic_apis(static_cands, [tx1, tx2, tx3])
        self.assertEqual(len(res.correlations), 1)
        entry = res.correlations[0]
        self.assertEqual(entry.observation_count, 3)
        self.assertEqual(sorted(entry.transaction_ids), ["tx_1", "tx_2", "tx_3"])
        self.assertEqual(sorted(entry.observed_status_codes), [200, 500])
        self.assertEqual(entry.first_observed_at, "2026-10-01T12:00:00Z")
        self.assertEqual(entry.last_observed_at, "2026-10-01T12:00:10Z")

    # 16. template candidate aggregates multiple concrete paths
    def test_16_template_candidate_aggregates_multiple_concrete_paths(self):
        static_cands = [
            {"id": "c_user", "base_url": "https://api.example.com", "path": "/users/{id}", "method": "GET"}
        ]
        tx1 = _make_transaction(tx_id="tx_u1", host="api.example.com", path="/users/1", method="GET")
        tx2 = _make_transaction(tx_id="tx_u2", host="api.example.com", path="/users/2", method="GET")

        res = correlate_static_dynamic_apis(static_cands, [tx1, tx2])
        self.assertEqual(res.summary.correlated_count, 1)
        self.assertEqual(len(res.correlations), 1)
        entry = res.correlations[0]
        self.assertEqual(entry.match_type, MatchType.TEMPLATE.value)
        self.assertEqual(entry.observation_count, 2)
        self.assertEqual(sorted(entry.transaction_ids), ["tx_u1", "tx_u2"])

    # 17. static-only candidate preserved
    def test_17_static_only_candidate_preserved(self):
        static_cands = [
            {"id": "c_unused", "base_url": "https://api.example.com", "path": "/v1/hidden", "method": "POST"}
        ]
        res = correlate_static_dynamic_apis(static_cands, [])
        self.assertEqual(res.summary.static_candidate_count, 1)
        self.assertEqual(res.summary.correlated_count, 0)
        self.assertEqual(res.summary.static_only_count, 1)
        entry = res.correlations[0]
        self.assertEqual(entry.match_type, MatchType.STATIC_ONLY.value)
        self.assertEqual(entry.observation_count, 0)
        self.assertEqual(entry.transaction_ids, [])

    # 18. dynamic-only endpoint preserved
    def test_18_dynamic_only_endpoint_preserved(self):
        tx = _make_transaction(tx_id="tx_dyn_1", host="analytics.example.com", path="/collect", method="POST")
        res = correlate_static_dynamic_apis([], [tx])
        self.assertEqual(res.summary.dynamic_endpoint_count, 1)
        self.assertEqual(res.summary.dynamic_only_count, 1)
        entry = res.correlations[0]
        self.assertEqual(entry.match_type, MatchType.DYNAMIC_ONLY.value)
        self.assertEqual(entry.host, "analytics.example.com")
        self.assertEqual(entry.path, "/collect")
        self.assertIsNone(entry.static_candidate_id)

    # 19. static-only wording does not claim endpoint absent
    def test_19_static_only_wording_does_not_claim_endpoint_absent(self):
        static_cands = [
            {"id": "c1", "base_url": "https://api.example.com", "path": "/admin/metrics", "method": "GET"}
        ]
        res = correlate_static_dynamic_apis(static_cands, [])
        note = res.correlations[0].notes or ""
        self.assertIn("not observed in available runtime traffic", note)
        self.assertNotIn("dead", note.lower())
        self.assertNotIn("unused", note.lower())
        self.assertNotIn("false positive", note.lower())

    # 20. partial HTTPS visibility preserved in summary
    def test_20_partial_https_visibility_preserved_in_summary(self):
        res = correlate_static_dynamic_apis(
            [],
            [],
            http_visibility="available",
            https_visibility="partial",
            https_visibility_reason="pinning_suspected",
        )
        self.assertEqual(res.summary.http_visibility, "available")
        self.assertEqual(res.summary.https_visibility, "partial")
        self.assertEqual(res.summary.https_visibility_reason, "pinning_suspected")
        self.assertIn("partial", res.summary.visibility_note)

    # 21. incomplete visibility does not claim endpoint unused
    def test_21_incomplete_visibility_does_not_claim_endpoint_unused(self):
        static_cands = [
            {"id": "c_https", "base_url": "https://api.example.com", "path": "/secure/data", "method": "GET"}
        ]
        res = correlate_static_dynamic_apis(
            static_cands,
            [],
            https_visibility="unavailable",
            https_visibility_reason="certificate_trust_unknown",
        )
        note = res.correlations[0].notes
        self.assertIn("not observed in available runtime traffic", note)
        self.assertNotIn("dead", note.lower())
        self.assertNotIn("unused", note.lower())

    # 22. transaction IDs canonical
    def test_22_transaction_ids_canonical(self):
        static_cands = [{"id": "c1", "base_url": "https://api.example.com", "path": "/api", "method": "GET"}]
        tx = _make_transaction(tx_id="tx_exact_guid_1234", host="api.example.com", path="/api", method="GET")
        res = correlate_static_dynamic_apis(static_cands, [tx])
        self.assertEqual(res.correlations[0].transaction_ids, ["tx_exact_guid_1234"])

    # 23. action IDs linked from traffic evidence
    def test_23_action_ids_linked_from_traffic_evidence(self):
        static_cands = [{"id": "c1", "base_url": "https://api.example.com", "path": "/login", "method": "POST"}]
        tx = _make_transaction(tx_id="tx_login", host="api.example.com", path="/login", method="POST")

        traffic_evidence = TrafficEvidenceArtifact(
            session_id=self.session_id,
            actions=[
                ActionTrafficEvidence(
                    action_id="act_btn_login",
                    occurrence=1,
                    source_node_id="node_welcome",
                    target_node_id="node_dashboard",
                    transaction_ids=["tx_login"],
                )
            ],
        )

        res = correlate_static_dynamic_apis(static_cands, [tx], traffic_evidence=traffic_evidence, session_id=self.session_id)
        entry = res.correlations[0]
        self.assertEqual(entry.observed_action_ids, ["act_btn_login"])

    # 24. source/target route context optional and compact
    def test_24_source_target_route_context_optional_and_compact(self):
        static_cands = [{"id": "c1", "base_url": "https://api.example.com", "path": "/cart", "method": "POST"}]
        tx = _make_transaction(tx_id="tx_cart", host="api.example.com", path="/cart", method="POST")

        traffic_evidence = TrafficEvidenceArtifact(
            session_id=self.session_id,
            actions=[
                ActionTrafficEvidence(
                    action_id="act_add_cart",
                    source_node_id="node_product",
                    target_node_id="node_cart",
                    transaction_ids=["tx_cart"],
                )
            ],
        )

        res = correlate_static_dynamic_apis(static_cands, [tx], traffic_evidence=traffic_evidence, session_id=self.session_id)
        entry = res.correlations[0]
        self.assertEqual(len(entry.route_context), 1)
        self.assertEqual(entry.route_context[0]["source_node_id"], "node_product")
        self.assertEqual(entry.route_context[0]["target_node_id"], "node_cart")

    # 25. query values not persisted
    def test_25_query_values_not_persisted(self):
        static_cands = [{"id": "c1", "base_url": "https://api.example.com", "path": "/items", "method": "GET"}]
        tx = _make_transaction(
            host="api.example.com",
            path="/items",
            method="GET",
            query={"category": "electronics", "sort": "price_asc"},
        )
        res = correlate_static_dynamic_apis(static_cands, [tx])
        entry_dict = res.correlations[0].to_dict()
        self.assertIn("observed_query_keys", entry_dict)
        self.assertEqual(entry_dict["observed_query_keys"], ["category", "sort"])
        json_str = json.dumps(entry_dict)
        self.assertNotIn("electronics", json_str)
        self.assertNotIn("price_asc", json_str)

    # 26. sensitive query values absent
    def test_26_sensitive_query_values_absent(self):
        static_cands = [{"id": "c1", "base_url": "https://api.example.com", "path": "/auth", "method": "GET"}]
        tx = _make_transaction(
            host="api.example.com",
            path="/auth",
            method="GET",
            query={"token": "secret_jwt_token_9999", "api_key": "super_secret_key"},
        )
        res = correlate_static_dynamic_apis(static_cands, [tx])
        json_str = json.dumps(res.to_dict())
        self.assertNotIn("secret_jwt_token_9999", json_str)
        self.assertNotIn("super_secret_key", json_str)
        self.assertEqual(res.correlations[0].observed_query_keys, ["api_key", "token"])

    # 27. no full request bodies
    def test_27_no_full_request_bodies(self):
        tx = _make_transaction(host="api.example.com", path="/data", method="POST")
        tx.request.body = {"username": "admin", "raw_payload": "X" * 1000}
        res = correlate_static_dynamic_apis([], [tx])
        json_str = json.dumps(res.to_dict())
        self.assertNotIn("raw_payload", json_str)
        self.assertNotIn("body", res.correlations[0].to_dict())

    # 28. no full response bodies
    def test_28_no_full_response_bodies(self):
        tx = _make_transaction(host="api.example.com", path="/data", method="GET")
        tx.response.body = {"database_dump": "Y" * 1000}
        res = correlate_static_dynamic_apis([], [tx])
        json_str = json.dumps(res.to_dict())
        self.assertNotIn("database_dump", json_str)

    # 29. deterministic correlation ID
    def test_29_deterministic_correlation_id(self):
        id1 = generate_deterministic_correlation_id("cand_1", "api.example.com", "/v1/users", "exact", "GET")
        id2 = generate_deterministic_correlation_id("cand_1", "api.example.com", "/v1/users", "exact", "GET")
        self.assertEqual(id1, id2)
        self.assertTrue(id1.startswith("corr_"))

    # 30. atomic artifact persistence
    def test_30_atomic_artifact_persistence(self):
        res = ApiCorrelationResult(
            session_id=self.session_id,
            summary=ApiCorrelationSummary(static_candidate_count=1),
            correlations=[
                ApiCorrelationEntry(
                    correlation_id="corr_1",
                    match_type=MatchType.EXACT.value,
                    confidence=MatchConfidence.HIGH.value,
                    host="api.example.com",
                    path="/v1/test",
                )
            ],
        )
        target = self.base_dir / "dynamic" / "api_correlation.json"
        saved = res.save_atomic(target)
        self.assertTrue(Path(saved).is_file())
        with open(target, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["schema_version"], "1.0")
        self.assertEqual(data["session_id"], self.session_id)
        self.assertEqual(len(data["correlations"]), 1)

    # 31. corrupt artifact handling explicit if load supported
    def test_31_corrupt_artifact_handling_explicit(self):
        target = self.base_dir / "api_correlation_corrupt.json"
        target.write_text("{ corrupt json data ::: ")
        with self.assertRaises(ValueError) as ctx:
            ApiCorrelationResult.load(target)
        self.assertIn("Corrupt JSON", str(ctx.exception))

        target_bad_schema = self.base_dir / "bad_schema.json"
        target_bad_schema.write_text(json.dumps(["not a dict"]))
        with self.assertRaises(ValueError):
            ApiCorrelationResult.load(target_bad_schema)

    # 32. no static report mutation
    def test_32_no_static_report_mutation(self):
        report_file = self.base_dir / "static_analysis_report.json"
        original_data = {
            "report_type": "static_analysis",
            "api_candidates": [
                {"id": "cand_1", "base_url": "https://api.example.com", "path": "/login", "method": "POST"}
            ],
        }
        report_file.write_text(json.dumps(original_data, indent=2))
        orig_content = report_file.read_text()

        tx = _make_transaction(host="api.example.com", path="/login", method="POST")
        correlate_static_dynamic_apis(original_data["api_candidates"], [tx])

        # Verify static report file was not altered
        self.assertEqual(report_file.read_text(), orig_content)

    # 33. no traffic transaction mutation
    def test_33_no_traffic_transaction_mutation(self):
        tx = _make_transaction(tx_id="tx_immutable", host="api.example.com", path="/data", method="GET")
        orig_dict = tx.to_dict()

        static_cands = [{"id": "c1", "base_url": "https://api.example.com", "path": "/data", "method": "GET"}]
        correlate_static_dynamic_apis(static_cands, [tx])

        self.assertEqual(tx.to_dict(), orig_dict)

    # 34. no active request execution
    def test_34_no_active_request_execution(self):
        with patch("urllib.request.urlopen") as mock_urlopen, \
             patch("http.client.HTTPConnection") as mock_http:
            static_cands = [{"id": "c1", "base_url": "https://api.example.com", "path": "/data", "method": "GET"}]
            tx = _make_transaction(host="api.example.com", path="/data", method="GET")
            correlate_static_dynamic_apis(static_cands, [tx])
            mock_urlopen.assert_not_called()
            mock_http.assert_not_called()

    # 35. no vulnerability finding generated
    def test_35_no_vulnerability_finding_generated(self):
        static_cands = [{"id": "c1", "base_url": "https://api.example.com", "path": "/mismatch", "method": "GET"}]
        tx = _make_transaction(host="api.example.com", path="/mismatch", method="POST")
        res = correlate_static_dynamic_apis(static_cands, [tx])
        res_dict = res.to_dict()
        self.assertNotIn("vulnerabilities", res_dict)
        self.assertNotIn("findings", res_dict)
        self.assertNotIn("severity", res_dict)

    # 36. dynamic completion requires a validated canonical report
    def test_36_dynamic_analysis_completed_with_canonical_report(self):
        from src.demo_orchestrator import _wire_dynamic_exploration
        from src.scan_state import create_initial_scan_state, load_scan_state, save_scan_state

        dyn_dir = self.base_dir / "dynamic"
        dyn_dir.mkdir(parents=True, exist_ok=True)
        (dyn_dir / "preflight_result.json").write_text(json.dumps({
            "status": "PASS",
            "device": {"connected": True, "serial": "emulator-5554"},
            "application": {"process_running": True, "package_name": "com.test"},
            "runtime": {"launch_success": True},
        }))
        (dyn_dir / "session.json").write_text(json.dumps({
            "session_id": self.session_id,
            "status": "ACTIVE",
        }))
        (self.base_dir / "static_analysis_report.json").write_text(json.dumps({
            "report_type": "static_analysis",
            "api_candidates": [{"id": "c1", "base_url": "https://api.example.com", "path": "/status", "method": "GET"}],
        }))

        init_st = create_initial_scan_state(scan_id=self.base_dir.name, target_url="http://test.com/app.apk")
        save_scan_state(self.base_dir, init_st)

        from src.dynamic.ui.models import ScreenObservation
        obs = ScreenObservation(
            screen_identity="screen_1",
            foreground_package="com.test",
            foreground_activity="MainActivity",
            target_package="com.test",
            is_target_package=True,
            action_candidates=[],
        )

        with patch("src.dynamic.ui.observer.observe_screen", return_value=obs), \
             patch("src.dynamic.runtime.observer.AndroidRuntimeObserver.observe"):
            _wire_dynamic_exploration(self.base_dir, package_name="com.test")

        final_st = load_scan_state(self.base_dir)
        stage_status = final_st.get("stages", {}).get("dynamic_analysis", {}).get("status")
        self.assertEqual(stage_status, "completed")
        self.assertTrue((self.base_dir / "dynamic_analysis_report.json").is_file())

        from src.dynamic.report import load_dynamic_analysis_report
        load_dynamic_analysis_report(self.base_dir)

    # 37. no dynamic_analysis_report.json created

    def test_37_no_dynamic_analysis_report_json_created(self):
        from src.demo_orchestrator import _wire_api_correlation

        (self.base_dir / "static_analysis_report.json").write_text(json.dumps({
            "api_candidates": [{"base_url": "https://api.example.com", "path": "/data", "method": "GET"}]
        }))
        _wire_api_correlation(root_path=self.base_dir, session_id=self.session_id)

        dyn_report = self.base_dir / "dynamic_analysis_report.json"
        dyn_sub_report = self.base_dir / "dynamic" / "dynamic_analysis_report.json"
        self.assertFalse(dyn_report.exists())
        self.assertFalse(dyn_sub_report.exists())
        self.assertTrue((self.base_dir / "dynamic" / "api_correlation.json").is_file())

    # 38. host absolute paths absent
    def test_38_host_absolute_paths_absent(self):
        static_cands = [
            {
                "id": "c_leak",
                "base_url": "https://api.example.com",
                "path": "/leak",
                "method": "GET",
                "source_file": "/Users/suleymansardogan/Desktop/project/smali/Main.smali",
                "evidence": {
                    "debug_path": "/Users/suleymansardogan/.gemini/logs/run.log"
                },
            }
        ]
        res = correlate_static_dynamic_apis(static_cands, [])
        json_str = json.dumps(res.to_dict())
        self.assertNotIn("/Users/suleymansardogan", json_str)
        self.assertIn("<host_path>", json_str)

    # 39. empty static candidates handled
    def test_39_empty_static_candidates_handled(self):
        tx = _make_transaction(host="api.example.com", path="/data", method="GET")
        res = correlate_static_dynamic_apis([], [tx])
        self.assertEqual(res.summary.static_candidate_count, 0)
        self.assertEqual(res.summary.correlated_count, 0)
        self.assertEqual(res.summary.dynamic_only_count, 1)

    # 40. empty dynamic transactions handled
    def test_40_empty_dynamic_transactions_handled(self):
        static_cands = [{"id": "c1", "base_url": "https://api.example.com", "path": "/data", "method": "GET"}]
        res = correlate_static_dynamic_apis(static_cands, [])
        self.assertEqual(res.summary.static_candidate_count, 1)
        self.assertEqual(res.summary.correlated_count, 0)
        self.assertEqual(res.summary.static_only_count, 1)
        self.assertEqual(res.summary.dynamic_endpoint_count, 0)

    # 41. zero traffic + unavailable HTTPS handled honestly
    def test_41_zero_traffic_unavailable_https_handled_honestly(self):
        static_cands = [{"id": "c1", "base_url": "https://api.example.com", "path": "/secure", "method": "GET"}]
        res = correlate_static_dynamic_apis(
            static_cands,
            [],
            https_visibility="unavailable",
            https_visibility_reason="certificate_trust_unknown",
        )
        self.assertEqual(res.summary.correlated_count, 0)
        self.assertEqual(res.summary.static_only_count, 1)
        self.assertIn("HTTPS traffic visibility was unavailable", res.summary.visibility_note)
        self.assertIn("certificate_trust_unknown", res.summary.visibility_note)

    # 42. timeline summary event compact if implemented
    def test_42_timeline_summary_event_compact_if_implemented(self):
        from src.demo_orchestrator import _wire_api_correlation

        (self.base_dir / "static_analysis_report.json").write_text(json.dumps({
            "api_candidates": [{"id": "c1", "base_url": "https://api.example.com", "path": "/api", "method": "GET"}]
        }))

        mock_timeline = MagicMock()
        _wire_api_correlation(
            root_path=self.base_dir,
            session_id=self.session_id,
            timeline_recorder=mock_timeline,
        )

        correlation_events = [call.args for call in mock_timeline._record_system_event.call_args_list
                              if call.args[0] == "API_CORRELATION_COMPLETED"]
        self.assertEqual(len(correlation_events), 1)
        event_name, event_data = correlation_events[0]
        self.assertEqual(event_name, "API_CORRELATION_COMPLETED")
        self.assertEqual(event_data["static_candidates"], 1)
        self.assertEqual(event_data["static_only"], 1)
        self.assertEqual(event_data["correlated_count"], 0)


class TestConservativePathIdentity(unittest.TestCase):
    UUID = "550e8400-e29b-41d4-a716-446655440000"
    OTHER_UUID = "550e8400-e29b-41d4-a716-446655440001"

    def correlate(self, static_path, dynamic_paths, static_method="GET", dynamic_method="GET"):
        return correlate_static_dynamic_apis(
            [{"base_url": "https://api.example.com", "path": static_path, "method": static_method}],
            [_make_transaction(tx_id=f"tx_{i}", path=path, method=dynamic_method)
             for i, path in enumerate(dynamic_paths)],
        )

    def test_literal_numeric_identical_is_exact_high(self):
        self.assertEqual(match_paths("/users/123", "/users/123"), (True, False))
        entry = self.correlate("/users/123", ["/users/123"]).correlations[0]
        self.assertEqual((entry.match_type, entry.confidence), ("exact", "high"))

    def test_literal_numeric_different_never_templates(self):
        self.assertEqual(match_paths("/users/123", "/users/456"), (False, False))

    def test_literal_uuid_identical_is_exact_high(self):
        path = f"/orders/{self.UUID}"
        self.assertEqual(match_paths(path, path), (True, False))
        entry = self.correlate(path, [path]).correlations[0]
        self.assertEqual((entry.match_type, entry.confidence), ("exact", "high"))

    def test_literal_uuid_different_never_templates(self):
        self.assertEqual(match_paths(f"/orders/{self.UUID}", f"/orders/{self.OTHER_UUID}"), (False, False))

    def test_explicit_templates_match_concrete_segments_medium(self):
        for template in ("{id}", ":userId", "<account_id>"):
            for value in ("123", self.UUID, "alice"):
                with self.subTest(template=template, value=value):
                    self.assertEqual(match_paths(f"/users/{template}", f"/users/{value}"), (True, True))
                    entry = self.correlate(f"/users/{template}", [f"/users/{value}"]).correlations[0]
                    self.assertEqual((entry.match_type, entry.confidence), ("template", "medium"))

    def test_template_cannot_consume_multiple_or_empty_segments(self):
        for path in ("/users/1/profile", "/users/", "/users"):
            with self.subTest(path=path):
                self.assertEqual(match_paths("/users/{id}", path), (False, False))

    def test_literal_static_and_different_runtime_remain_unmatched(self):
        for literal, runtime in (("1", "2"), (self.UUID, self.OTHER_UUID)):
            with self.subTest(literal=literal):
                res = self.correlate(f"/users/{literal}", [f"/users/{runtime}"])
                self.assertEqual(res.summary.correlated_count, 0)
                self.assertEqual((res.summary.static_only_count, res.summary.dynamic_only_count), (1, 1))
                self.assertEqual({e.match_type for e in res.correlations}, {"static_only", "dynamic_only"})

    def test_literal_matches_only_identical_runtime(self):
        res = self.correlate("/users/1", ["/users/1", "/users/2"])
        exact = next(e for e in res.correlations if e.match_type == "exact")
        self.assertEqual(exact.transaction_ids, ["tx_0"])
        dynamic_only = next(e for e in res.correlations if e.match_type == "dynamic_only")
        self.assertEqual(dynamic_only.path, "/users/2")

    def test_explicit_template_aggregates_runtime_paths(self):
        res = self.correlate("/users/{id}", ["/users/1", "/users/2"])
        self.assertEqual(len(res.correlations), 1)
        entry = res.correlations[0]
        self.assertEqual(entry.transaction_ids, ["tx_0", "tx_1"])
        self.assertEqual((entry.match_type, entry.confidence), ("template", "medium"))

    def test_dynamic_template_cannot_parameterize_static_literal(self):
        for static in ("/users/123", f"/users/{self.UUID}"):
            self.assertEqual(match_paths(static, "/users/{id}"), (False, False))
        self.assertEqual(match_paths("/users/{id}", "/users/:other"), (False, False))

    def test_method_mismatch_requires_valid_path_identity(self):
        for static, dynamic in (("/users/1", "/users/1"), ("/users/{id}", "/users/2")):
            entry = self.correlate(static, [dynamic], dynamic_method="POST").correlations[0]
            self.assertEqual((entry.match_type, entry.confidence), ("method_mismatch", "low"))
        res = self.correlate("/users/1", ["/users/2"], dynamic_method="POST")
        self.assertEqual({e.match_type for e in res.correlations}, {"static_only", "dynamic_only"})

    def test_unknown_method_requires_valid_path_identity(self):
        entry = self.correlate("/users/1", ["/users/1"], static_method=None).correlations[0]
        self.assertEqual((entry.match_type, entry.confidence), ("host_path", "medium"))
        res = self.correlate("/users/1", ["/users/2"], static_method=None)
        self.assertEqual(res.summary.correlated_count, 0)

    def test_candidate_id_provenance_matches_canonical_schema(self):
        from src.report_generator import sanitize_api_candidates_for_canonical_report
        for field in ("id", "candidate_id", "endpoint_id", None):
            with self.subTest(field=field):
                candidate = {"base_url": "https://api.example.com", "path": "/users/1", "method": "GET"}
                if field:
                    candidate[field] = "source-id"
                canonical = sanitize_api_candidates_for_canonical_report([candidate])
                original = json.dumps(canonical, sort_keys=True)
                for transactions in ([], [_make_transaction(path="/users/1")]):
                    res = correlate_static_dynamic_apis(canonical, transactions)
                    entry = res.correlations[0]
                    # C7 assigns the canonical report its own deterministic candidate_id.
                    # Correlation must reuse the ID actually carried by that report.
                    expected_field = "id" if field == "id" else "candidate_id"
                    self.assertEqual(entry.static_candidate_id, canonical[0][expected_field])
                    self.assertEqual(entry.provenance["static_candidate_id_origin"], "source_report")
                    self.assertEqual(entry.provenance["static_candidate_id_source_field"], expected_field)
                    again = correlate_static_dynamic_apis(canonical, transactions)
                    self.assertEqual(entry.correlation_id, again.correlations[0].correlation_id)
                self.assertEqual(json.dumps(canonical, sort_keys=True), original)


if __name__ == "__main__":
    unittest.main()
