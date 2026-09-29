"""Unit and integration tests for Call-Context-Aware Static API Candidate Extractor."""

from pathlib import Path
import tempfile
import unittest

from src.api_candidate_extractor import extract_api_candidates


class TestApiCandidateExtractorUnit(unittest.TestCase):
    """Synthetic unit tests for Fuel API candidate extraction."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_smali(self, rel_path: str, content: str) -> Path:
        target = self.root_path / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content.strip(), encoding="utf-8")
        return target

    def test_01_fuel_get_direct_flow(self):
        code = """
        .class public Lcom/test/ApiTest;
        .super Ljava/lang/Object;

        .method public testGet()V
            .locals 2
            const-string v0, "/users"
            invoke-static {v0}, Lcom/github/kittinunf/fuel/FuelKt;->get(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;
            return-void
        .end method
        """
        self._write_smali("ApiTest.smali", code)
        res = extract_api_candidates(self.root_path)
        self.assertEqual(len(res["api_candidates"]), 1)
        c = res["api_candidates"][0]
        self.assertEqual(c["method"], "GET")
        self.assertEqual(c["path"], "/users")
        self.assertEqual(c["framework"], "Fuel")
        self.assertEqual(c["status"], "static_api_candidate")
        self.assertEqual(c["evidence"]["path_register"], "v0")

    def test_02_fuel_post_direct_flow(self):
        code = """
        .class public Lcom/test/PostTest;
        .super Ljava/lang/Object;

        .method public testPost()V
            .locals 3
            const-string v1, "/login"
            invoke-static {v1}, Lcom/github/kittinunf/fuel/FuelKt;->post(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;
            return-void
        .end method
        """
        self._write_smali("PostTest.smali", code)
        res = extract_api_candidates(self.root_path)
        self.assertEqual(len(res["api_candidates"]), 1)
        c = res["api_candidates"][0]
        self.assertEqual(c["method"], "POST")
        self.assertEqual(c["path"], "/login")

    def test_03_fuel_put(self):
        code = """
        .class public Lcom/test/PutTest;
        .super Ljava/lang/Object;

        .method public testPut()V
            .locals 2
            const-string v0, "/profile"
            invoke-static {v0}, Lcom/github/kittinunf/fuel/FuelKt;->put(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;
            return-void
        .end method
        """
        self._write_smali("PutTest.smali", code)
        res = extract_api_candidates(self.root_path)
        self.assertEqual(res["api_candidates"][0]["method"], "PUT")

    def test_04_fuel_delete(self):
        code = """
        .class public Lcom/test/DeleteTest;
        .super Ljava/lang/Object;

        .method public testDelete()V
            .locals 2
            const-string v0, "/item/123"
            invoke-static {v0}, Lcom/github/kittinunf/fuel/FuelKt;->delete(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;
            return-void
        .end method
        """
        self._write_smali("DeleteTest.smali", code)
        res = extract_api_candidates(self.root_path)
        self.assertEqual(res["api_candidates"][0]["method"], "DELETE")

    def test_05_fuel_patch(self):
        code = """
        .class public Lcom/test/PatchTest;
        .super Ljava/lang/Object;

        .method public testPatch()V
            .locals 2
            const-string v0, "/status"
            invoke-static {v0}, Lcom/github/kittinunf/fuel/FuelKt;->patch(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;
            return-void
        .end method
        """
        self._write_smali("PatchTest.smali", code)
        res = extract_api_candidates(self.root_path)
        self.assertEqual(res["api_candidates"][0]["method"], "PATCH")

    def test_06_unrelated_string_register_not_associated(self):
        # v2 contains /users, v3 contains hello. Invoke calls v2. Candidate must be /users, NOT hello!
        code = """
        .class public Lcom/test/RegisterIsolation;
        .super Ljava/lang/Object;

        .method public testIsolation()V
            .locals 4
            const-string v2, "/users"
            const-string v3, "hello"
            invoke-static {v2}, Lcom/github/kittinunf/fuel/FuelKt;->get(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;
            return-void
        .end method
        """
        self._write_smali("RegisterIsolation.smali", code)
        res = extract_api_candidates(self.root_path)
        self.assertEqual(len(res["api_candidates"]), 1)
        self.assertEqual(res["api_candidates"][0]["path"], "/users")

    def test_07_register_overwrite_uses_latest_value(self):
        # v1 is assigned /old, then overwritten with /new. Call should see /new.
        code = """
        .class public Lcom/test/Overwrite;
        .super Ljava/lang/Object;

        .method public testOverwrite()V
            .locals 2
            const-string v1, "/old"
            const-string v1, "/new"
            invoke-static {v1}, Lcom/github/kittinunf/fuel/FuelKt;->post(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;
            return-void
        .end method
        """
        self._write_smali("Overwrite.smali", code)
        res = extract_api_candidates(self.root_path)
        self.assertEqual(len(res["api_candidates"]), 1)
        self.assertEqual(res["api_candidates"][0]["path"], "/new")

    def test_08_method_boundary_resets_register_state(self):
        # Method 1 defines v0 = /secret. Method 2 calls invoke without defining v0. Must NOT find candidate!
        code = """
        .class public Lcom/test/Boundary;
        .super Ljava/lang/Object;

        .method public methodA()V
            .locals 1
            const-string v0, "/secret"
            return-void
        .end method

        .method public methodB()V
            .locals 1
            invoke-static {v0}, Lcom/github/kittinunf/fuel/FuelKt;->get(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;
            return-void
        .end method
        """
        self._write_smali("Boundary.smali", code)
        res = extract_api_candidates(self.root_path)
        self.assertEqual(len(res["api_candidates"]), 0)

    def test_09_string_in_previous_method_must_not_leak(self):
        # Same boundary safety check across methods
        code = """
        .class public Lcom/test/Leak;
        .super Ljava/lang/Object;

        .method public first()V
            const-string v1, "http://127.0.0.1"
            invoke-virtual {v0, v1}, Lcom/github/kittinunf/fuel/core/FuelManager;->setBasePath(Ljava/lang/String;)V
            return-void
        .end method

        .method public second()V
            const-string v0, "/route"
            invoke-static {v0}, Lcom/github/kittinunf/fuel/FuelKt;->post(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;
            return-void
        .end method
        """
        self._write_smali("Leak.smali", code)
        res = extract_api_candidates(self.root_path)
        self.assertEqual(len(res["api_candidates"]), 1)
        # Base URL from first method must NOT leak into second method
        self.assertIsNone(res["api_candidates"][0]["base_url"])
        self.assertIsNone(res["api_candidates"][0]["full_url"])

    def test_10_fuel_set_base_path_direct_register_detection(self):
        code = """
        .class public Lcom/test/BaseUrl;
        .super Ljava/lang/Object;

        .method public setup()V
            .locals 3
            const-string v1, "https://api.example.com"
            invoke-virtual {v0, v1}, Lcom/github/kittinunf/fuel/core/FuelManager;->setBasePath(Ljava/lang/String;)V
            const-string v2, "/data"
            invoke-static {v2}, Lcom/github/kittinunf/fuel/FuelKt;->get(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;
            return-void
        .end method
        """
        self._write_smali("BaseUrl.smali", code)
        res = extract_api_candidates(self.root_path)
        c = res["api_candidates"][0]
        self.assertEqual(c["base_url"], "https://api.example.com")
        self.assertEqual(c["evidence"]["base_url_register"], "v1")

    def test_11_base_url_and_path_combination(self):
        code = """
        .class public Lcom/test/Combine;
        .super Ljava/lang/Object;

        .method public run()V
            .locals 3
            const-string v1, "http://127.0.0.1"
            invoke-virtual {v0, v1}, Lcom/github/kittinunf/fuel/core/FuelManager;->setBasePath(Ljava/lang/String;)V
            const-string v2, "/signup"
            invoke-static {v2}, Lcom/github/kittinunf/fuel/FuelKt;->post(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;
            return-void
        .end method
        """
        self._write_smali("Combine.smali", code)
        res = extract_api_candidates(self.root_path)
        self.assertEqual(res["api_candidates"][0]["full_url"], "http://127.0.0.1/signup")

    def test_12_url_joining_without_double_slash(self):
        code = """
        .class public Lcom/test/Slash;
        .super Ljava/lang/Object;

        .method public run()V
            .locals 3
            const-string v1, "https://api.test.com/"
            invoke-virtual {v0, v1}, Lcom/github/kittinunf/fuel/core/FuelManager;->setBasePath(Ljava/lang/String;)V
            const-string v2, "/v1/users"
            invoke-static {v2}, Lcom/github/kittinunf/fuel/FuelKt;->get(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;
            return-void
        .end method
        """
        self._write_smali("Slash.smali", code)
        res = extract_api_candidates(self.root_path)
        self.assertEqual(res["api_candidates"][0]["full_url"], "https://api.test.com/v1/users")

    def test_13_no_base_url_produces_candidate_with_full_url_null(self):
        code = """
        .class public Lcom/test/NoBase;
        .super Ljava/lang/Object;

        .method public run()V
            .locals 2
            const-string v0, "/ping"
            invoke-static {v0}, Lcom/github/kittinunf/fuel/FuelKt;->get(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;
            return-void
        .end method
        """
        self._write_smali("NoBase.smali", code)
        res = extract_api_candidates(self.root_path)
        c = res["api_candidates"][0]
        self.assertIsNone(c["base_url"])
        self.assertIsNone(c["full_url"])

    def test_14_multiple_base_paths_use_latest_local_context(self):
        code = """
        .class public Lcom/test/MultiBase;
        .super Ljava/lang/Object;

        .method public run()V
            .locals 3
            const-string v1, "https://api-a.com"
            invoke-virtual {v0, v1}, Lcom/github/kittinunf/fuel/core/FuelManager;->setBasePath(Ljava/lang/String;)V
            const-string v1, "https://api-b.com"
            invoke-virtual {v0, v1}, Lcom/github/kittinunf/fuel/core/FuelManager;->setBasePath(Ljava/lang/String;)V
            const-string v2, "/check"
            invoke-static {v2}, Lcom/github/kittinunf/fuel/FuelKt;->get(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;
            return-void
        .end method
        """
        self._write_smali("MultiBase.smali", code)
        res = extract_api_candidates(self.root_path)
        self.assertEqual(res["api_candidates"][0]["base_url"], "https://api-b.com")
        self.assertEqual(res["api_candidates"][0]["full_url"], "https://api-b.com/check")

    def test_15_unsupported_nearby_invoke_must_not_produce_candidate(self):
        code = """
        .class public Lcom/test/Nearby;
        .super Ljava/lang/Object;

        .method public run()V
            .locals 2
            const-string v0, "/path"
            invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;
            return-void
        .end method
        """
        self._write_smali("Nearby.smali", code)
        res = extract_api_candidates(self.root_path)
        self.assertEqual(len(res["api_candidates"]), 0)

    def test_16_non_fuel_method_call_ignored(self):
        code = """
        .class public Lcom/test/NonFuel;
        .super Ljava/lang/Object;

        .method public run()V
            .locals 2
            const-string v0, "/fake"
            invoke-static {v0}, Lcom/other/http/Client;->post(Ljava/lang/String;)V
            return-void
        .end method
        """
        self._write_smali("NonFuel.smali", code)
        res = extract_api_candidates(self.root_path)
        self.assertEqual(len(res["api_candidates"]), 0)

    def test_17_local_file_url_must_not_become_api_candidate(self):
        code = """
        .class public Lcom/test/WebViewFile;
        .super Ljava/lang/Object;

        .method public run()V
            .locals 2
            const-string v0, "file:///android_asset/unsafe_content.html"
            invoke-virtual {v1, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
            return-void
        .end method
        """
        self._write_smali("WebViewFile.smali", code)
        res = extract_api_candidates(self.root_path)
        self.assertEqual(len(res["api_candidates"]), 0)

    def test_18_filesystem_path_ignored_unless_passed_to_fuel(self):
        code = """
        .class public Lcom/test/RootCheck;
        .super Ljava/lang/Object;

        .method public run()V
            .locals 2
            const-string v0, "/sbin/su"
            new-instance v1, Ljava/io/File;
            invoke-direct {v1, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V
            return-void
        .end method
        """
        self._write_smali("RootCheck.smali", code)
        res = extract_api_candidates(self.root_path)
        self.assertEqual(len(res["api_candidates"]), 0)

    def test_19_deterministic_sorting(self):
        code = """
        .class public Lcom/test/SortTest;
        .super Ljava/lang/Object;

        .method public run()V
            .locals 3
            const-string v0, "/z_route"
            invoke-static {v0}, Lcom/github/kittinunf/fuel/FuelKt;->get(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;
            const-string v1, "/a_route"
            invoke-static {v1}, Lcom/github/kittinunf/fuel/FuelKt;->post(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;
            return-void
        .end method
        """
        self._write_smali("SortTest.smali", code)
        res = extract_api_candidates(self.root_path)
        self.assertEqual(len(res["api_candidates"]), 2)
        # Sorted by request_line
        self.assertEqual(res["api_candidates"][0]["path"], "/z_route")
        self.assertEqual(res["api_candidates"][1]["path"], "/a_route")

    def test_20_relative_source_paths(self):
        code = """
        .class public Lcom/test/RelPath;
        .super Ljava/lang/Object;

        .method public run()V
            .locals 2
            const-string v0, "/rel"
            invoke-static {v0}, Lcom/github/kittinunf/fuel/FuelKt;->get(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;
            return-void
        .end method
        """
        self._write_smali("sub/nested/RelPath.smali", code)
        res = extract_api_candidates(self.root_path)
        self.assertEqual(res["api_candidates"][0]["source_file"], "sub/nested/RelPath.smali")

    def test_21_one_based_evidence_lines(self):
        code = """
        .class public Lcom/test/LineNum;
        .super Ljava/lang/Object;

        .method public run()V
            .locals 2
            const-string v0, "/endpoint"
            invoke-static {v0}, Lcom/github/kittinunf/fuel/FuelKt;->get(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;
            return-void
        .end method
        """
        self._write_smali("LineNum.smali", code)
        res = extract_api_candidates(self.root_path)
        evidence = res["api_candidates"][0]["evidence"]
        self.assertGreater(evidence["path_line"], 0)
        self.assertGreater(evidence["request_call_line"], evidence["path_line"])

    def test_22_unsupported_move_object_invalidates_tracked_register(self):
        # const-string v2, "/signup" followed by move-object v2, v5.
        # v2 is overwritten with an unsupported instruction, so stale "/signup" must be invalidated!
        code = """
        .class public Lcom/test/Invalidate;
        .super Ljava/lang/Object;

        .method public run()V
            .locals 6
            const-string v2, "/signup"
            move-object v2, v5
            invoke-static {v2}, Lcom/github/kittinunf/fuel/FuelKt;->post(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;
            return-void
        .end method
        """
        self._write_smali("Invalidate.smali", code)
        res = extract_api_candidates(self.root_path)
        # Because v2 was invalidated, no candidate should be produced
        self.assertEqual(len(res["api_candidates"]), 0)


class TestRealOwaspApiCandidateIntegration(unittest.TestCase):
    """Integration test against actual OWASP smali directory."""

    def test_owasp_ground_truth(self):
        repo_root = Path(__file__).resolve().parent.parent if (Path(__file__).resolve().parent.parent / "MSTG-Android-Kotlin.apk").is_file() else Path(__file__).resolve().parent.parent.parent
        smali_dir = repo_root / "apk_lab" / "apktool_out" / "smali"
        self.assertTrue(smali_dir.is_dir(), f"smali directory not found at {smali_dir}")

        result = extract_api_candidates(smali_dir)
        candidates = result["api_candidates"]

        self.assertEqual(len(candidates), 1)
        c = candidates[0]

        # Verify exact ground truth
        self.assertEqual(c["framework"], "Fuel")
        self.assertEqual(c["method"], "POST")
        self.assertEqual(c["base_url"], "http://127.0.0.1")
        self.assertEqual(c["path"], "/signup")
        self.assertEqual(c["full_url"], "http://127.0.0.1/signup")
        self.assertEqual(c["status"], "static_api_candidate")
        self.assertEqual(
            c["source_file"],
            "sg/vantagepoint/mstgkotlin/RegisterActivity$onCreate$2.smali",
        )
        self.assertEqual(c["request_line"], 214)

        # Verify evidence block
        ev = c["evidence"]
        self.assertEqual(ev["path_value"], "/signup")
        self.assertEqual(ev["path_register"], "v0")
        self.assertEqual(ev["path_line"], 102)
        self.assertEqual(ev["request_call_line"], 214)
        self.assertEqual(ev["base_url_value"], "http://127.0.0.1")
        self.assertEqual(ev["base_url_register"], "v1")
        self.assertEqual(ev["base_url_line"], 97)
        self.assertEqual(ev["base_url_call_line"], 99)


if __name__ == "__main__":
    unittest.main()
