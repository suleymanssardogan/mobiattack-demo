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
            invoke-virtual {v0, v2}, Lcom/github/kittinunf/fuel/core/FuelManager;->get(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;
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
            invoke-virtual {v0, v2}, Lcom/github/kittinunf/fuel/core/FuelManager;->post(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;
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
            invoke-virtual {v0, v2}, Lcom/github/kittinunf/fuel/core/FuelManager;->get(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;
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
            invoke-virtual {v0, v2}, Lcom/github/kittinunf/fuel/core/FuelManager;->get(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;
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


# Focused regressions for S1's URI and receiver-binding correctness gaps.
import pytest

_MANAGER = 'Lcom/github/kittinunf/fuel/core/FuelManager;'
_REQUEST = 'Lcom/github/kittinunf/fuel/core/Request;'


def _fuel_probe(tmp_path, instructions):
    (tmp_path / 'Probe.smali').write_text(
        '.class public LProbe;\n.super Ljava/lang/Object;\n'
        '.method public run()V\n.locals 8\n' + instructions +
        '\nreturn-void\n.end method\n', encoding='utf-8'
    )
    return extract_api_candidates(tmp_path)['api_candidates']


def _base(receiver, url):
    return (f'const-string v7, "{url}"\n'
            f'invoke-virtual {{{receiver}, v7}}, {_MANAGER}->setBasePath(Ljava/lang/String;)V\n')


def _request(receiver='v0', path='/signup'):
    return (f'const-string v6, "{path}"\n'
            f'invoke-virtual {{{receiver}, v6}}, {_MANAGER}->post(Ljava/lang/String;){_REQUEST}\n')


@pytest.mark.parametrize('path', [
    'file:///android_asset/test.html', 'content://contacts/1', 'data:text/plain,hello',
    'ftp://example.com/test', 'javascript:alert(1)', 'mailto:user@example.com',
    'FILE:///android_asset/test.html', '//other.example.com/path',
    'http:///missing-host', 'https://', 'https://example.com:bad/path',
    'https://example.com\\other/path', ' https://example.com/path', '',
])
def test_fuel_rejects_non_network_or_ambiguous_uri(tmp_path, path):
    # Escape the literal to preserve the exact Smali string boundary.
    escaped = path.replace('\\', '\\\\')
    assert _fuel_probe(tmp_path, _base('v0', 'https://api.example.com') +
                       _request(path=escaped)) == []


@pytest.mark.parametrize('url', ['http://127.0.0.1/signup', 'https://example.com/users',
                                 'HTTPS://example.com/users'])
def test_fuel_absolute_network_url_needs_no_base(tmp_path, url):
    candidate, = _fuel_probe(tmp_path, _request(path=url))
    assert candidate['full_url'] == url
    assert candidate['base_url'] is None
    assert candidate['evidence']['path_value'] == url


def test_fuel_two_managers_keep_their_own_base_provenance(tmp_path):
    candidates = _fuel_probe(tmp_path,
        _base('v0', 'https://first.example.com') +
        _base('v3', 'https://second.example.com') + _request('v0') + _request('v3'))
    assert [c['full_url'] for c in candidates] == [
        'https://first.example.com/signup', 'https://second.example.com/signup']
    assert candidates[0]['evidence']['base_url_value'] == 'https://first.example.com'
    assert candidates[0]['evidence']['base_url_call_line'] < candidates[1]['evidence']['base_url_call_line']


def test_fuel_unconfigured_receiver_preserves_only_independent_path(tmp_path):
    candidate, = _fuel_probe(tmp_path, _base('v3', 'https://second.example.com') + _request('v0'))
    assert candidate['base_url'] is None
    assert candidate['full_url'] is None
    assert candidate['method'] == 'POST'
    assert candidate['path'] == '/signup'
    assert candidate['source_file'] == 'Probe.smali'
    assert candidate['evidence']['path_line'] < candidate['request_line']
    assert candidate['evidence']['base_url_call_line'] is None


def test_fuel_static_call_does_not_borrow_arbitrary_manager_base(tmp_path):
    candidate, = _fuel_probe(tmp_path, _base('v0', 'https://first.example.com') +
        _base('v3', 'https://second.example.com') +
        'const-string v6, "/signup"\n'
        f'invoke-static {{v6}}, Lcom/github/kittinunf/fuel/FuelKt;->post(Ljava/lang/String;){_REQUEST}\n')
    assert candidate['base_url'] is None
    assert candidate['full_url'] is None


@pytest.mark.parametrize('overwrite', ['new-instance v0, LOther;', 'move-object v0, v3',
                                      'const-string v0, "other"'])
def test_fuel_receiver_overwrite_revokes_binding(tmp_path, overwrite):
    candidate, = _fuel_probe(tmp_path, _base('v0', 'https://first.example.com') +
                            overwrite + '\n' + _request())
    assert candidate['full_url'] is None


@pytest.mark.parametrize('url', ['file:///android_asset/', 'content://provider/',
                                 'data:text/plain,hello', 'https://',
                                 'https://example.com?redirect=1'])
def test_fuel_invalid_base_revokes_previous_valid_binding(tmp_path, url):
    candidate, = _fuel_probe(tmp_path, _base('v0', 'https://first.example.com') +
                            _base('v0', url) + _request())
    assert candidate['base_url'] is None
    assert candidate['full_url'] is None
    assert candidate['path'] == '/signup'


def test_fuel_unknown_base_setter_revokes_old_binding(tmp_path):
    candidate, = _fuel_probe(tmp_path, _base('v0', 'https://first.example.com') +
        f'invoke-virtual {{v0, p1}}, {_MANAGER}->setBasePath(Ljava/lang/String;)V\n' + _request())
    assert candidate['full_url'] is None


@pytest.mark.parametrize('boundary', [':join', 'if-eqz p1, :join\n:join', 'goto :join'])
def test_fuel_ambiguous_control_flow_does_not_bind(tmp_path, boundary):
    candidate, = _fuel_probe(tmp_path, _base('v0', 'https://first.example.com') +
                            boundary + '\n' + _request())
    assert candidate['full_url'] is None
    assert candidate['path'] == '/signup'


def test_fuel_explicit_singleton_context_survives_register_reuse(tmp_path):
    candidate, = _fuel_probe(tmp_path,
        'invoke-virtual {v1}, Lcom/github/kittinunf/fuel/core/FuelManager$Companion;->getInstance()'
        'Lcom/github/kittinunf/fuel/core/FuelManager;\nmove-result-object v0\n' +
        _base('v0', 'http://127.0.0.1') +
        'const-string v0, "/signup"\n'
        f'invoke-static {{v0}}, Lcom/github/kittinunf/fuel/FuelKt;->post(Ljava/lang/String;){_REQUEST}\n')
    assert candidate['full_url'] == 'http://127.0.0.1/signup'
    assert candidate['evidence']['base_url_value'] == 'http://127.0.0.1'


def test_fuel_random_url_string_without_request_is_not_a_candidate(tmp_path):
    assert _fuel_probe(tmp_path, 'const-string v0, "https://example.com/random"\n') == []


def test_fuel_unconditional_base_before_guard_still_binds_fallthrough(tmp_path):
    candidate, = _fuel_probe(tmp_path, _base('v0', 'https://first.example.com') +
        'if-eqz p1, :exit\n' + _request() + ':exit\n')
    assert candidate['full_url'] == 'https://first.example.com/signup'


def test_fuel_unsupported_alias_mutation_cannot_leave_stale_base(tmp_path):
    candidate, = _fuel_probe(tmp_path, _base('v0', 'https://first.example.com') +
        'move-object v3, v0\n' + _base('v3', 'https://second.example.com') + _request('v0'))
    assert candidate['base_url'] is None
    assert candidate['full_url'] is None
