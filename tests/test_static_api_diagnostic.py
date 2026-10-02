from scripts.diagnose_static_api import classify, compare, inventory, safe_url


def test_classifies_noise_separately_from_explicit_context():
    assert classify("https://example.com/privacy", 'API_URL="https://example.com/privacy"', "smali") == ("non_api_url", False)
    assert classify("https://example.com/users", 'DEBUG_ENDPOINT="https://example.com/users"', "smali") == ("absolute_url", True)
    assert classify("https://example.com", 'URL="https://example.com"', "smali") == ("unknown_network_indicator", False)


def test_coverage_uses_source_and_candidate_semantics():
    args = dict(source_scanned=True, indicator_found=True, candidate_found=False, meaningful=True, kind="absolute_url")
    assert compare(**args) == "PATTERN_NOT_SUPPORTED"
    assert compare(**{**args, "source_scanned": False}) == "SOURCE_NOT_SCANNED"
    assert compare(**{**args, "kind": "endpoint_annotation"}) == "ANNOTATION_NOT_PARSED"
    assert compare(**{**args, "candidate_found": True}) == "RECOGNIZED_CANDIDATE"
    assert compare(**{**args, "meaningful": False}) == "NON_API_OR_UNCLASSIFIED"


def test_url_sanitization_drops_all_sensitive_components():
    value = safe_url("https://username:password@example.com/secret-token/person@example.com?token=secret#cookie")
    for sensitive in ("username", "password", "example.com", "secret", "person", "cookie", "token", "?"):
        assert sensitive not in value
    assert value.startswith("https://host_")
    assert safe_url("https://[invalid") == "<redacted_url>"


def test_real_field_pattern_diagnostic_preserves_provenance_not_secrets(tmp_path):
    root = tmp_path / "apktool_out"
    root.mkdir()
    (root / "Secrets.smali").write_text('.field public static final DEBUG_ENDPOINT:Ljava/lang/String; = "http://192.168.18.5:5000/debug/users?password=private"\n')
    result = inventory("app_test", tmp_path)
    signal = result["signals"][0]
    assert signal["source_ref"] == "apktool_out/Secrets.smali"
    assert signal["line_number"] == 1
    assert signal["source_scanned"]
    assert signal["reason"] == "PATTERN_NOT_SUPPORTED"
    assert signal["recognized_by_indicator_extractor"]
    assert result["candidate_count"] == 0
    assert "private" not in str(result)
    assert str(tmp_path) not in str(result)
    assert result == inventory("app_test", tmp_path)


def test_fuel_candidate_recognized_and_java_source_not_scanned(tmp_path):
    root=tmp_path/"apktool_out";root.mkdir()
    (root/"Api.smali").write_text('.method public run()V\nconst-string v0, "https://example.com/api/users"\ninvoke-static {v0}, Lcom/github/kittinunf/fuel/FuelKt;->get(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;\n.end method\n')
    java=tmp_path/"jadx_out/sources";java.mkdir(parents=True)
    (java/"Api.java").write_text('String API_URL = "https://example.com/api/users";')
    result=inventory("app_test",tmp_path)
    assert result["candidate_count"] == 1
    assert result["coverage"]["RECOGNIZED_CANDIDATE"] == 1
    assert result["coverage"]["SOURCE_NOT_SCANNED"] == 1


def test_inventory_byte_budget_excludes_large_files(tmp_path):
    root=tmp_path/"apktool_out";root.mkdir()
    (root/"big.txt").write_text("x"*100)
    result=inventory("app_test",tmp_path,max_file_bytes=10)
    assert result["skipped_files"]["size_budget"] == 1
    assert result["signals"] == []


def test_static_string_field_is_indicator_only_and_noise_stays_filtered(tmp_path):
    from src.network_indicator_extractor import extract_network_indicators
    from src.api_candidate_extractor import extract_api_candidates
    root=tmp_path/"apktool_out";root.mkdir()
    (root/"Secrets.smali").write_text('''\
.field public static final DEBUG_ENDPOINT:Ljava/lang/String; = "http://192.168.18.5:5000/debug/users"
.field public static final NAMESPACE:Ljava/lang/String; = "http://schemas.android.com/apk/res/android"
.field public static final LOCAL:Ljava/lang/String; = "file:///android_asset/index.html"
.field public static final NOT_STRING:I = "https://invalid.example/api"
.field public static final EXPRESSION:Ljava/lang/String; = "https://invalid.example/api" + other
''')
    indicators=extract_network_indicators(root)
    assert [item["value"] for item in indicators["network_urls"]] == ["http://192.168.18.5:5000/debug/users"]
    assert indicators["network_urls"][0]["source_file"]=="Secrets.smali"
    assert indicators["network_urls"][0]["line_number"]==1
    assert len(indicators["local_file_urls"])==1
    assert extract_api_candidates(root)["api_candidates"]==[]
