from pathlib import Path
import shutil

import pytest

from src.api_candidate_extractor import extract_api_candidates
from src.retrofit_candidate_extractor import extract_retrofit


def service(root, name="Orders", method="GET", path="orders/{id}", body=None):
    text = body if body is not None else f'''.annotation runtime Lretrofit2/http/{method};
    value = "{path}"
.end annotation'''
    (root / (name + ".smali")).write_text(f'''.class public interface abstract Lapp/{name};
.super Ljava/lang/Object;
.method public abstract endpoint()Ljava/lang/Object;
{text}
.end method
''')


def factory(root, name="Orders", base="https://api.example.com/v1/", extra=""):
    (root / (name + "Factory.smali")).write_text(f'''.class public Lapp/{name}Factory;
.super Ljava/lang/Object;
.method public create()V
new-instance v0, Lretrofit2/Retrofit$Builder;
invoke-direct {{v0}}, Lretrofit2/Retrofit$Builder;-><init>()V
const-string v1, "{base}"
{extra}
invoke-virtual {{v0, v1}}, Lretrofit2/Retrofit$Builder;->baseUrl(Ljava/lang/String;)Lretrofit2/Retrofit$Builder;
move-result-object v0
invoke-virtual {{v0}}, Lretrofit2/Retrofit$Builder;->build()Lretrofit2/Retrofit;
move-result-object v0
const-class v2, Lapp/{name};
invoke-virtual {{v0, v2}}, Lretrofit2/Retrofit;->create(Ljava/lang/Class;)Ljava/lang/Object;
return-void
.end method
''')


@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
def test_supported_methods_structural_binding_and_provenance(tmp_path, method):
    service(tmp_path, method=method)
    factory(tmp_path)
    candidates = extract_api_candidates(tmp_path)["api_candidates"]
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate["method"] == method
    assert candidate["framework"] == "Retrofit"
    assert candidate["path"] == "/v1/orders/{id}"
    assert candidate["provenance"][0]["extractor_identity"]["path"] == "orders/{id}"
    assert candidate["full_url"] == "https://api.example.com/v1/orders/{id}"
    assert candidate["source_file"] == "Orders.smali"
    assert candidate["request_line"] == 4
    assert candidate["evidence"]["source_method"] == "endpoint()Ljava/lang/Object;"
    assert candidate["evidence"]["base_url_source_file"] == "OrdersFactory.smali"
    assert candidate["evidence"]["base_url_line"] == 6
    assert candidate["evidence"]["service_create_line"] > candidate["evidence"]["base_url_call_line"]
    assert candidates == extract_api_candidates(tmp_path)["api_candidates"]


def test_url_join_leading_slash_and_query_privacy(tmp_path):
    service(tmp_path, path="/users/{id}?token=TOP_SECRET&q=PRIVATE")
    factory(tmp_path)
    result = extract_retrofit(tmp_path)
    candidate = result["api_candidates"][0]
    assert candidate["full_url"] == "https://api.example.com/users/{id}"
    assert candidate["evidence"]["query_values_removed"]
    assert "TOP_SECRET" not in str(result) and "PRIVATE" not in str(result)


@pytest.mark.parametrize("body", [
    '.annotation runtime Lretrofit2/http/GET;\nvalue = ""\n.end annotation',
    '.annotation runtime Lretrofit2/http/GET;\n.end annotation',
    '.annotation runtime Lretrofit2/http/GET;\nvalue = resourceId\n.end annotation',
    '.annotation runtime Lretrofit2/http/GET;\nvalue = "orders"',
    '.annotation runtime Lretrofit2/http/GET;\nvalue = "orders"\nvalue = "users"\n.end annotation',
    '.annotation runtime Lretrofit2/http/HTTP;\nvalue = "orders"\n.end annotation',
    '.annotation runtime Lretrofit2/http/Query;\nvalue = "orders"\n.end annotation',
    '.annotation runtime Lretrofit2/http/GET;\nvalue = "orders"\n.end annotation\n.annotation runtime Lretrofit2/http/POST;\nvalue = "orders"\n.end annotation',
])
def test_invalid_or_unsupported_declarations_not_promoted(tmp_path, body):
    service(tmp_path, body=body)
    factory(tmp_path)
    assert extract_retrofit(tmp_path)["api_candidates"] == []


def test_annotation_definition_and_class_level_metadata_ignored(tmp_path):
    service(tmp_path)
    p = tmp_path / "Orders.smali"
    p.write_text(p.read_text().replace(".class public interface abstract", ".class public interface abstract annotation"))
    factory(tmp_path)
    assert extract_api_candidates(tmp_path)["api_candidates"] == []


def test_unbound_paths_unrelated_urls_and_service_isolation(tmp_path):
    service(tmp_path, name="Unbound")
    service(tmp_path, name="First")
    service(tmp_path, name="Second", path="users")
    factory(tmp_path, name="First", base="https://first.example.com/")
    factory(tmp_path, name="Second", base="https://second.example.com/")
    (tmp_path / "URL.smali").write_text('.field public static final API_URL:Ljava/lang/String; = "https://unrelated.example.com/"')
    result = extract_retrofit(tmp_path)
    assert result["unbound_declaration_count"] == 1
    assert {c["full_url"] for c in result["api_candidates"]} == {"https://first.example.com/orders/{id}", "https://second.example.com/users"}


@pytest.mark.parametrize("extra", [
    "const/4 v1, 0x0",
    "move-object v1, v3",
    ":branch_label",
    "invoke-static {v0}, Lapp/Unknown;->mutate(Ljava/lang/Object;)V",
])
def test_unknown_flow_or_overwrite_does_not_reuse_stale_binding(tmp_path, extra):
    service(tmp_path)
    factory(tmp_path, extra=extra)
    assert extract_retrofit(tmp_path)["api_candidates"] == []


@pytest.mark.parametrize("base", [
    "https://username:SECRET@example.com/", "https://example.com/?token=SECRET",
    "https://example.com", "file:///tmp/", "https://example.com:99999/",
])
def test_unsafe_or_invalid_base_rejected(tmp_path, base):
    service(tmp_path)
    factory(tmp_path, base=base)
    result = extract_retrofit(tmp_path)
    assert result["api_candidates"] == [] and "SECRET" not in str(result)


def test_malformed_file_isolated_and_generic_url_fields_not_promoted(tmp_path):
    service(tmp_path)
    factory(tmp_path)
    (tmp_path / "Broken.smali").write_bytes(b"\xff")
    (tmp_path / "Unterminated.smali").write_text('''.class public Lapp/Orders;
.method public invalid()V
.annotation runtime Lretrofit2/http/GET;
value = "unexpected"
.end annotation
''')
    assert len(extract_api_candidates(tmp_path)["api_candidates"]) == 1


def test_real_wikipedia_declaration_remains_unbound(tmp_path):
    source = Path(__file__).parent / "fixtures/retrofit/SemanticSearchService.smali"
    shutil.copyfile(source, tmp_path / source.name)
    result = extract_retrofit(tmp_path)
    assert len(result["declarations"]) == 1
    assert result["declarations"][0]["method"] == "GET"
    assert result["declarations"][0]["path"] == "api/search"
    assert result["declarations"][0]["annotation_line"] == 43
    assert result["unbound_declaration_count"] == 1
    assert result["api_candidates"] == []


def test_canonical_static_only_context_does_not_claim_runtime_observation(tmp_path):
    from src.demo_orchestrator import _wire_api_correlation, _wire_endpoint_contexts
    from src.report_generator import build_static_analysis_report, save_static_analysis_report
    from src.dynamic.context.models import EndpointContextArtifact
    service(tmp_path)
    factory(tmp_path)
    candidates = extract_api_candidates(tmp_path)["api_candidates"]
    run = tmp_path / "scan"
    save_static_analysis_report(run, build_static_analysis_report("scan", {"static_analysis": {
        "app": {"package_name": "app", "launcher_activity": "app.Main"},
        "api_candidates": candidates}, "demo_status": "completed"}))
    _wire_api_correlation(run, "static_session")
    _wire_endpoint_contexts(run)
    artifact = EndpointContextArtifact.load(run / "dynamic/endpoint_contexts.json")
    assert len(artifact.endpoints) == 1
    context = artifact.endpoints[0].to_dict()
    assert context["static"]["match_type"] == "static_only"
    assert not context["dynamic"]["observed"]
    assert context["dynamic"]["note"] == "Not observed in available runtime traffic."
