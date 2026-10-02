from pathlib import Path
import json
import shutil
from unittest.mock import patch

import pytest

from src.retrofit_candidate_extractor import extract_retrofit
from src.retrofit_flow import optimized_bindings
from tests.test_retrofit_candidate_extractor import service, factory


def helper(root, body=None, name="make", descriptor="(Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;"):
    body = body or '''invoke-static {p0}, Lokhttp3/HttpUrl;->parse(Ljava/lang/String;)Lokhttp3/HttpUrl;
move-result-object v0
new-instance v1, Lretrofit2/Retrofit;
const/4 v2, 0x0
invoke-direct {v1, v2, v0, v2, v2}, Lretrofit2/Retrofit;-><init>(Lokhttp3/OkHttpClient;Lokhttp3/HttpUrl;Ljava/util/List;Ljava/util/List;)V
invoke-virtual {v1, p1}, Lretrofit2/Retrofit;->create(Ljava/lang/Class;)Ljava/lang/Object;
move-result-object v0
return-object v0'''
    (root / "Helper.smali").write_text(f'''.class public final Lapp/Helper;
.super Ljava/lang/Object;
.method public static {name}{descriptor}
{body}
.end method
''')


def caller(root, name="Caller", target="Lapp/Helper;->make(Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;",
           base="https://api.example.com/v1/", cls="Orders", extra=""):
    (root / (name + ".smali")).write_text(f'''.class public Lapp/{name};
.super Ljava/lang/Object;
.method public static run()V
const-string v0, "{base}"
const-class v1, Lapp/{cls};
{extra}
invoke-static {{v0, v1}}, {target}
move-result-object v2
return-void
.end method
''')


def test_exact_argument_class_parameter_constructor_and_callsite_isolation(tmp_path):
    service(tmp_path, name="First")
    service(tmp_path, name="Second", path="users")
    helper(tmp_path, name="make$default")
    target="Lapp/Helper;->make$default(Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;"
    caller(tmp_path, name="A", target=target, cls="First", base="https://first.example.com/")
    caller(tmp_path, name="B", target=target, cls="Second", base="https://second.example.com/")
    with patch("urllib.request.urlopen", side_effect=AssertionError("no network")):
        first=extract_retrofit(tmp_path)
        second=extract_retrofit(tmp_path)
    assert {c["full_url"] for c in first["api_candidates"]} == {
        "https://first.example.com/orders/{id}", "https://second.example.com/users"}
    assert first["api_candidates"] == second["api_candidates"]
    for c in first["api_candidates"]:
        trace=c["evidence"]["interprocedural_trace"]
        assert any(event["kind"]=="argument" and event["parameter_register"]=="p1" for event in trace)
        assert any("-><init>" in event.get("callee","") for event in trace)
        assert c["evidence"]["base_url_source_file"] in ("A.smali","B.smali")
        assert str(tmp_path) not in str(c)


def test_direct_wrapper_return_and_moves_reach_create_receiver(tmp_path):
    service(tmp_path)
    helper(tmp_path, body='''move-object v3, p0
invoke-static {v3}, Lokhttp3/HttpUrl;->get(Ljava/lang/String;)Lokhttp3/HttpUrl;
move-result-object v0
new-instance v1, Lretrofit2/Retrofit;
const/4 v2, 0x0
invoke-direct {v1, v2, v0, v2, v2}, Lretrofit2/Retrofit;-><init>(Lokhttp3/OkHttpClient;Lokhttp3/HttpUrl;Ljava/util/List;Ljava/util/List;)V
return-object v1''', descriptor="(Ljava/lang/String;)Lretrofit2/Retrofit;")
    caller(tmp_path, target="Lapp/Helper;->make(Ljava/lang/String;)Lretrofit2/Retrofit;")
    p=tmp_path/"Caller.smali"
    p.write_text(p.read_text().replace("invoke-static {v0, v1}", "invoke-static {v0}").replace("return-void", """move-object v3, v2
invoke-virtual {v3, v1}, Lretrofit2/Retrofit;->create(Ljava/lang/Class;)Ljava/lang/Object;
return-void"""))
    candidates=extract_retrofit(tmp_path)["api_candidates"]
    assert len(candidates)==1
    assert any(e["kind"]=="return" for e in candidates[0]["evidence"]["interprocedural_trace"])
    assert any(e["kind"]=="move" for e in candidates[0]["evidence"]["interprocedural_trace"])


def test_actual_optimized_httpurl_builder_signature_with_proven_literal(tmp_path):
    service(tmp_path)
    helper(tmp_path, body='''new-instance v0, Lokhttp3/HttpUrl$Builder;
const/4 v2, 0x0
invoke-direct {v0, v2}, Lokhttp3/HttpUrl$Builder;-><init>(B)V
invoke-virtual {v0, v2, p0}, Lokhttp3/HttpUrl$Builder;->parse$okhttp(Lokhttp3/HttpUrl;Ljava/lang/String;)V
invoke-virtual {v0}, Lokhttp3/HttpUrl$Builder;->build()Lokhttp3/HttpUrl;
move-result-object v0
new-instance v1, Lretrofit2/Retrofit;
invoke-direct {v1, v2, v0, v2, v2}, Lretrofit2/Retrofit;-><init>(Lokhttp3/OkHttpClient;Lokhttp3/HttpUrl;Ljava/util/List;Ljava/util/List;)V
invoke-virtual {v1, p1}, Lretrofit2/Retrofit;->create(Ljava/lang/Class;)Ljava/lang/Object;
return-void''')
    caller(tmp_path)
    assert len(extract_retrofit(tmp_path)["api_candidates"])==1


@pytest.mark.parametrize("extra,cls,base", [
    ("const/4 v0, 0x0","Orders","https://api.example.com/"),
    ("if-eqz v0, :end\n:end","Orders","https://api.example.com/"),
    ("","Unknown","https://api.example.com/"),
    ("","Orders","https://user:SECRET@example.com/"),
    ("","Orders","https://api.example.com/?token=SECRET"),
])
def test_incomplete_or_ambiguous_chain_is_not_canonical(tmp_path, extra, cls, base):
    service(tmp_path)
    helper(tmp_path)
    caller(tmp_path,extra=extra,cls=cls,base=base)
    result=extract_retrofit(tmp_path)
    assert result["api_candidates"]==[]
    assert "SECRET" not in str(result)
    assert result["declarations"]


def test_nonfinal_virtual_helper_is_ambiguous(tmp_path):
    service(tmp_path)
    helper(tmp_path)
    p=tmp_path/"Helper.smali"
    p.write_text(p.read_text().replace("public final Lapp/Helper", "public Lapp/Helper").replace("public static make", "public make").replace("p1}", "p2}").replace("{p0}", "{p1}"))
    caller(tmp_path)
    p=tmp_path/"Caller.smali"
    p.write_text(p.read_text().replace("invoke-static {v0, v1}", "invoke-virtual {v2, v0, v1}"))
    result=extract_retrofit(tmp_path)
    assert result["api_candidates"]==[]
    assert any(d["reason"]=="CALLSITE_AMBIGUOUS" for d in result["unresolved_flow"])


@pytest.mark.parametrize("cycle", [False,True])
def test_depth_limit_and_cycle_rejected(tmp_path,cycle):
    service(tmp_path)
    helper(tmp_path)
    signature="(Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;"
    for i in range(5):
        target=f"Lapp/W{0 if cycle and i==1 else i+1};->forward{signature}" if i<4 else f"Lapp/Helper;->make{signature}"
        (tmp_path/f"W{i}.smali").write_text(f'''.class public Lapp/W{i};
.method public static forward{signature}
invoke-static {{p0,p1}}, {target}
move-result-object v0
return-object v0
.end method''')
    caller(tmp_path,target=f"Lapp/W0;->forward{signature}")
    result=extract_retrofit(tmp_path)
    assert result["api_candidates"]==[]
    reasons={d["reason"] for d in result["unresolved_flow"]}
    assert ("INTERPROCEDURAL_CYCLE" if cycle else "INTERPROCEDURAL_DEPTH_LIMIT") in reasons
    assert result["flow_performance"]["max_traversal_depth"]<=3


def test_simple_v1_binding_unchanged_and_unknown_url_never_attaches(tmp_path):
    service(tmp_path)
    factory(tmp_path)
    result=extract_retrofit(tmp_path)
    assert len(result["api_candidates"])==1
    assert "interprocedural_trace" not in result["api_candidates"][0]["evidence"]
    (tmp_path/"Unrelated.smali").write_text('.class public Lapp/Unrelated;\n.method static x()V\nconst-string v0, "https://unrelated.example.com/"\nreturn-void\n.end method')
    assert extract_retrofit(tmp_path)["api_candidates"]==result["api_candidates"]


def test_wide_parameter_slots_and_malformed_helper_isolation(tmp_path):
    service(tmp_path)
    helper(tmp_path, descriptor="(Ljava/lang/String;JLjava/lang/Class;)Ljava/lang/Object;")
    p=tmp_path/"Helper.smali";p.write_text(p.read_text().replace("{v1, p1}","{v1, p3}"))
    caller(tmp_path)
    p=tmp_path/"Caller.smali"
    p.write_text(p.read_text().replace("{v0, v1}", "{v0,v3,v4,v1}").replace("(Ljava/lang/String;Ljava/lang/Class;)", "(Ljava/lang/String;JLjava/lang/Class;)"))
    (tmp_path/"Broken.smali").write_bytes(b"\xff")
    assert len(extract_retrofit(tmp_path)["api_candidates"])==1


def test_real_wikipedia_optimized_wrapper_remains_unresolved(tmp_path):
    fixture=Path(__file__).parent/"fixtures/retrofit/OptimizedServiceFactory.smali"
    shutil.copyfile(fixture,tmp_path/fixture.name)
    shutil.copyfile(fixture.parent/"SemanticSearchService.smali",tmp_path/"SemanticSearchService.smali")
    result=extract_retrofit(tmp_path)
    assert result["declarations"] and not result["api_candidates"]
    assert any(d["reason"]=="UNSUPPORTED_BRANCH_FLOW" for d in result["unresolved_flow"])
    assert result["flow_performance"]["methods_indexed"]>0


def test_literal_return_helper_and_optimized_static_only_context(tmp_path):
    from src.api_candidate_extractor import extract_api_candidates
    from src.demo_orchestrator import _wire_api_correlation, _wire_endpoint_contexts
    from src.report_generator import build_static_analysis_report, save_static_analysis_report
    from src.dynamic.context.models import EndpointContextArtifact
    service(tmp_path)
    helper(tmp_path)
    caller(tmp_path)
    (tmp_path / "Literal.smali").write_text('''.class public Lapp/Literal;
.method public static base()Ljava/lang/String;
const-string v0, "https://api.example.com/v1/"
return-object v0
.end method''')
    p = tmp_path / "Caller.smali"
    p.write_text(p.read_text().replace('const-string v0, "https://api.example.com/v1/"',
        'invoke-static {}, Lapp/Literal;->base()Ljava/lang/String;\nmove-result-object v0'))
    candidates = extract_api_candidates(tmp_path)["api_candidates"]
    assert len(candidates) == 1
    assert candidates[0]["evidence"]["base_url_source_file"] == "Literal.smali"
    run = tmp_path / "scan"
    save_static_analysis_report(run, build_static_analysis_report("scan", {"static_analysis": {
        "app": {"package_name": "app", "launcher_activity": "app.Main"},
        "api_candidates": candidates}, "demo_status": "completed"}))
    _wire_api_correlation(run, "static_session")
    _wire_endpoint_contexts(run)
    context = EndpointContextArtifact.load(run / "dynamic/endpoint_contexts.json").endpoints[0].to_dict()
    assert context["static"]["match_type"] == "static_only"
    assert not context["dynamic"]["observed"]
    assert context["dynamic"]["note"] == "Not observed in available runtime traffic."


def test_duplicate_method_descriptor_is_not_selected(tmp_path):
    service(tmp_path)
    helper(tmp_path)
    shutil.copyfile(tmp_path / "Helper.smali", tmp_path / "Duplicate.smali")
    caller(tmp_path)
    result = extract_retrofit(tmp_path)
    assert not result["api_candidates"]
    assert any(d["reason"] == "CALLSITE_AMBIGUOUS" for d in result["unresolved_flow"])


def test_builder_field_escape_through_local_alias_is_rejected(tmp_path):
    service(tmp_path)
    factory(tmp_path)
    p = tmp_path / "OrdersFactory.smali"
    # The legacy parser cannot bind this moved receiver. The optimized layer
    # must not keep its local alias after the object escapes into a field.
    assert p.exists()
    p.write_text(p.read_text().replace('invoke-virtual {v0}, Lretrofit2/Retrofit$Builder;->build()',
        'move-object v4, v0\niput-object v0, p0, Lapp/Factory;->builder:Lretrofit2/Retrofit$Builder;\ninvoke-virtual {v4}, Lretrofit2/Retrofit$Builder;->build()'))
    result = extract_retrofit(tmp_path)
    assert not result["api_candidates"]
    assert any(d["reason"] == "UNSUPPORTED_OBJECT_ESCAPE" for d in result["unresolved_flow"])
