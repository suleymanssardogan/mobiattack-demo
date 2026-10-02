"""Audit probes: unsupported call sites must never become guessed API candidates."""
import pytest
from src.api_candidate_extractor import extract_api_candidates
from src.network_indicator_extractor import extract_network_indicators

@pytest.mark.parametrize('owner,signature', [
 ('Lokhttp3/Request$Builder;', 'url(Ljava/lang/String;)Lokhttp3/Request$Builder;'),
 ('Lcom/android/volley/RequestQueue;', 'add(Lcom/android/volley/Request;)Lcom/android/volley/Request;'),
 ('Lio/ktor/client/HttpClient;', 'close()V'),
 ('Ljava/net/HttpURLConnection;', 'connect()V'),
 ('Landroid/webkit/WebView;', 'loadUrl(Ljava/lang/String;)V'),
 ('Ljava/net/Socket;', 'connect(Ljava/net/SocketAddress;)V'),
 ('Ltraining/CustomNetwork;', 'send(Ljava/lang/String;)V'),
])
def test_unsupported_framework_is_not_guessed(tmp_path, owner, signature):
    folder=tmp_path/'smali';folder.mkdir()
    if '()' in signature:
        extra_parameter, arguments = '', 'p0'
    elif name := ('Ljava/net/SocketAddress;' if owner == 'Ljava/net/Socket;' else 'Lcom/android/volley/Request;' if owner == 'Lcom/android/volley/RequestQueue;' else ''):
        extra_parameter, arguments = name, 'p0, p1'
    else:
        extra_parameter, arguments = '', 'p0, v0'
    (folder/'Probe.smali').write_text(f'''.class public Ltraining/Probe;
.super Ljava/lang/Object;
.method public static probe({owner}{extra_parameter})V
.locals 2
const-string v0, "https://api.training.invalid/profile"
invoke-virtual {{{arguments}}}, {owner}->{signature}
return-void
.end method
''')
    assert extract_api_candidates(tmp_path)['api_candidates'] == []
    assert extract_network_indicators(tmp_path)['network_urls']


def test_jni_and_native_strings_are_not_api_evidence(tmp_path):
    (tmp_path/'Native.smali').write_text('''.class public Ltraining/Native;
.super Ljava/lang/Object;
.method public native send()V
.end method
''')
    folder=tmp_path/'lib/arm64-v8a';folder.mkdir(parents=True)
    (folder/'libtraining.so').write_bytes(b'\x7fELF https://api.training.invalid/profile')
    assert extract_api_candidates(tmp_path)['api_candidates']==[]
    assert extract_network_indicators(tmp_path)['network_urls']==[]
