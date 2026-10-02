"""Network-free regressions for D1 traffic integrity and persistence boundaries."""
import io
import json
import socket
from email.message import Message
from unittest.mock import Mock

import pytest

from src.dynamic.traffic import native_backend
from src.dynamic.traffic.models import HttpRequestModel, HttpResponseModel, TrafficTransaction, TrafficException
from src.dynamic.traffic.normalizer import normalize_http_transaction, process_body_content
from src.dynamic.traffic.storage import TrafficStorage


@pytest.fixture
def proxy_handler(monkeypatch):
    # Exercise the production proxy handler without starting sockets or contacting APIs.
    monkeypatch.setattr(native_backend, 'is_port_in_use', lambda *a, **k: False)
    holder = {}
    def server(address, handler):
        holder['handler'] = handler
        return Mock(serve_forever=lambda: None)
    monkeypatch.setattr(native_backend, '_ThreadingHTTPServer', server)
    backend = native_backend.NativeProxyCaptureBackend()
    backend.start()
    handler = object.__new__(holder['handler'])
    handler.headers = Message()
    handler.headers['Host'] = 'localhost'
    handler.path = 'http://localhost:9123/orders?token=DUMMY_SECRET'
    handler.rfile = io.BytesIO(b'')
    handler.wfile = io.BytesIO()
    handler.send_response = Mock()
    handler.send_header = Mock()
    handler.end_headers = Mock()
    yield backend, handler
    backend.stop()


@pytest.mark.parametrize('error', [socket.gaierror('dummy DNS error'), ConnectionRefusedError(),
                                   TimeoutError(), RuntimeError('dummy failure')])
def test_upstream_failure_is_not_an_observed_success(proxy_handler, monkeypatch, error):
    backend, handler = proxy_handler
    conn = Mock()
    conn.request.side_effect = error
    monkeypatch.setattr(native_backend.http.client, 'HTTPConnection', Mock(return_value=conn))
    handler.do_GET()
    handler.send_response.assert_called_once_with(502)
    tx, = backend.captured_transactions
    assert tx.response is None
    assert tx.correlation['response_observation']['state'] == 'unavailable'
    assert tx.correlation['response_observation']['internal_proxy_response_excluded'] is True
    assert tx.request.query['token'] == '[REDACTED]'
    assert tx.request.path == '/orders'


@pytest.mark.parametrize('status', [200, 201, 401, 500])
def test_localhost_real_upstream_status_is_preserved(proxy_handler, monkeypatch, status):
    backend, handler = proxy_handler
    conn = Mock()
    response = Mock(status=status)
    response.read.return_value = b'{"result":"observed","token":"DUMMY_SECRET"}'
    response.getheaders.return_value = [('Content-Type', 'application/json')]
    conn.getresponse.return_value = response
    connect = Mock(return_value=conn)
    monkeypatch.setattr(native_backend.http.client, 'HTTPConnection', connect)
    handler.do_GET()
    connect.assert_called_once_with('localhost', 9123, timeout=3.0)
    tx, = backend.captured_transactions
    assert tx.response.status_code == status
    assert tx.response.body == {'result': 'observed', 'token': '[REDACTED]'}
    assert 'response_observation' not in tx.correlation


def test_unsupported_https_cannot_be_forwarded_as_plain_http(proxy_handler, monkeypatch):
    backend, handler = proxy_handler
    handler.path = 'https://localhost/orders'
    connect = Mock()
    monkeypatch.setattr(native_backend.http.client, 'HTTPConnection', connect)
    handler.do_GET()
    connect.assert_not_called()
    tx, = backend.captured_transactions
    assert tx.response is None
    assert tx.correlation['response_observation']['reason'] == 'unsupported_scheme'


@pytest.mark.parametrize('key', ['token','access_token','auth','authorization','api_key','key',
                                'password','passwd','secret','session','cookie','jwt','JWT','sessionId'])
def test_query_keys_preserved_sensitive_values_redacted(key):
    tx = normalize_http_transaction({'url': f'http://example.invalid/orders?{key}=DUMMY_SECRET&q=hello',
                                     'path':f'/orders?{key}=DUMMY_SECRET&q=hello'}, None, 'capture')
    assert tx.request.path == '/orders'
    assert tx.request.query[key] == '[REDACTED]'
    assert tx.request.query['q'] == 'hello'
    assert 'DUMMY_SECRET' not in json.dumps(tx.to_dict())


@pytest.mark.parametrize('ct,body', [
    ('application/json', '{"auth":{"session":"DUMMY_SECRET"},"items":[{"jwt":"DUMMY_SECRET","count":2}],"password":"DUMMY_SECRET"}'),
    ('application/x-www-form-urlencoded', 'token=DUMMY_SECRET&password=DUMMY_SECRET&q=hello'),
])
def test_structured_body_preserves_shape_without_sensitive_values(ct, body):
    tx = normalize_http_transaction({'url':'http://example.invalid/orders',
        'headers':{'Content-Type':ct},'body':body},
        {'status_code':201,'headers':{'Content-Type':ct},'body':body}, 'capture')
    serialized = json.dumps(tx.to_dict())
    assert 'DUMMY_SECRET' not in serialized
    assert tx.request.headers['content-type'] == ct
    if 'json' in ct:
        assert tx.request.body['auth'] == {'session':'[REDACTED]'}
        assert tx.request.body['items'] == [{'jwt':'[REDACTED]', 'count':2}]
    else:
        assert tx.request.body['q'] == 'hello'
    assert tx.response.status_code == 201


@pytest.mark.parametrize('ct,body', [('text/plain','password=DUMMY_SECRET'),
                                    (None,'Bearer DUMMY_SECRET'),
                                    ('application/json','{"token":"DUMMY_SECRET"'),
                                    ('text/html','<input value="DUMMY_SECRET">')])
def test_plaintext_or_malformed_body_never_persists_raw_content(ct, body):
    content, meta = process_body_content(body, ct)
    assert content == '[REDACTED]'
    assert meta['size'] == len(body.encode())
    assert meta['redacted'] is True


@pytest.mark.parametrize('ct', ['image/png','application/octet-stream','application/protobuf',None])
def test_binary_metadata_only(ct):
    content, meta = process_body_content(b'\x89\xffDUMMY_SECRET', ct)
    assert content is None
    assert meta['binary'] is True
    assert meta['size'] == 14


def test_sensitive_headers_and_url_header_queries_are_sanitized():
    tx = normalize_http_transaction({'url':'http://example.invalid/orders', 'headers':{
        'Authorization':'DUMMY_SECRET','X-Session':'DUMMY_SECRET',
        'Referer':'http://example.invalid/?token=DUMMY_SECRET&q=hello','Content-Type':'application/json'}},
        {'status_code':302,'headers':{'Location':'http://example.invalid/?jwt=DUMMY_SECRET',
                                   'Set-Cookie':'DUMMY_SECRET'}},'capture')
    assert 'DUMMY_SECRET' not in json.dumps(tx.to_dict())
    assert tx.request.headers['content-type'] == 'application/json'
    assert 'q=hello' in tx.request.headers['referer']


@pytest.mark.parametrize('flag',['synthetic','internal'])
def test_synthetic_request_rejected_and_internal_response_excluded(flag):
    with pytest.raises(TrafficException):
        normalize_http_transaction({'url':'http://example.invalid/',flag:True},None,'capture')
    tx = normalize_http_transaction({'url':'http://example.invalid/'},
                                    {'status_code':200,flag:True},'capture')
    assert tx.response is None
    assert tx.correlation['response_observation']['state'] == 'unavailable'


def test_persistence_sanitizes_direct_models_and_preserves_metadata(tmp_path):
    storage = TrafficStorage(str(tmp_path))
    tx = TrafficTransaction(request=HttpRequestModel(method='POST',host='example.invalid',
        path='/orders?token=DUMMY_SECRET',query={'jwt':'DUMMY_SECRET','q':'hello'},
        headers={'Authorization':'DUMMY_SECRET','Content-Type':'application/json'},
        body={'password':'DUMMY_SECRET','count':2}),
        response=HttpResponseModel(status_code=201,body='DUMMY_SECRET',headers={'Content-Type':'text/plain'}))
    storage.append_transaction('session',tx)
    path=tmp_path/'traffic.json'
    storage.save_traffic_json(path,'session',[tx,tx.to_dict()])
    assert 'DUMMY_SECRET' not in path.read_text()
    records=storage.load_transactions('session')
    assert 'DUMMY_SECRET' not in json.dumps(records)
    assert records[0]['request']['path']=='/orders'
    assert records[0]['request']['body']['count']==2
    assert records[0]['response']['status_code']==201


def test_persistence_cannot_bypass_internal_response_exclusion(tmp_path):
    storage=TrafficStorage(str(tmp_path))
    tx=TrafficTransaction().to_dict()
    tx['response']={'status_code':200,'internal':True,'body':'DUMMY_SECRET'}
    path=tmp_path/'traffic.json'
    storage.save_traffic_json(path,'session',[tx])
    stored=json.loads(path.read_text())['transactions'][0]
    assert stored['response'] is None
    assert 'DUMMY_SECRET' not in path.read_text()
    tx['request']['synthetic']=True
    with pytest.raises(TrafficException):
        storage.save_traffic_json(path,'session',[tx])
    assert json.loads(path.read_text())['transactions'][0]['response'] is None


def test_origin_form_local_request_is_forwarded_without_mock_success(proxy_handler, monkeypatch):
    backend, handler = proxy_handler
    handler.path = '/orders'
    handler.headers.replace_header('Host', 'localhost:9123')
    conn = Mock()
    response = Mock(status=204)
    response.read.return_value = b''
    response.getheaders.return_value = []
    conn.getresponse.return_value = response
    connect = Mock(return_value=conn)
    monkeypatch.setattr(native_backend.http.client, 'HTTPConnection', connect)
    handler.do_GET()
    connect.assert_called_once_with('localhost', 9123, timeout=3.0)
    assert backend.captured_transactions[0].response.status_code == 204


def test_failure_persistence_contains_request_but_no_internal_status(proxy_handler, monkeypatch, tmp_path):
    backend, handler = proxy_handler
    monkeypatch.setattr(native_backend.http.client, 'HTTPConnection', Mock(side_effect=ConnectionRefusedError()))
    handler.do_GET()
    storage = TrafficStorage(str(tmp_path))
    tx, = backend.captured_transactions
    storage.append_transaction('session', tx)
    storage.save_traffic_json(tmp_path / 'traffic.json', 'session', [tx])
    saved = json.loads((tmp_path / 'traffic.json').read_text())['transactions'][0]
    assert saved['request']['method'] == 'GET'
    assert saved['response'] is None
    assert saved['correlation']['response_observation']['reason'] == 'upstream_failure'
    assert 'DUMMY_SECRET' not in (tmp_path / 'traffic.json').read_text()
