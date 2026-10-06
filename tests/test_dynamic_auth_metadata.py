import json
import pytest
from src.dynamic.traffic.normalizer import normalize_http_transaction, sanitize_transaction_data, sanitize_headers, sanitize_body_payload
from src.dynamic.traffic.auth_metadata import observe_auth, safe_auth_metadata
from src.dynamic.traffic.storage import TrafficStorage
from src.dynamic.context.endpoint_context_builder import build_endpoint_contexts
from src.dynamic.correlation.api_correlator import correlate_static_dynamic_apis

SECRET='DISPOSABLE_FIXTURE_SECRET'

def transaction(headers=None, session='session_fixture'):
    return normalize_http_transaction({'url':'http://controlled.invalid/profile','headers':headers if headers is not None else {'Authorization':'Bearer '+SECRET,'Cookie':'sid='+SECRET},'body':'{"opaque":"'+SECRET+'","count":2}','timestamp':'2026-10-05T00:00:00Z'}, {'status_code':200,'headers':{'Set-Cookie':'sid='+SECRET+'; HttpOnly; Secure; SameSite=Lax; Path=/'}},'capture',session_id=session)

@pytest.mark.parametrize('key',['Authorization','X-Custom-Credential','X-Weird','Cookie','Set-Cookie'])
def test_arbitrary_header_values_never_persist(key):
    assert SECRET not in json.dumps(sanitize_headers({key:SECRET}))

@pytest.mark.parametrize('body',[{'opaque':SECRET},{'sid':SECRET},{'note':'Bearer '+SECRET},{'list':[SECRET]},{'nested':{'id':SECRET}}])
def test_all_structured_text_values_redacted(body):
    assert SECRET not in json.dumps(sanitize_body_payload(body))

@pytest.mark.parametrize('headers,state', [({},'absent'),(None,'unknown'),({'Authorization':'Bearer '+SECRET},'present'),({'Cookie':'sid='+SECRET},'present')])
def test_request_state(headers,state):
    assert observe_auth(headers,'session_fixture')['state']==state


def test_safe_token_subtype_cookie_attributes_and_reference():
    tx=transaction();data=tx.to_dict()
    assert SECRET not in json.dumps(data)
    assert tx.request.auth_metadata['token_type']=='bearer'
    assert tx.request.auth_metadata['state']=='present'
    cookie=tx.response.auth_metadata['cookies'][0]
    assert cookie['name']=='sid' and cookie['httponly'] and cookie['secure'] and cookie['samesite']=='lax'
    assert cookie['path_present'] and 'value' not in cookie
    assert tx.request.auth_metadata['authenticated_state']=='unknown'
    assert tx.request.auth_metadata['cookies'][0]['credential_ref']==cookie['credential_ref']


def test_scoped_refs_stable_only_in_same_session():
    one=transaction();two=transaction();other=transaction(session='other_session')
    assert one.request.auth_metadata['credential_refs']==two.request.auth_metadata['credential_refs']
    assert one.request.auth_metadata['credential_refs']!=other.request.auth_metadata['credential_refs']
    assert not transaction(session=None).request.auth_metadata['credential_refs']


def test_storage_idempotent_redaction(tmp_path):
    tx=transaction();storage=TrafficStorage(str(tmp_path))
    storage.append_transaction('session_fixture',tx)
    records=storage.load_transactions('session_fixture')
    assert SECRET not in json.dumps(records)
    assert records[0]['request']['auth_metadata']['token_type']=='bearer'
    assert sanitize_transaction_data(records[0])==records[0]


def test_metadata_injection_and_cross_session_refs_excluded():
    meta=transaction().request.auth_metadata
    meta['raw_token']=SECRET;meta['authenticated_state']='authenticated'
    safe=safe_auth_metadata(meta,'different_session')
    assert SECRET not in json.dumps(safe) and not safe['credential_refs']
    assert safe['authenticated_state']=='unknown'


def test_endpoint_linkage_and_no_authenticated_claim():
    tx=transaction();corr=correlate_static_dynamic_apis([], [tx],session_id='session_fixture')
    endpoint=build_endpoint_contexts(corr,[tx]).endpoints[0]
    assert endpoint.auth['bearer_token_present'] is True
    assert endpoint.auth['request_auth_states']==['present']
    assert endpoint.auth['authenticated_state']=='unknown'
    assert endpoint.request['auth_observations'][0]['transaction_id']==tx.transaction_id
    assert endpoint.response['cookie_observations'][0]['transaction_id']==tx.transaction_id
    assert SECRET not in json.dumps(endpoint.to_dict())


def test_trafficless_auth_unknown():
    from src.dynamic.context.endpoint_context_builder import _auth
    result=_auth([])
    assert result['authorization_header_present'] is None and result['cookie_present'] is None
    assert result['request_auth_states']==['unknown']


def test_query_and_plaintext_never_persist():
    tx=normalize_http_transaction({'url':'http://controlled.invalid/profile?odd='+SECRET,'headers':{'Content-Type':'text/plain'},'body':'opaque '+SECRET},None,'capture')
    assert SECRET not in json.dumps(tx.to_dict())
    assert tx.request.query['odd']=='[REDACTED]'


def test_query_or_json_credential_presence_is_not_authentication():
    tx=normalize_http_transaction({'url':'http://controlled.invalid/profile?access_token='+SECRET,'headers':{},'body':{'opaque':SECRET}},None,'capture',session_id='fixture')
    assert tx.request.auth_metadata['state']=='present'
    assert tx.request.auth_metadata['authenticated_state']=='unknown'
    assert tx.request.auth_metadata['credential_refs']
    assert SECRET not in json.dumps(tx.to_dict())


def test_multiple_set_cookie_attributes_without_values():
    meta=observe_auth({'Set-Cookie':['sid='+SECRET+'; HttpOnly','theme='+SECRET+'; Secure']},'fixture',response=True)
    assert [c['name'] for c in meta['cookies']]==['sid','theme']
    assert SECRET not in json.dumps(meta)


def test_legacy_redacted_values_keep_unknown_subtype():
    from src.dynamic.context.endpoint_context_builder import _auth
    auth=_auth([{'headers':{'authorization':'[REDACTED]','cookie':'[REDACTED]'}}])
    assert auth['bearer_token_present'] is None and auth['session_cookie_present'] is None


def test_numeric_opaque_credentials_are_not_persisted():
    assert sanitize_body_payload({'unusual_code':123456,'otp':123456,'count':2})=={'unusual_code':'[REDACTED]','otp':'[REDACTED]','count':2}


def test_body_named_token_is_present_before_redaction():
    tx=normalize_http_transaction({'url':'http://controlled.invalid/profile','headers':{'Content-Type':'application/json'},'body':'{"custom":{"access_token":"'+SECRET+'"}}'},None,'capture',session_id='fixture')
    assert tx.request.auth_metadata['state']=='present' and tx.request.auth_metadata['credential_refs']
    assert SECRET not in json.dumps(tx.to_dict())


def test_free_text_flow_notes_and_lists_withheld():
    from src.dynamic.session.flow_recorder import sanitize_metadata
    assert SECRET not in json.dumps(sanitize_metadata({'note':SECRET,'items':[SECRET],'debug':'Bearer '+SECRET}))
