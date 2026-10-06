"""mitmdump event bridge: emit sanitized evidence, never raw credentials or logs."""
from datetime import datetime, timezone
import json
import os
from src.dynamic.traffic.normalizer import normalize_http_transaction

PREFIX = 'MOBIATTACK_EVIDENCE '


def _timestamp(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat() if value else ''


def _emit(record):
    print(PREFIX + json.dumps(record, separators=(',', ':')), flush=True)


class CaptureAddon:
    def running(self):
        _emit({"event": "ready"})

    def _transaction(self, flow, response):
        req = flow.request
        raw_request = {'method': req.method, 'scheme': req.scheme, 'host': req.host,
                       'port': req.port, 'path': req.path, 'headers': dict(req.headers),
                       'body': req.raw_content, 'timestamp': _timestamp(req.timestamp_start)}
        raw_response = None
        if response is not None:
            raw_response = {'status_code': response.status_code, 'headers': dict(response.headers),
                            'body': response.raw_content, 'timestamp': _timestamp(response.timestamp_end)}
        if response is not None:
            raw_response['headers']['set-cookie'] = response.headers.get_all('set-cookie') if hasattr(response.headers, 'get_all') else raw_response['headers'].get('set-cookie', [])
            if not raw_response['headers']['set-cookie']: raw_response['headers'].pop('set-cookie',None)
        tx = normalize_http_transaction(raw_request, raw_response, 'mitmproxy', session_id=os.environ.get('MOBIATTACK_CAPTURE_SESSION') or None)
        if response is None:
            tx.correlation['response_observation'] = {'state': 'unavailable', 'reason': 'upstream_or_tls_failure'}
        _emit({'event': 'transaction', 'transaction': tx.to_dict()})

    def response(self, flow):
        # Proxy onboarding and addon-generated responses have no upstream connection.
        if flow.response is not None and flow.server_conn.timestamp_tcp_setup is not None:
            self._transaction(flow, flow.response)

    def error(self, flow):
        if flow.request is not None:
            self._transaction(flow, None)

    def tls_failed_client(self, data):
        _emit({'event': 'tls_failure', 'side': 'client'})

    def tls_failed_server(self, data):
        _emit({'event': 'tls_failure', 'side': 'upstream'})


addons = [CaptureAddon()]
