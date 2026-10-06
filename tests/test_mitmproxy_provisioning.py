"""Focused executable selection checks; no live proxy or network."""
from unittest.mock import patch

from src.dynamic.traffic.mitmproxy_backend import (
    MitmproxyCaptureBackend, find_mitmproxy_binary,
)
from src.dynamic.traffic.service import DynamicTrafficService


def test_explicit_isolated_executable_takes_priority(tmp_path):
    binary = tmp_path / 'mitmdump'
    binary.write_text('#!/bin/sh\nexit 0\n')
    binary.chmod(0o700)
    with patch('shutil.which', return_value='/other/mitmdump'):
        assert find_mitmproxy_binary(str(binary)) == str(binary)


def test_existing_environment_override_selects_local_backend(tmp_path, monkeypatch):
    binary = tmp_path / 'mitmdump'
    binary.write_text('#!/bin/sh\nexit 0\n')
    binary.chmod(0o700)
    monkeypatch.delenv('MITMPROXY_PATH', raising=False)
    monkeypatch.setenv('MITMDUMP_PATH', str(binary))
    backend = MitmproxyCaptureBackend(ca_directory=tmp_path / 'ca')
    service = DynamicTrafficService(backend=backend)
    assert backend.check_available()
    assert service.backend is backend  # no silent native fallback
    assert service.get_visibility_metadata()['https_reason'] != 'cleartext_http_only_backend'


def test_missing_binary_remains_unavailable_not_native(tmp_path):
    with patch('src.dynamic.traffic.mitmproxy_backend.find_mitmproxy_binary', return_value=None):
        backend = MitmproxyCaptureBackend(ca_directory=tmp_path / 'ca')
        service = DynamicTrafficService(backend=backend)
        assert not backend.check_available()
        assert service.backend is backend
        assert service.get_visibility_metadata()['https_reason'] == 'capture_backend_unavailable'
