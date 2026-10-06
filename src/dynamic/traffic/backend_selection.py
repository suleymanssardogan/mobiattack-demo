"""Explicit capture mode; capability failures never change the chosen backend."""
import os
from .mitmproxy_backend import MitmproxyCaptureBackend
from .native_backend import NativeProxyCaptureBackend

TRAFFIC_MODES = ('https', 'native_http')
DEFAULT_TRAFFIC_MODE = 'https'


def validate_traffic_mode(mode):
    if mode not in TRAFFIC_MODES:
        raise ValueError('traffic_mode must be https or native_http')
    return mode


def select_capture_backend(mode=DEFAULT_TRAFFIC_MODE, *, executable_path=None, ca_directory=None):
    validate_traffic_mode(mode)
    if mode == 'native_http':
        return NativeProxyCaptureBackend()
    return MitmproxyCaptureBackend(executable_path=executable_path,
                                  ca_directory=ca_directory or os.getenv('MITMPROXY_CA_DIR'))
