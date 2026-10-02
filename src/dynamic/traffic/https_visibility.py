"""Evidence-based HTTPS capability and read-only emulator CA trust inspection."""
from dataclasses import dataclass
import hashlib
from pathlib import Path
import ssl
import subprocess

from src.dynamic.preflight.device_check import run_adb_cmd


def check_ca_trust(adb_bin: str, serial: str, certificate: Path) -> tuple[str, str]:
    """Compare the public CA certificate with accessible stores; never modify stores."""
    if not certificate.is_file():
        return 'unknown', 'proxy_ca_not_generated'
    try:
        pem = certificate.read_text()
        fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).digest()
        proc = subprocess.run(['openssl', 'x509', '-subject_hash_old', '-noout', '-in', str(certificate)],
                              capture_output=True, text=True, timeout=3)
        cert_hash = proc.stdout.strip()
        if proc.returncode or len(cert_hash) != 8 or any(c not in '0123456789abcdef' for c in cert_hash):
            return 'unknown', 'ca_fingerprint_check_unavailable'
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return 'unknown', 'ca_fingerprint_check_unavailable'
    unreadable = False
    for store in ['/apex/com.android.conscrypt/cacerts', '/system/etc/security/cacerts',
                  '/data/misc/user/0/cacerts-added']:
        code, names, _ = run_adb_cmd(adb_bin, ['shell', 'ls', store], serial=serial)
        if code:
            unreadable = True
            continue
        for name in names.split()[:2048]:
            if not name.startswith(cert_hash + '.') or not name[len(cert_hash)+1:].isdigit():
                continue
            code, contents, _ = run_adb_cmd(adb_bin, ['shell', 'cat', store + '/' + name], serial=serial)
            try:
                if not code and hashlib.sha256(ssl.PEM_cert_to_DER_cert(contents)).digest() == fingerprint:
                    scope = 'user' if 'cacerts-added' in store else 'system'
                    return 'trusted', scope + '_ca_present_app_trust_not_verified'
            except ValueError:
                unreadable = True
    return ('unknown', 'ca_store_not_readable') if unreadable else ('not_installed', 'ca_not_installed')


@dataclass
class HttpsVisibility:
    ca_trust: str = 'unknown'
    ca_reason: str = 'certificate_trust_unknown'
    verified_transactions: int = 0
    tls_failures: int = 0
    backend_failed: bool = False

    def metadata(self) -> tuple[str, str]:
        if self.backend_failed:
            return 'unavailable', 'capture_backend_failure'
        if self.verified_transactions:
            if self.tls_failures:
                return 'partial', 'tls_interception_failed_for_some_connections'
            if self.ca_trust != 'trusted':
                return 'partial', 'https_observed_ca_trust_or_target_app_scope_unverified'
            return 'available', 'https_transaction_verified_for_observed_clients'
        if self.tls_failures:
            return 'unavailable', 'tls_interception_failed_ca_or_app_trust_unverified'
        if self.ca_trust == 'not_installed':
            return 'unavailable', 'ca_not_installed'
        return 'unknown', 'no_https_transaction_available_to_verify'
