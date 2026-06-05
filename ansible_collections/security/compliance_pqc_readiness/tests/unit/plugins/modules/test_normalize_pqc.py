# GNU General Public License v3.0+

"""Unit tests for normalize_pqc module."""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import json
import os
import tempfile
import pytest
from unittest.mock import patch

from ansible.module_utils import basic
from ansible.module_utils.common.text.converters import to_bytes


def set_module_args(args):
    """Prepare module args for AnsibleModule instantiation."""
    args = json.dumps({'ANSIBLE_MODULE_ARGS': args})
    basic._ANSIBLE_ARGS = to_bytes(args)
    if hasattr(basic, '_ANSIBLE_PROFILE'):
        basic._ANSIBLE_PROFILE = 'json'


class AnsibleExitJson(Exception):
    pass


class AnsibleFailJson(Exception):
    pass


def exit_json(*args, **kwargs):
    if 'changed' not in kwargs:
        kwargs['changed'] = False
    raise AnsibleExitJson(kwargs)


def fail_json(*args, **kwargs):
    kwargs['failed'] = True
    raise AnsibleFailJson(kwargs)


@pytest.fixture(autouse=True)
def patch_module():
    with patch.object(basic.AnsibleModule, 'exit_json', exit_json):
        with patch.object(basic.AnsibleModule, 'fail_json', fail_json):
            yield


CRYPTO_REPORT_PQC_READY = {
    'host': 'pqc-ready-host',
    'collected_at': '2026-06-01T12:00:00Z',
    'openssl_version': 'OpenSSL 3.5.0 8 Apr 2025',
    'openssl_version_rc': 0,
    'openssl_tls1_3_groups': 'X25519MLKEM768:MLKEM768:X25519:P-256:P-384',
    'openssl_tls1_3_groups_rc': 0,
    'openssl_packages': {'openssl': [{'version': '3.5.0', 'release': '1.el9', 'arch': 'x86_64'}]},
    'crypto_policy': {
        'profile': 'DEFAULT:PQC',
        'fips_enabled': False,
        'fips_output': '',
        'local_overrides': ['/etc/crypto-policies/local.d/pqc.txt'],
    },
    'ssh_host_keys': [],
    'system_certificates': [],
    'tls_services': [],
    'nginx_present': False,
    'nginx_certificates': [],
    'sshd_crypto_lines': [],
    'sshd_crypto_lines_commented': [],
}

CRYPTO_REPORT_VULNERABLE = {
    'host': 'vulnerable-host',
    'collected_at': '2026-06-01T12:00:00Z',
    'openssl_version': 'OpenSSL 3.0.7 1 Nov 2022',
    'openssl_version_rc': 0,
    'openssl_tls1_3_groups': 'X25519:P-256:P-384',
    'openssl_tls1_3_groups_rc': 0,
    'openssl_packages': {'openssl': [{'version': '3.0.7', 'release': '1.el9', 'arch': 'x86_64'}]},
    'crypto_policy': {
        'profile': 'DEFAULT',
        'fips_enabled': False,
        'fips_output': 'FIPS mode is disabled.',
        'local_overrides': [],
    },
    'ssh_host_keys': [
        {'path': '/etc/ssh/ssh_host_rsa_key.pub', 'bits': 3072, 'fingerprint': 'SHA256:abc', 'algorithm': 'RSA', 'risk': 'quantum_vulnerable'},
        {'path': '/etc/ssh/ssh_host_ed25519_key.pub', 'bits': 256, 'fingerprint': 'SHA256:def', 'algorithm': 'ED25519', 'risk': 'quantum_vulnerable'},
    ],
    'system_certificates': [
        {'path': '/etc/pki/tls/certs/server.pem', 'subject': 'CN=vulnerable-host', 'issuer': 'CN=CA', 'expires': 'Dec 2027', 'signature_algorithm': 'sha256WithRSAEncryption', 'public_key_algorithm': 'rsaEncryption', 'public_key_size': 2048, 'risk': 'quantum_vulnerable'},
    ],
    'tls_services': [
        {'port': 443, 'protocol': 'TLSv1.3', 'cipher': 'TLS_AES_256_GCM_SHA384', 'key_exchange': 'X25519', 'key_exchange_risk': 'quantum_vulnerable', 'peer_signature': 'RSA-PSS', 'server_signature': 'RSA-PSS'},
    ],
    'nginx_present': False,
    'nginx_certificates': [],
    'sshd_crypto_lines': ['KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256'],
    'sshd_crypto_lines_commented': [],
}

CRYPTO_REPORT_EMPTY = {
    'host': 'empty-host',
    'collected_at': '2026-06-01T12:00:00Z',
    'openssl_version': '',
    'openssl_version_rc': -1,
    'openssl_tls1_3_groups': '',
    'openssl_tls1_3_groups_rc': -1,
    'openssl_packages': {},
    'crypto_policy': {},
    'ssh_host_keys': [],
    'system_certificates': [],
    'tls_services': [],
    'nginx_present': False,
    'nginx_certificates': [],
    'sshd_crypto_lines': [],
    'sshd_crypto_lines_commented': [],
}


def _run_module(crypto_report, **extra_args):
    """Run normalize_pqc with the given crypto_report and return the result."""
    import importlib
    module_path = os.path.join(
        os.path.dirname(__file__), '..', '..', '..', '..',
        'plugins', 'modules', 'normalize_pqc.py',
    )
    spec = importlib.util.spec_from_file_location('normalize_pqc', module_path)
    mod = importlib.util.module_from_spec(spec)

    args = {'crypto_report': crypto_report}
    args.update(extra_args)
    set_module_args(args)

    with pytest.raises(AnsibleExitJson) as exc_info:
        spec.loader.exec_module(mod)

    return exc_info.value.args[0]


class TestNormalizePQCReadyHost:
    """Tests for a PQC-ready host (OpenSSL 3.5, ML-KEM groups)."""

    def test_openssl_mlkem_pass(self):
        result = _run_module(CRYPTO_REPORT_PQC_READY)
        mlkem_findings = [f for f in result['findings'] if f['rule_id'] == 'pqc_openssl_mlkem_support']
        assert len(mlkem_findings) == 1
        assert mlkem_findings[0]['status'] == 'pass'

    def test_openssl_version_pass(self):
        result = _run_module(CRYPTO_REPORT_PQC_READY)
        version_findings = [f for f in result['findings'] if f['rule_id'] == 'pqc_openssl_version']
        assert len(version_findings) == 1
        assert version_findings[0]['status'] == 'pass'

    def test_crypto_policy_pass(self):
        result = _run_module(CRYPTO_REPORT_PQC_READY)
        policy_findings = [f for f in result['findings'] if f['rule_id'] == 'pqc_crypto_policy_profile']
        assert len(policy_findings) == 1
        assert policy_findings[0]['status'] == 'pass'

    def test_high_compliance_score(self):
        result = _run_module(CRYPTO_REPORT_PQC_READY)
        assert result['summary']['compliance_score'] == 100.0

    def test_host_field_set(self):
        result = _run_module(CRYPTO_REPORT_PQC_READY)
        for finding in result['findings']:
            assert finding['host'] == 'pqc-ready-host'


class TestNormalizePQCVulnerableHost:
    """Tests for a non-PQC-ready host (OpenSSL 3.0, classical algorithms)."""

    def test_openssl_mlkem_fail(self):
        result = _run_module(CRYPTO_REPORT_VULNERABLE)
        mlkem = [f for f in result['findings'] if f['rule_id'] == 'pqc_openssl_mlkem_support']
        assert mlkem[0]['status'] == 'fail'

    def test_openssl_version_fail(self):
        result = _run_module(CRYPTO_REPORT_VULNERABLE)
        version = [f for f in result['findings'] if f['rule_id'] == 'pqc_openssl_version']
        assert version[0]['status'] == 'fail'

    def test_ssh_keys_vulnerable(self):
        result = _run_module(CRYPTO_REPORT_VULNERABLE)
        ssh_findings = [f for f in result['findings'] if f['rule_id'].startswith('pqc_ssh_hostkey_')]
        assert len(ssh_findings) == 2
        assert all(f['status'] == 'fail' for f in ssh_findings)

    def test_certificate_vulnerable(self):
        result = _run_module(CRYPTO_REPORT_VULNERABLE)
        cert_findings = [f for f in result['findings'] if f['rule_id'].startswith('pqc_cert_')]
        assert len(cert_findings) == 1
        assert cert_findings[0]['status'] == 'fail'

    def test_tls_service_vulnerable(self):
        result = _run_module(CRYPTO_REPORT_VULNERABLE)
        tls_findings = [f for f in result['findings'] if f['rule_id'].startswith('pqc_tls_service_port_')]
        assert len(tls_findings) == 1
        assert tls_findings[0]['status'] == 'fail'

    def test_sshd_kex_no_pqc(self):
        result = _run_module(CRYPTO_REPORT_VULNERABLE)
        sshd = [f for f in result['findings'] if f['rule_id'] == 'pqc_sshd_kex_algorithms']
        assert sshd[0]['status'] == 'fail'

    def test_crypto_policy_fail(self):
        result = _run_module(CRYPTO_REPORT_VULNERABLE)
        policy = [f for f in result['findings'] if f['rule_id'] == 'pqc_crypto_policy_profile']
        assert policy[0]['status'] == 'fail'

    def test_low_compliance_score(self):
        result = _run_module(CRYPTO_REPORT_VULNERABLE)
        assert result['summary']['compliance_score'] < 10

    def test_total_findings_count(self):
        result = _run_module(CRYPTO_REPORT_VULNERABLE)
        assert result['summary']['total'] >= 8


class TestNormalizePQCEmptyReport:
    """Tests for an empty/minimal crypto report."""

    def test_produces_at_least_openssl_findings(self):
        result = _run_module(CRYPTO_REPORT_EMPTY)
        assert result['summary']['total'] >= 2

    def test_openssl_fails_when_empty(self):
        result = _run_module(CRYPTO_REPORT_EMPTY)
        mlkem = [f for f in result['findings'] if f['rule_id'] == 'pqc_openssl_mlkem_support']
        assert mlkem[0]['status'] == 'fail'

    def test_no_certificates_means_no_cert_findings(self):
        result = _run_module(CRYPTO_REPORT_EMPTY)
        cert_findings = [f for f in result['findings'] if f['rule_id'].startswith('pqc_cert_')]
        assert len(cert_findings) == 0

    def test_sshd_not_checked_when_no_config(self):
        result = _run_module(CRYPTO_REPORT_EMPTY)
        sshd = [f for f in result['findings'] if f['rule_id'] == 'pqc_sshd_kex_algorithms']
        assert sshd[0]['status'] == 'not_checked'


class TestNormalizePQCCFFCompliance:
    """Verify CFF v1.0.0 structural compliance."""

    def test_all_findings_have_required_fields(self):
        result = _run_module(CRYPTO_REPORT_VULNERABLE)
        for f in result['findings']:
            assert 'rule_id' in f
            assert 'stig_id' in f
            assert 'cis_id' in f
            assert 'cce_id' in f
            assert 'cci_id' in f
            assert 'title' in f
            assert 'status' in f
            assert 'severity' in f
            assert 'category' in f
            assert 'evidence' in f
            assert 'remediation' in f

    def test_scan_metadata_has_certification(self):
        result = _run_module(CRYPTO_REPORT_VULNERABLE)
        meta = result['scan_metadata']
        assert 'certification' in meta
        assert meta['certification']['status'] == 'uncertified'

    def test_scan_metadata_framework(self):
        result = _run_module(CRYPTO_REPORT_VULNERABLE)
        assert result['scan_metadata']['framework'] == 'CUSTOM'

    def test_custom_scan_id(self):
        result = _run_module(CRYPTO_REPORT_VULNERABLE, scan_id='test-scan-123')
        assert result['scan_metadata']['scan_id'] == 'test-scan-123'

    def test_certification_parameters(self):
        result = _run_module(
            CRYPTO_REPORT_VULNERABLE,
            certification_status='conformant',
            certification_authority='Test Authority',
        )
        cert = result['scan_metadata']['certification']
        assert cert['status'] == 'conformant'
        assert cert['authority'] == 'Test Authority'

    def test_evidence_structure(self):
        result = _run_module(CRYPTO_REPORT_VULNERABLE)
        for f in result['findings']:
            ev = f['evidence']
            assert 'actual_value' in ev
            assert 'expected_value' in ev

    def test_remediation_not_available(self):
        result = _run_module(CRYPTO_REPORT_VULNERABLE)
        for f in result['findings']:
            assert f['remediation']['available'] is False


class TestNormalizePQCOutputFile:
    """Test output file writing."""

    def test_writes_json_file(self):
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
            tmp_path = tmp.name

        try:
            result = _run_module(CRYPTO_REPORT_PQC_READY, output_file=tmp_path)
            assert result['output_file'] == tmp_path
            with open(tmp_path) as f:
                data = json.load(f)
            assert data['version'] == '1.0.0'
            assert len(data['findings']) > 0
        finally:
            os.unlink(tmp_path)
