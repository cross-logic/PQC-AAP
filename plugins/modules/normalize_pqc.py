#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+

DOCUMENTATION = r'''
---
module: normalize_pqc
short_description: Normalize PQC crypto posture report to Common Findings Format
description:
  - Accepts the pqc_crypto_report fact produced by the crypto_posture_snapshot role.
  - Transforms each cryptographic asset into a pass/fail finding using PQC readiness rules.
  - Output conforms to CFF v1.0.0 for consumption by the Backstage compliance plugin.
  - Read-only evaluation — does not modify any system state.
version_added: "1.0.0"
options:
  crypto_report:
    description: The pqc_crypto_report fact dictionary from the discovery role.
    type: dict
    required: true
  profile_id:
    description: Compliance profile identifier.
    type: str
    default: pqc_readiness_v1
  profile_name:
    description: Human-readable profile name.
    type: str
    default: Post-Quantum Cryptography Readiness
  output_file:
    description: >
      Optional path to write the normalized CFF JSON output.
      If omitted, findings are returned only in the module result (suitable for pipeline mode).
    type: str
    required: false
author:
  - Red Hat Ansible Automation Platform
'''

EXAMPLES = r'''
- name: Normalize PQC report for Backstage pipeline
  normalize_pqc:
    crypto_report: "{{ pqc_crypto_report }}"
  register: pqc_normalized

- name: Display summary
  ansible.builtin.debug:
    msg: >
      PQC assessment: {{ pqc_normalized.summary.compliance_score }}% ready
      ({{ pqc_normalized.summary.pass }} pass, {{ pqc_normalized.summary.fail }} fail)

- name: Write normalized report to file
  normalize_pqc:
    crypto_report: "{{ pqc_crypto_report }}"
    output_file: /tmp/pqc-cff-{{ inventory_hostname }}.json
'''

RETURN = r'''
findings:
  description: List of CFF v1.0.0 findings for consumption by the Backstage plugin
  returned: always
  type: list
  elements: dict
summary:
  description: Aggregate counts (total, pass, fail, error, not_applicable, not_checked, compliance_score)
  returned: always
  type: dict
scan_metadata:
  description: CFF scan_metadata block
  returned: always
  type: dict
output_file:
  description: Path to the written output file (if requested)
  returned: when output_file is specified
  type: str
'''

import hashlib
import json
import os
import re

from ansible.module_utils.basic import AnsibleModule

PQC_SAFE_ALGORITHMS = frozenset([
    'dilithium', 'ml-dsa', 'ml-kem', 'mlkem', 'kyber',
    'sphincs', 'slh-dsa', 'falcon', 'bike', 'hqc',
    'frodokem', 'classic-mceliece',
])

QUANTUM_VULNERABLE_KEY_ALGOS = frozenset([
    'rsa', 'ec', 'ecdsa', 'dsa', 'ed25519', 'ed448', 'dh', 'ecdh',
])


def is_pqc_safe(algorithm_string):
    """Check if an algorithm string contains any PQC-safe algorithm."""
    lower = algorithm_string.lower()
    return any(pqc in lower for pqc in PQC_SAFE_ALGORITHMS)


def is_quantum_vulnerable(algorithm_string):
    """Check if an algorithm string uses only classical (quantum-vulnerable) crypto."""
    lower = algorithm_string.lower()
    return any(algo in lower for algo in QUANTUM_VULNERABLE_KEY_ALGOS)


def short_hash(value):
    """Create a short deterministic hash for path-based rule IDs."""
    return hashlib.sha256(value.encode()).hexdigest()[:8]


def evaluate_openssl(report):
    """Evaluate OpenSSL ML-KEM support."""
    findings = []
    version = report.get('openssl_version', '')
    tls_groups = report.get('openssl_tls1_3_groups', '')
    tls_groups_rc = int(report.get('openssl_tls1_3_groups_rc', -1))

    has_mlkem = bool(re.search(r'(?i)mlkem|kyber', tls_groups))

    findings.append({
        'rule_id': 'pqc_openssl_mlkem_support',
        'title': 'OpenSSL ML-KEM Key Exchange Support',
        'status': 'pass' if has_mlkem else 'fail',
        'severity': 'high',
        'category': 'Cryptographic Libraries',
        'description': (
            'OpenSSL must support ML-KEM (Kyber) hybrid key exchange groups in TLS 1.3 '
            'to enable post-quantum key encapsulation.'
        ),
        'check_text': 'Run: openssl list -tls-groups -tls1_3 and verify ML-KEM groups are listed.',
        'fix_text': 'Upgrade OpenSSL to 3.5+ which includes ML-KEM support, or apply RHEL crypto-policy with PQC modules.',
        'evidence': {
            'actual_value': tls_groups if tls_groups else '(no TLS 1.3 groups available)',
            'expected_value': 'ML-KEM groups (MLKEM512, MLKEM768, MLKEM1024, or hybrids)',
            'message': f'OpenSSL version: {version}. TLS 1.3 groups command rc={tls_groups_rc}.',
            'scanner_rule_id': 'pqc_openssl_mlkem_support',
        },
        'remediation': {
            'role': 'upgrade_openssl',
            'available': False,
            'disruption': 'high',
        },
    })

    version_ok = bool(re.search(r'3\.[5-9]\.|[4-9]\.', version))
    findings.append({
        'rule_id': 'pqc_openssl_version',
        'title': 'OpenSSL Version Supports PQC Algorithms',
        'status': 'pass' if version_ok else 'fail',
        'severity': 'medium',
        'category': 'Cryptographic Libraries',
        'description': 'OpenSSL 3.5+ is required for native ML-KEM and ML-DSA algorithm support.',
        'check_text': 'Run: openssl version',
        'fix_text': 'Upgrade to OpenSSL 3.5 or later (RHEL 9.7+ provides this).',
        'evidence': {
            'actual_value': version or '(not detected)',
            'expected_value': 'OpenSSL >= 3.5.0',
            'message': f'Detected: {version}' if version else 'OpenSSL version could not be determined.',
            'scanner_rule_id': 'pqc_openssl_version',
        },
        'remediation': {
            'role': 'upgrade_openssl',
            'available': False,
            'disruption': 'high',
        },
    })

    return findings


def evaluate_certificates(report):
    """Evaluate system certificates for PQC readiness."""
    findings = []
    certs = report.get('system_certificates', [])

    if not certs:
        return findings

    for cert in certs:
        cert_path = cert.get('path', 'unknown')
        pub_algo = cert.get('public_key_algorithm', 'unknown')
        pub_size = cert.get('public_key_size', 0)
        sig_algo = cert.get('signature_algorithm', 'unknown')
        risk = cert.get('risk', 'unknown')
        subject = cert.get('subject', 'unknown')
        expires = cert.get('expires', 'unknown')

        is_safe = (risk == 'quantum_safe')
        rule_hash = short_hash(cert_path)

        severity = 'medium'
        if not is_safe and int(pub_size) < 2048:
            severity = 'high'

        findings.append({
            'rule_id': f'pqc_cert_{rule_hash}',
            'title': f'Certificate PQC Readiness: {os.path.basename(cert_path)}',
            'status': 'pass' if is_safe else 'fail',
            'severity': severity,
            'category': 'Certificates',
            'description': (
                f'Certificate at {cert_path} must use a post-quantum signature algorithm '
                f'(ML-DSA, SLH-DSA) to resist quantum attacks.'
            ),
            'check_text': f'Inspect certificate: openssl x509 -in {cert_path} -noout -text',
            'fix_text': 'Re-issue certificate with a PQC or hybrid signature algorithm.',
            'evidence': {
                'actual_value': f'{pub_algo} {pub_size}-bit, {sig_algo}',
                'expected_value': 'ML-DSA or hybrid PQC signature algorithm',
                'message': f'Subject: {subject}, Expires: {expires}, Risk: {risk}',
                'scanner_rule_id': f'pqc_cert_{rule_hash}',
            },
            'remediation': {
                'role': 'reissue_certificate_pqc',
                'available': False,
                'disruption': 'high',
            },
        })

    return findings


def evaluate_nginx_certificates(report):
    """Evaluate nginx TLS certificates for PQC readiness."""
    findings = []
    nginx_certs = report.get('nginx_certificates', [])

    if not nginx_certs:
        return findings

    for cert in nginx_certs:
        cert_path = cert.get('path', 'unknown')
        pub_type = cert.get('public_key_type', 'unknown')
        pub_size = cert.get('public_key_size', '0')
        sig_algo = cert.get('signature_algorithm', 'unknown')
        rule_hash = short_hash(cert_path)

        is_safe = is_pqc_safe(pub_type) or is_pqc_safe(sig_algo)

        findings.append({
            'rule_id': f'pqc_nginx_cert_{rule_hash}',
            'title': f'Nginx TLS Certificate: {os.path.basename(cert_path)}',
            'status': 'pass' if is_safe else 'fail',
            'severity': 'high',
            'category': 'TLS Services',
            'description': (
                f'Nginx TLS certificate at {cert_path} must use a post-quantum algorithm '
                f'to protect web traffic against quantum-capable adversaries.'
            ),
            'check_text': f'Inspect: openssl x509 -in {cert_path} -noout -text',
            'fix_text': 'Re-issue the nginx TLS certificate with a PQC or hybrid signature.',
            'evidence': {
                'actual_value': f'{pub_type} {pub_size}-bit, {sig_algo}',
                'expected_value': 'PQC or hybrid signature algorithm',
                'message': f'Service-facing certificate using classical cryptography.',
                'scanner_rule_id': f'pqc_nginx_cert_{rule_hash}',
            },
            'remediation': {
                'role': 'reissue_certificate_pqc',
                'available': False,
                'disruption': 'medium',
            },
        })

    return findings


def evaluate_ssh_host_keys(report):
    """Evaluate SSH host keys for PQC readiness."""
    findings = []
    keys = report.get('ssh_host_keys', [])

    if not keys:
        return findings

    for key in keys:
        algo = key.get('algorithm', 'unknown')
        bits = key.get('bits', 0)
        risk = key.get('risk', 'unknown')
        key_path = key.get('path', 'unknown')

        is_safe = (risk == 'quantum_safe')

        findings.append({
            'rule_id': f'pqc_ssh_hostkey_{algo.lower()}',
            'title': f'SSH Host Key Algorithm: {algo}',
            'status': 'pass' if is_safe else 'fail',
            'severity': 'medium',
            'category': 'SSH Configuration',
            'description': (
                f'SSH host key ({algo}, {bits}-bit) must use a post-quantum algorithm '
                f'to prevent harvest-now-decrypt-later attacks on SSH sessions.'
            ),
            'check_text': f'Run: ssh-keygen -l -f {key_path}',
            'fix_text': 'Generate PQC SSH host keys when ML-DSA host key support is available in OpenSSH.',
            'evidence': {
                'actual_value': f'{algo} ({bits}-bit)',
                'expected_value': 'ML-DSA or PQC-hybrid host key',
                'message': f'Key at {key_path}: {risk}',
                'scanner_rule_id': f'pqc_ssh_hostkey_{algo.lower()}',
            },
            'remediation': {
                'role': 'generate_pqc_ssh_hostkeys',
                'available': False,
                'disruption': 'medium',
            },
        })

    return findings


def evaluate_tls_services(report):
    """Evaluate TLS services (port probes) for PQC key exchange."""
    findings = []
    services = report.get('tls_services', [])

    if not services:
        return findings

    for svc in services:
        port = svc.get('port', 0)
        protocol = svc.get('protocol', 'unknown')
        cipher = svc.get('cipher', 'unknown')
        kex = svc.get('key_exchange', 'unknown')
        kex_risk = svc.get('key_exchange_risk', 'unknown')

        is_safe = kex_risk in ('quantum_safe', 'hybrid_transitional')

        findings.append({
            'rule_id': f'pqc_tls_service_port_{port}',
            'title': f'TLS Service Key Exchange on Port {port}',
            'status': 'pass' if is_safe else 'fail',
            'severity': 'high',
            'category': 'TLS Services',
            'description': (
                f'TLS service on port {port} must negotiate a PQC or hybrid key exchange '
                f'to protect session keys against quantum decryption.'
            ),
            'check_text': f'Run: openssl s_client -connect localhost:{port}',
            'fix_text': 'Configure the service to prefer ML-KEM hybrid key exchange groups.',
            'evidence': {
                'actual_value': f'{kex} ({kex_risk})',
                'expected_value': 'ML-KEM hybrid or PQC key exchange',
                'message': f'Protocol: {protocol}, Cipher: {cipher}, KEX: {kex}',
                'scanner_rule_id': f'pqc_tls_service_port_{port}',
            },
            'remediation': {
                'role': 'configure_tls_pqc_kex',
                'available': False,
                'disruption': 'medium',
            },
        })

    return findings


def evaluate_sshd_config(report):
    """Evaluate sshd crypto configuration for PQC KEX algorithms."""
    findings = []
    crypto_lines = report.get('sshd_crypto_lines', [])

    kex_line = ''
    for line in crypto_lines:
        if line.strip().startswith('KexAlgorithms'):
            kex_line = line
            break

    has_pqc_kex = is_pqc_safe(kex_line) if kex_line else False

    status = 'pass' if has_pqc_kex else 'fail'
    if not kex_line:
        status = 'not_checked'

    findings.append({
        'rule_id': 'pqc_sshd_kex_algorithms',
        'title': 'SSHD Key Exchange Algorithms Include PQC',
        'status': status,
        'severity': 'medium',
        'category': 'SSH Configuration',
        'description': (
            'The sshd_config KexAlgorithms directive should include a post-quantum '
            'key exchange method (e.g., mlkem768x25519-sha256) when available.'
        ),
        'check_text': 'Check /etc/ssh/sshd_config for KexAlgorithms directive.',
        'fix_text': 'Add PQC KEX algorithms to sshd_config KexAlgorithms when supported by OpenSSH.',
        'evidence': {
            'actual_value': kex_line if kex_line else '(KexAlgorithms not explicitly configured — using system default)',
            'expected_value': 'KexAlgorithms including mlkem or sntrup',
            'message': f'Active crypto lines: {len(crypto_lines)}',
            'scanner_rule_id': 'pqc_sshd_kex_algorithms',
        },
        'remediation': {
            'role': 'configure_sshd_pqc_kex',
            'available': False,
            'disruption': 'low',
        },
    })

    return findings


def evaluate_crypto_policy(report):
    """Evaluate RHEL system-wide crypto-policy for PQC readiness."""
    findings = []
    policy = report.get('crypto_policy', {})

    if not policy:
        return findings

    profile = policy.get('profile', 'unknown')
    fips_enabled = policy.get('fips_enabled', False)
    local_overrides = policy.get('local_overrides', [])

    has_pqc_policy = is_pqc_safe(profile) or any(
        is_pqc_safe(str(o)) for o in local_overrides
    )

    findings.append({
        'rule_id': 'pqc_crypto_policy_profile',
        'title': 'System Crypto-Policy Supports PQC',
        'status': 'pass' if has_pqc_policy else 'fail',
        'severity': 'low',
        'category': 'System Configuration',
        'description': (
            'The system-wide crypto-policy should enable PQC algorithm modules '
            'to ensure all applications default to quantum-safe configurations.'
        ),
        'check_text': 'Run: update-crypto-policies --show',
        'fix_text': 'Apply a crypto-policy sub-policy that enables PQC modules: update-crypto-policies --set DEFAULT:PQC',
        'evidence': {
            'actual_value': f'Profile: {profile}, FIPS: {fips_enabled}',
            'expected_value': 'Crypto-policy with PQC sub-policy enabled',
            'message': f'Local overrides: {len(local_overrides)} files',
            'scanner_rule_id': 'pqc_crypto_policy_profile',
        },
        'remediation': {
            'role': 'set_crypto_policy_pqc',
            'available': False,
            'disruption': 'medium',
        },
    })

    return findings


def build_summary(findings):
    """Compute CFF summary counts from a findings list."""
    counts = {
        'total': len(findings),
        'pass': 0,
        'fail': 0,
        'error': 0,
        'not_applicable': 0,
        'not_checked': 0,
    }
    for f in findings:
        status = f.get('status', 'error')
        if status in counts:
            counts[status] += 1

    applicable = counts['total'] - counts['not_applicable'] - counts['not_checked']
    if applicable > 0:
        counts['compliance_score'] = round((counts['pass'] / applicable) * 100, 1)
    else:
        counts['compliance_score'] = 0.0

    return counts


def main():
    module = AnsibleModule(
        argument_spec=dict(
            crypto_report=dict(type='dict', required=True),
            profile_id=dict(type='str', default='pqc_readiness_v1'),
            profile_name=dict(type='str', default='Post-Quantum Cryptography Readiness'),
            output_file=dict(type='str', required=False, default=None),
        ),
        supports_check_mode=True,
    )

    report = module.params['crypto_report']
    profile_id = module.params['profile_id']
    profile_name = module.params['profile_name']
    output_file = module.params['output_file']

    host = report.get('host', 'unknown')
    collected_at = report.get('collected_at', '')

    findings = []
    findings.extend(evaluate_openssl(report))
    findings.extend(evaluate_certificates(report))
    findings.extend(evaluate_nginx_certificates(report))
    findings.extend(evaluate_ssh_host_keys(report))
    findings.extend(evaluate_tls_services(report))
    findings.extend(evaluate_sshd_config(report))
    findings.extend(evaluate_crypto_policy(report))

    for f in findings:
        f['host'] = host

    summary = build_summary(findings)

    scan_metadata = {
        'scan_id': f'pqc-{short_hash(host + collected_at)}',
        'profile_id': profile_id,
        'profile_name': profile_name,
        'framework': 'CUSTOM',
        'scanner': {
            'name': 'custom',
            'version': '1.0.0',
            'tier': 1,
        },
        'timestamp': collected_at,
        'host': host,
    }

    cff_report = {
        'version': '1.0.0',
        'scan_metadata': scan_metadata,
        'findings': findings,
        'summary': summary,
    }

    if output_file and not module.check_mode:
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        with open(output_file, 'w') as f:
            json.dump(cff_report, f, indent=2)

    module.exit_json(
        changed=False,
        findings=findings,
        summary=summary,
        scan_metadata=scan_metadata,
        output_file=output_file or '',
    )


if __name__ == '__main__':
    main()
