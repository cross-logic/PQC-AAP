# security.compliance_pqc_readiness

Ansible collection for Post-Quantum Cryptography readiness assessment on RHEL 8/9.

## Installation

```bash
ansible-galaxy collection install security.compliance_pqc_readiness
```

Or install from source:

```bash
ansible-galaxy collection build ansible_collections/security/compliance_pqc_readiness
ansible-galaxy collection install security-compliance_pqc_readiness-0.2.0.tar.gz
```

## Usage

### As a compliance profile (pipeline mode)

```yaml
- name: PQC Discovery
  hosts: all
  become: true
  roles:
    - security.compliance_pqc_readiness.crypto_posture_snapshot

- name: Normalize findings
  hosts: localhost
  tasks:
    - security.compliance_pqc_readiness.normalize_pqc:
        crypto_report: "{{ hostvars[item].pqc_crypto_report }}"
      loop: "{{ groups['all'] | select('ne', 'localhost') | list }}"
```

### Standalone

```bash
ansible-playbook security.compliance_pqc_readiness.pqc_pipeline
```

## Dependencies

- `community.crypto` >= 2.0.0
- `ansible.posix` >= 1.5.0
- `community.general` >= 5.0.0

## License

GPL-3.0-or-later
