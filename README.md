# PQC-AAP

Read-only **Post-Quantum Cryptography readiness** assessment for RHEL 8/9 hosts, delivered as an Ansible collection installable on the [AAP Compliance Pipelines](https://github.com/cross-logic/aap-compliance-pipelines).

Evaluates PQC readiness across 8 categories — OpenSSL runtime, system certificates, SSH host keys, TLS services, nginx certificates, sshd configuration, and RHEL crypto-policies — producing Common Findings Format (CFF) v1.0.0 JSON for the Backstage compliance plugin.

| Property | Value |
|----------|-------|
| **Framework** | CUSTOM |
| **Scanner** | custom (Tier 1 — native OS tools) |
| **Certification** | uncertified |
| **Platforms** | RHEL 8, RHEL 9 |
| **Remediation** | Not available (manual guidance in fix_text) |

## Project Structure

```
PQC-AAP/
  ansible_collections/security/compliance_pqc_readiness/
    galaxy.yml                    # Collection metadata (v0.2.0)
    meta/compliance-profile.yml   # Compliance pipeline profile identity
    meta/runtime.yml              # Ansible version constraint
    plugins/modules/normalize_pqc.py  # CFF normalizer module
    playbooks/
      pqc_pipeline.yml            # Pipeline-compatible (2-play Direct POST)
      normalize.yml               # Standalone normalization utility
      remediate.yml               # Placeholder (manual guidance)
    roles/crypto_posture_snapshot/  # Discovery role (read-only)
    tests/unit/                   # pytest unit tests
    LICENSE
  ee/execution-environment.yml    # Execution Environment build definition
  install.yml                     # Register profile on AAP Controller
  playbooks/                      # Standalone playbooks (non-pipeline use)
    crypto_posture_snapshot.yml   # Full snapshot with HTML/PDF reports
    pqc_pipeline.yml              # Legacy pipeline (event-based)
    normalize.yml                 # Standalone normalize
    sync_pqc_inventory.yml        # Sync results to Controller inventory
  roles/                          # Standalone role (same as collection)
  plugins/modules/                # Standalone module (same as collection)
  setup/configure-aap-project.yml # AAP project + EE registration
  inventory/hosts.yml             # Sample inventory
  collections/requirements.yml    # Galaxy dependencies
  reports/                        # Generated report output
```

## Installation on AAP Compliance Pipelines

This project is designed as a compliance profile that plugs into the [aap-compliance-pipelines](https://github.com/cross-logic/aap-compliance-pipelines) Backstage plugin.

### 1. Build the Execution Environment

```bash
ansible-builder build -f ee/execution-environment.yml -t compliance-pqc-readiness:latest -v3
```

Push to your container registry:

```bash
podman push compliance-pqc-readiness:latest quay.io/your-org/compliance-pqc-readiness:latest
```

### 2. Register on AAP Controller

```bash
export AAP_HOST=https://controller.example.com
export AAP_API_TOKEN=<your-token>

ansible-playbook install.yml \
  -e organization=Default \
  -e project=compliance-profile-pqc-readiness \
  -e execution_environment=compliance-pqc-readiness \
  -e inventory=compliance-rhel-inventory
```

This creates:
- **Assessment JT**: `compliance-scan-pqc-readiness` (runs `pqc_pipeline.yml`)
- **Remediation JT**: `compliance-remediate-pqc-readiness` (placeholder)

### 3. Register in Backstage

In **Compliance > Settings**, add a new profile:
- Select the assessment JT (`compliance-scan-pqc-readiness`)
- The `compliance-profile.yml` metadata auto-populates profile fields
- Link the remediation JT (`compliance-remediate-pqc-readiness`)

### Pipeline Integration (Direct POST)

The collection's `playbooks/pqc_pipeline.yml` follows the ADR-003 pattern:

1. **Play 1** (on targets): Runs the `crypto_posture_snapshot` role — read-only discovery
2. **Play 2** (on localhost): Normalizes to CFF and POSTs findings to `/api/compliance/findings/ingest`

Extra vars injected by the Backstage plugin at launch:
- `scan_id` — UUID assigned by the backend
- `backstage_api_url` — Backend base URL
- `ingest_token` — Per-scan security token (ADR-010)
- `compliance_profile` — Profile UUID from Settings

## Standalone Usage (without Pipeline)

### Requirements

- Ansible 2.15+
- Collections: `community.crypto`, `ansible.posix`, `community.general`

```bash
ansible-galaxy collection install -r collections/requirements.yml -p collections
```

### Quick Start

1. Add hosts under the `pqc_targets` group in `inventory/hosts.yml`
2. Run the snapshot:

```bash
ansible-playbook playbooks/crypto_posture_snapshot.yml
```

3. Generate HTML/PDF reports:

```bash
ansible-playbook playbooks/crypto_posture_snapshot.yml \
  -e pqc_write_html_report=true \
  -e pqc_write_pdf_report=true
```

4. Sync findings to AAP Controller inventory:

```bash
ansible-playbook playbooks/sync_pqc_inventory.yml \
  -e aap_controller_url=https://controller.example.com
```

## What It Checks

| Category | Rule IDs | Check |
|----------|----------|-------|
| Cryptographic Libraries | `pqc_openssl_mlkem_support`, `pqc_openssl_version` | ML-KEM in TLS 1.3 groups, OpenSSL >= 3.5 |
| Certificates | `pqc_cert_<hash>` | PQC-safe public key algorithm |
| TLS Services | `pqc_nginx_cert_<hash>`, `pqc_tls_service_port_<port>` | PQC KEX on active TLS services |
| SSH Configuration | `pqc_ssh_hostkey_<algo>`, `pqc_sshd_kex_algorithms` | PQC host keys and KEX config |
| System Configuration | `pqc_crypto_policy_profile` | RHEL crypto-policy PQC sub-policy |

## Role Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `pqc_collect_packages` | `true` | Gather OpenSSL package versions |
| `pqc_collect_openssl` | `true` | OpenSSL version and TLS groups |
| `pqc_collect_nginx_certs` | `true` | Discover and inspect nginx certs |
| `pqc_collect_sshd` | `true` | SSH daemon crypto directives |
| `pqc_collect_ssh_host_keys` | `true` | SSH host key algorithms |
| `pqc_collect_system_certs` | `true` | System certificate scan |
| `pqc_collect_tls_services` | `true` | TLS port probe |
| `pqc_collect_crypto_policy` | `true` | RHEL crypto-policies |
| `pqc_write_local_report` | `false` | Write JSON reports |
| `pqc_write_html_report` | `false` | Generate HTML reports |
| `pqc_write_pdf_report` | `false` | Export PDF (requires weasyprint) |

## Running Tests

```bash
cd ansible_collections/security/compliance_pqc_readiness
pytest tests/unit/ -v
```

## Discovery Tools Used

All discovery is read-only (`changed=0`):

- `openssl version`, `openssl list -tls-groups -tls1_3`
- `ssh-keygen -l -f`
- `openssl x509 -noout -text`
- `openssl s_client -connect`
- `ss -tlnp`
- `update-crypto-policies --show`
- `fips-mode-setup --check`
- `community.crypto.x509_certificate_info` (nginx certs)

## Maintainer Checks

```bash
ansible-galaxy collection install -r collections/requirements.yml -p collections
ansible-playbook --syntax-check playbooks/crypto_posture_snapshot.yml
ansible-playbook --syntax-check install.yml
cd ansible_collections/security/compliance_pqc_readiness && pytest tests/unit/ -v
```
