# Security Governance Model

V7 adds enterprise-style governance around dependency decisions.

## Policy-as-code

`data/security_policy.example.json` supports:

- allowlist
- blocklist
- risk-score rules
- malware-analysis rules
- expiring exceptions
- approver and ticket metadata
- policy result export
- JSONL audit log append

## Exceptions

Exceptions should be temporary and reviewed. Each exception should include:

- `expires`
- `approved_by`
- `ticket`
- `justification`
- risk boundaries such as `max_risk_score`

## Provenance

`data/provenance_policy.example.json` supports:

- registry digest requirement
- optional Sigstore CLI identity verification
- local SLSA/in-toto attestation validation
- expected builder and source repository checks

## Malware analysis

Static package analysis checks artifacts for:

- secrets and tokens
- private keys
- suspicious webhooks and IOCs
- crypto wallets
- reverse shell patterns
- credential exfiltration intent
- native binary/high-entropy artifacts
- archive bomb protections
