# Quick Start

```powershell
python -m pip install -e .
supply-chain-auditor --version
python -m unittest discover -s tests -v
```

Run a full enterprise-style audit:

```powershell
supply-chain-auditor audit . `
  --resolver exact `
  --policy data/security_policy.example.json `
  --policy-mode report `
  --policy-report policy-results.json `
  --policy-audit-log policy-audit.jsonl `
  --provenance-policy data/provenance_policy.example.json `
  --ci-hardening-report ci-hardening.json `
  --owner-map data/owners.example.json `
  --sla-report sla-report.json `
  --jira-export jira-import.csv `
  --evidence-bundle evidence-bundle.json `
  --json results.json `
  --html report.html `
  --sbom sbom.json `
  --sarif results.sarif `
  --remediation remediation.json
```
