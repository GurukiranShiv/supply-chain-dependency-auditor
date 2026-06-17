# Supply Chain Dependency Auditor

Supply Chain Dependency Auditor is an enterprise-style security tool that audits dependency manifests, package metadata, transitive dependencies, package artifacts, CI/CD workflows, provenance signals, and policy-as-code rules.

It supports CLI usage, REST API usage, webhook-style automation, SARIF, CycloneDX SBOM, HTML reports, remediation plans, SLA reports, Jira/ServiceNow CSV export, and evidence bundles.

## Core use cases

- Detect typosquatting such as `reques7s` vs `requests`
- Check OSV vulnerabilities, CVSS, EPSS, maintainer signals, and registry metadata
- Scan package artifacts for install scripts, malware indicators, secrets, IOCs, and native binaries
- Verify artifact hashes and configured provenance/SLSA policy paths
- Review GitHub Actions hardening, workflow permissions, and action pinning
- Enforce policy-as-code with exceptions, approvals, tickets, and JSONL audit logs

## Demo result

A clean demo should show one critical test dependency and normal packages as safe:

```text
reques7s  CRITICAL
requests  SAFE
flask     SAFE
ollama    SAFE
```
