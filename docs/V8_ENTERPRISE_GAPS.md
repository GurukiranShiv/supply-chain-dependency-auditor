# V8 Enterprise Gap Closure

V8 addresses the seven remaining industrial gaps that were identified during review.

## 1. False-positive tuning

`auditor.scorer` now includes a final confidence-calibration guardrail. Established packages with only low-confidence static malware/context findings are capped below actionable risk unless there is a strong signal such as typosquatting, breach-watchlist match, integrity mismatch, malicious install script, high CVE, or dynamic sandbox behavior.

## 2. Real resolver-level accuracy

`auditor.resolver` adds native package-manager resolution:

- `pip install --dry-run --report` for exact Python resolution
- `npm install --package-lock-only --ignore-scripts` for exact npm resolution
- `go list -m -json all` for Go module resolution

Use:

```bash
supply-chain-auditor audit . --resolver exact --resolver-report resolver-results.json
```

## 3. Sigstore/SLSA provenance verification

The existing V7 provenance engine remains in place and is now documented as a strict enterprise mode. It supports:

- registry digest verification
- Sigstore CLI identity verification when a trusted identity/issuer policy is configured
- SLSA/in-toto attestation validation against expected builder and source repository

Use:

```bash
supply-chain-auditor audit . --provenance-policy data/provenance_policy.example.json
```

## 4. Dynamic malware sandboxing

`auditor.sandbox` adds optional Docker-based dynamic install analysis. It is disabled by default. When enabled, it runs pip/npm installs in a restricted container with dropped capabilities, memory and process limits, tmpfs, and configurable network mode.

Use safe no-network mode:

```bash
supply-chain-auditor audit . --sandbox --sandbox-network none --sandbox-report sandbox-results.json
```

Use `--sandbox-network bridge` only in a disposable CI worker or lab VM.

## 5. Multi-ecosystem coverage

`auditor.lockfile` now parses additional ecosystem manifests:

- Maven: `pom.xml`, `build.gradle`, `build.gradle.kts`
- Go: `go.mod`
- NuGet: `packages.lock.json`, `.csproj`
- RubyGems: `Gemfile.lock`
- Containers: `Dockerfile`
- GitHub Actions: `.github/workflows/*.yml`, `.yaml`
- Terraform: `*.tf`

OSV ecosystem mapping was also extended for Maven, Go, NuGet, RubyGems, and Docker.

## 6. Enterprise governance workflow

`auditor.enterprise_governance` adds:

- owner map support
- SLA report generation
- Jira/ServiceNow-compatible CSV export
- enterprise evidence bundle with NIST SSDF, SLSA, and OWASP SCVS control mapping

Use:

```bash
supply-chain-auditor audit . \
  --owner-map data/owners.example.json \
  --sla-report sla-report.json \
  --jira-export jira-import.csv \
  --evidence-bundle evidence-bundle.json
```

## 7. Safer CI/CD hardening

`auditor.ci_hardening` audits GitHub Actions workflows for:

- unpinned actions
- missing least-privilege `permissions`
- dangerous broad permissions
- risky `pull_request_target` usage

Use:

```bash
supply-chain-auditor audit . --ci-hardening-report ci-hardening.json
```

## Recommended V8 command

```bash
supply-chain-auditor audit . \
  --resolver exact \
  --policy data/security_policy.example.json \
  --policy-mode report \
  --policy-report policy-results.json \
  --policy-audit-log policy-audit.jsonl \
  --provenance-policy data/provenance_policy.example.json \
  --ci-hardening-report ci-hardening.json \
  --owner-map data/owners.example.json \
  --sla-report sla-report.json \
  --jira-export jira-import.csv \
  --evidence-bundle evidence-bundle.json \
  --json results.json \
  --html report.html \
  --sbom sbom.json \
  --sarif results.sarif \
  --remediation remediation.json
```
