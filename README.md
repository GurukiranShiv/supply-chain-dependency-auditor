# Supply Chain Dependency Auditor

**Enterprise-style software supply-chain security auditor for open-source dependencies, package artifacts, CI/CD workflows, provenance signals, REST API integrations, and policy-as-code enforcement.**

This project helps developers and security teams identify risky third-party dependencies before they are installed, merged, or deployed. It focuses on supply-chain risks that are often missed by traditional vulnerability-only scanners, such as typosquatting, suspicious package metadata, weak provenance, unpinned dependencies, unsafe CI/CD workflows, and policy violations.

> Project status: enterprise-grade prototype / industrial-style security tool.  
> Suitable for portfolio, research, capstone, internal lab use, and security engineering demonstrations.

---

## Why this project matters

Modern applications depend heavily on open-source packages from ecosystems such as PyPI, npm, GitHub Actions, Docker, Go, Maven, NuGet, RubyGems, and Terraform.

A dependency may be risky even when it does not have a known CVE. For example:

- A malicious package may use a name similar to a popular package.
- A package may be newly uploaded with limited reputation.
- A dependency may be unpinned or missing integrity hashes.
- A package artifact may contain suspicious install behavior.
- A CI/CD workflow may use unpinned GitHub Actions.
- A package may lack provenance or trusted publishing metadata.
- Security teams may need SBOM, SARIF, Jira, SLA, and evidence output for governance.

This tool was built to detect these risks early and generate practical reports for developers and security teams.

---

## Key capabilities

### Dependency and ecosystem coverage

- PyPI / Python dependency scanning
- npm dependency scanning
- GitHub Actions workflow parsing
- Dockerfile dependency indicators
- Go module parsing
- Maven `pom.xml` parsing
- Gradle dependency parsing
- NuGet dependency parsing
- RubyGems dependency parsing
- Terraform provider parsing
- Direct and transitive dependency expansion

### Supply-chain security checks

- Typosquatting detection
- OSV vulnerability lookup
- CVSS severity enrichment
- EPSS exploit probability enrichment
- Registry metadata analysis
- Maintainer and repository takeover signals
- Recently uploaded package detection
- License compliance checks
- Dependency pinning checks
- Lockfile and integrity validation
- Artifact digest verification
- Provenance and SLSA policy support
- Sigstore verification path
- Static malware behavior analysis
- Secret and IOC detection
- Native binary and high-entropy artifact inspection
- Optional Docker sandbox path
- CI/CD hardening checks
- Policy-as-code enforcement
- Diff-aware baseline scanning
- Auto-remediation planning

### Enterprise-style outputs

The tool can generate:

- `results.json` — main structured audit report
- `report.html` — readable browser report
- `sbom.json` — CycloneDX SBOM
- `results.sarif` — GitHub code scanning compatible SARIF
- `remediation.json` — fix recommendations
- `policy-results.json` — policy-as-code decisions
- `policy-audit.jsonl` — JSONL audit log
- `ci-hardening.json` — GitHub Actions hardening results
- `sla-report.json` — owner and SLA tracking
- `jira-import.csv` — Jira / ServiceNow import file
- `evidence-bundle.json` — enterprise evidence package

---

## Demo result

A clean demo scan should flag the intentionally suspicious package `reques7s` while keeping normal packages safe.

Example result:

```text
Scanned 21 package(s) | CRITICAL: 1 | SAFE: 20

reques7s   pip   100   CRITICAL
requests   pip     0   SAFE
flask      pip     0   SAFE
ollama     pip     0   SAFE
```

`reques7s` is flagged because it is one character away from the popular package `requests`, which is a common typosquatting pattern.

---

## Project structure

```text
supply_chain_dependency_auditor_industrial_v9_1/
├── auditor/
│   ├── cli.py
│   ├── api_server.py
│   ├── registry.py
│   ├── typosquat.py
│   ├── osv_check.py
│   ├── epss.py
│   ├── transitive.py
│   ├── scanner.py
│   ├── malware_analysis.py
│   ├── provenance.py
│   ├── policy_engine.py
│   ├── remediation.py
│   ├── ci_hardening.py
│   ├── enterprise_governance.py
│   ├── sbom.py
│   ├── sarif.py
│   └── data/
├── docs/
├── tests/
├── test-project/
├── test-project-safe/
├── .github/
│   └── workflows/
├── pyproject.toml
├── mkdocs.yml
├── SECURITY.md
├── RELEASE.md
└── README.md
```

---

## Requirements

- Python 3.10 or later
- PowerShell, Bash, or another terminal
- Internet access for live registry and OSV checks
- Optional: Docker for sandbox analysis
- Optional: GitHub CLI for auto-PR workflows
- Optional: Sigstore CLI for stronger provenance verification

---

## Installation

Clone the repository:

```bash
git clone https://github.com/GurukiranShiv/supply-chain-dependency-auditor.git
cd supply-chain-dependency-auditor
```

Install locally in editable mode:

```bash
python -m pip install -e .
```

Check the version:

```bash
supply-chain-auditor --version
```

Expected:

```text
supply-chain-auditor 9.1.0
```

---

## Run tests

```bash
python -m unittest discover -s tests -v
```

Expected:

```text
Ran 94 tests
OK
```

---

## Quick start

Run a clean demo audit against the sample test project:

```bash
supply-chain-auditor audit test-project \
  --no-scan \
  --no-malware \
  --json results.json \
  --html report.html \
  --sbom sbom.json \
  --sarif results.sarif \
  --remediation remediation.json
```

On PowerShell, use backticks:

```powershell
supply-chain-auditor audit test-project `
  --no-scan `
  --no-malware `
  --json results.json `
  --html report.html `
  --sbom sbom.json `
  --sarif results.sarif `
  --remediation remediation.json
```

Open the HTML report:

```powershell
start report.html
```

Or open output files in VS Code:

```powershell
code results.json
code sbom.json
code results.sarif
code remediation.json
```

---

## Full enterprise audit

This command generates the full enterprise-style evidence package.

```powershell
supply-chain-auditor audit . `
  --resolver exact `
  --no-scan `
  --no-malware `
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

The `--no-scan` and `--no-malware` options make the enterprise demo faster by skipping deep package artifact scanning. Remove them when you want deeper static artifact analysis.

---

## REST API mode

The project includes a REST API server for integration with internal tools, dashboards, portals, webhook automation, or security engineering workflows.

Start the API server:

```powershell
supply-chain-auditor serve --host 127.0.0.1 --port 8080 --root . --token dev-token
```

Health check:

```text
http://127.0.0.1:8080/health
```

OpenAPI schema:

```text
http://127.0.0.1:8080/openapi.json
```

Available API paths:

```text
GET  /health
POST /audit
POST /webhook/audit
POST /webhook/github
GET  /openapi.json
```

Run an audit through the API using PowerShell:

```powershell
$headers = @{
  "Content-Type" = "application/json"
  "X-Auditor-Token" = "dev-token"
}

$body = @{
  path = "test-project"
  no_scan = $true
  no_malware = $true
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://127.0.0.1:8080/audit" -Method POST -Headers $headers -Body $body
```

Expected summary:

```text
ok: True
version: 9.1.0
summary:
  total: 21
  critical: 1
  safe: 20
```

> Note: `exit_code: 1` is expected when a critical package is found. It means the security gate correctly failed the audit.

---

## Docs site

Install documentation dependencies:

```bash
python -m pip install -e ".[docs]"
```

Run the documentation site locally:

```bash
mkdocs serve
```

Open:

```text
http://127.0.0.1:8000/supply-chain-dependency-auditor/
```

The documentation includes:

- Quick Start
- CLI Reference
- REST API
- Policy Configuration
- Release to PyPI
- Security Governance
- Branch Protection
- Enterprise Gaps

---

## Build PyPI package

Install build tools:

```bash
python -m pip install --upgrade build twine
```

Build source distribution and wheel:

```bash
python -m build
```

Validate package artifacts:

```bash
python -m twine check dist/*
```

Expected:

```text
PASSED
```

Generated artifacts:

```text
dist/supply_chain_dependency_auditor-9.1.0.tar.gz
dist/supply_chain_dependency_auditor-9.1.0-py3-none-any.whl
```

---

## GitHub Actions and CI/CD hardening

The project includes GitHub Actions workflow support for:

- Running tests
- Running dependency audits
- Generating SARIF
- Uploading code scanning results
- Building documentation
- Publishing package artifacts
- PyPI trusted publishing workflow
- CI/CD hardening checks

Security hardening checks include:

- GitHub Action pinning review
- Workflow permission review
- Risky pattern detection
- Artifact upload review
- CI/CD evidence generation

---

## Policy-as-code

The auditor supports security policy enforcement using JSON policy files.

Example policy file:

```text
data/security_policy.example.json
```

Policy checks can block or warn on:

- Critical risk packages
- High risk packages
- Denied licenses
- Blocklisted packages
- Missing approvals
- Expired exceptions
- Missing ticket references

Run with policy enabled:

```powershell
supply-chain-auditor audit test-project `
  --policy data/security_policy.example.json `
  --policy-mode report `
  --policy-report policy-results.json `
  --policy-audit-log policy-audit.jsonl `
  --json results.json `
  --html report.html
```

---

## Auto-remediation

Generate a remediation file during audit:

```powershell
supply-chain-auditor audit test-project `
  --json results.json `
  --remediation remediation.json
```

Preview fixes without modifying files:

```powershell
supply-chain-auditor fix test-project --remediation remediation.json --fix-report fix-results.json
```

Apply safe fixes:

```powershell
supply-chain-auditor fix test-project --remediation remediation.json --apply --fix-report fix-results.json
```

Validate fixes:

```powershell
supply-chain-auditor fix test-project --remediation remediation.json --apply --validate-fix --fix-report fix-results.json
```

Typosquat replacement requires explicit approval because automatically replacing suspicious packages can be risky.

---

## SARIF and GitHub code scanning

Generate SARIF:

```powershell
supply-chain-auditor audit test-project `
  --sarif results.sarif `
  --json results.json
```

Upload `results.sarif` to GitHub code scanning using GitHub Actions or CodeQL upload workflows.

---

## SBOM generation

Generate CycloneDX SBOM:

```powershell
supply-chain-auditor audit test-project `
  --sbom sbom.json `
  --json results.json
```

The SBOM contains package information and risk metadata that can be used for compliance and inventory tracking.

---

## Example risk interpretation

| Risk level | Meaning |
|---|---|
| SAFE | No major risk signals found |
| LOW | Minor hygiene or metadata issue |
| MEDIUM | Needs security review |
| HIGH | Avoid without approval or exception |
| CRITICAL | Do not install or deploy |

---

## Screenshots to include in portfolio

Recommended screenshots:

1. Unit tests passing: `Ran 94 tests OK`
2. CLI version: `supply-chain-auditor 9.1.0`
3. CLI audit summary showing `reques7s CRITICAL`
4. `report.html` opened in browser
5. REST API `/health` response
6. REST API `/openapi.json` response
7. REST API `/audit` PowerShell response
8. MkDocs documentation site
9. Generated output files in VS Code

---

## Security note

This project performs static and metadata-based supply-chain risk analysis. Some detections are deterministic, such as dependency parsing, SBOM generation, SARIF generation, policy checks, and report generation. Other detections are heuristic, such as typosquatting, suspicious package behavior, malware indicators, IOC extraction, and maintainer risk signals.

For real production use, organizations should tune policies, add private registry support, configure trusted provenance identities, integrate with SIEM/SOAR tools, and run scans inside hardened sandbox infrastructure.

---

## Suggested resume bullet

Built an enterprise-style supply-chain dependency auditor that detects typosquatting, vulnerable dependencies, suspicious package behavior, weak provenance, unsafe CI/CD configurations, and policy violations across multiple ecosystems. Implemented REST API support, SBOM/SARIF/HTML/JSON reporting, policy-as-code enforcement, remediation planning, CI/CD hardening checks, SLA tracking, Jira export, and evidence bundle generation.

---

## Disclaimer

This project is an enterprise-grade prototype designed for learning, portfolio demonstration, and security engineering experimentation. It should not be treated as a complete replacement for commercial enterprise supply-chain security platforms without additional production hardening, private registry integration, operational monitoring, and organization-specific policy tuning.
