# Security Policy

## Supported versions

Security fixes are applied to the latest major version of this project.

## Reporting a vulnerability

Please do not open a public issue for exploitable vulnerabilities. Send a private report to the repository owner or use GitHub private vulnerability reporting if enabled.

Include:

- Affected version or commit
- Reproduction steps
- Impact
- Suggested fix, if known

## Security controls in this repository

- Dependency audit CLI with SARIF, SBOM, policy-as-code, remediation, and auto-fix support
- Expiring policy exceptions with approver and ticket metadata
- Least-privilege GitHub Actions permissions
- Dependabot configuration for Python and GitHub Actions dependencies
- CODEOWNERS review routing for scanner, policy, and CI/CD changes
- Recommended branch protection documented in `docs/BRANCH_PROTECTION.md`
