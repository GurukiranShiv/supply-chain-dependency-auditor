# Branch Protection Recommendations

For production use, protect `main` with these controls:

1. Require pull requests before merging.
2. Require CODEOWNERS review.
3. Require status checks:
   - unit tests
   - supply-chain audit
   - policy-as-code enforcement
   - SARIF generation
4. Require conversation resolution.
5. Restrict who can push to protected branches.
6. Require signed commits or verified commits when your organization supports it.
7. Pin third-party GitHub Actions to full commit SHA after reviewing the action source.
8. Disable workflow write permissions by default; grant `contents: write` only to isolated remediation jobs.

This repository keeps workflow permissions least-privilege and separates normal audit from optional auto-remediation PR creation.
