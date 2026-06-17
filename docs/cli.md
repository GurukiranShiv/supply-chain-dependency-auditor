# CLI Reference

## Scan one package

```powershell
supply-chain-auditor scan requests --ecosystem pip --json result.json
```

## Audit a project

```powershell
supply-chain-auditor audit . --json results.json --html report.html --sbom sbom.json --sarif results.sarif
```

## Start REST API server

```powershell
supply-chain-auditor serve --host 127.0.0.1 --port 8080 --root . --token dev-token
```

## Auto-fix from remediation plan

```powershell
supply-chain-auditor fix . --remediation remediation.json --apply --validate-fix --fix-report fix-results.json
```
