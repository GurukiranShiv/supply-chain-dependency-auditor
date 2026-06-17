# Policy Configuration

Policy-as-code supports:

- allowlists
- blocklists
- risk score rules
- signal-based review rules
- expiring exceptions
- approver identity
- ticket ID
- JSONL audit log output

Example:

```json
{
  "schema": "supply-chain-auditor-policy-v2",
  "default_action": "allow",
  "rules": [
    {
      "id": "block-critical-risk",
      "when": {"risk_score_gte": 85, "not_allowlisted": true},
      "action": "block",
      "message": "Critical supply-chain risk is not allowed."
    }
  ]
}
```
