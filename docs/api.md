# REST API and Webhook Mode

V9 adds a lightweight REST API server using only the Python standard library.

Start the server:

```powershell
supply-chain-auditor serve --host 127.0.0.1 --port 8080 --root . --token dev-token
```

Health check:

```powershell
curl http://127.0.0.1:8080/health
```

Run an audit:

```powershell
curl -X POST http://127.0.0.1:8080/audit ^
  -H "Content-Type: application/json" ^
  -H "X-Auditor-Token: dev-token" ^
  -d "{\"path\":\"test-project\",\"no_scan\":true,\"no_malware\":true}"
```

Webhook endpoints:

- `POST /webhook/audit`
- `POST /webhook/github`

The server restricts requested paths to the configured `--root` directory to reduce local path abuse.
