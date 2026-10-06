# detect-secrets fixture (detect-secrets 1.5.0)

Recorded output the contract test parses, so a newer detect-secrets release
cannot silently change normalization. Re-record under a new version directory
and keep both passing.

```bash
cd sample
detect-secrets scan settings.py key.pem > ../detect-secrets.json
```

Positional files are used so the recording works outside a git checkout and
the `results` keys come back relative (`settings.py`), no rewriting needed.

`sample/` contains planted **fake** secrets: a keyword assignment, a
credential in a URL and a PEM-shaped block, triggering `Secret Keyword`,
`Basic Auth Credentials` and `Private Key`. The JSON carries only `type`,
`filename`, `line_number`, `hashed_secret` and `is_verified` - never the
value - which is exactly what the adapter keeps (file, line, type, hash).
