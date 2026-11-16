# Ruff fixture (ruff 0.16.10)

Recorded output the contract test parses, so a newer Ruff release cannot
silently change normalization. Re-record under a new version directory and
keep both passing.

```bash
cd sample
# absolute filenames rewritten to relative ("messy.py") after recording,
# so the fixture is machine-independent like Bandit's "./app.py"
ruff check --output-format json --select F,B,C90,PLE messy.py > ../ruff-check.json
# one `ruff rule <CODE> --output-format json` per unique code,
# collected as {code: metadata} in ../ruff-rules.json
```

`sample/messy.py` deliberately triggers all four default families of
section 6: F401/F841 (Pyflakes), B006 (Bugbear), C901 (mccabe) and
PLE1307 (Pylint errors).
