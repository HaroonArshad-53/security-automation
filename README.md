# Security Automation

Small, practical security scripts I write while learning. Each one solves a real problem I've run into.

## Scripts

| Script | What it does |
|--------|--------------|
| [`loginspector.py`](loginspector.py) | Scans auth logs for brute-force and password-spray patterns |

## loginspector.py

Parses syslog-style authentication logs and flags two classic attack patterns:

- **Brute force** — many failed logins for one account from one IP inside a time window
- **Password spray** — one IP attempting logins across many different accounts

```bash
# single file
python3 loginspector.py /var/log/auth.log

# piped input
zcat /var/log/auth.log.*.gz | python3 loginspector.py

# tune sensitivity
python3 loginspector.py --threshold 10 --window 300 auth.log
```

No dependencies beyond the standard library. If your log format isn't matched, extend `PATTERNS` at the top of the script.
