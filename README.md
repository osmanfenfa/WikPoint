# 🔍 Vulnerability Scanner

A terminal-based security scanner with six scan modes — no frameworks, minimal dependencies.

---

## Requirements

```bash
pip install requests
```

Python 3.10+ required for all other modes.

---

## Usage

```bash
python WikPoint.py
```

Select a mode from the interactive menu.

---

## Scan Modes

| # | Mode | What it checks |
|---|------|----------------|
| 1 | **URL** | HTTP vs HTTPS, open-redirect params, XSS / SQLi / path-traversal payloads, raw IPs, subdomain depth, encoded characters, tokens in URLs |
| 2 | **Password** | Entropy, common password list, character classes, keyboard walks, sequential/repeated patterns, overall strength rating |
| 3 | **Code snippet** | `eval`/`exec`, `innerHTML`, `document.write`, hardcoded secrets, raw SQL, shell execution, `pickle.loads`, `yaml.load`, weak PRNGs, MD5/SHA1, debug logging, `DEBUG=True`, SSL verify disabled |
| 4 | **Port scanner** | Scans well-known ports via `socket`; flags risky services (Telnet, RDP, Redis, MongoDB, etc.) |
| 5 | **HTTP headers** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, leaky `Server`/`X-Powered-By` headers |
| 6 | **File scanner** | Points the full code scan at any local source file |

---

## Severity Levels

| Label | Meaning |
|-------|---------|
| `CRITICAL` | Exploitable — fix immediately |
| `WARNING`  | Risky — review and remediate |
| `INFO`     | Notable — worth being aware of |
| `PASS`     | Check passed cleanly |

---

## Notes

- **No data leaves your machine.** All scans run locally.
- The code scanner uses static pattern matching — always combine with dynamic testing and manual review.
- Port scanning should only be run against hosts you own or have explicit permission to test.