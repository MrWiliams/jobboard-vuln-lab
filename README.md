# JobBoard Vulnerable Lab — Security Portfolio Project

> A deliberately insecure job-board web application, built to **demonstrate, exploit, and remediate** common web vulnerabilities — with a full penetration-test report to match.

This is a portfolio piece that shows web security from **both sides**: the attacker's (how each flaw is found and exploited) and the defender's (why it exists and how to fix it). It is intentionally vulnerable and is designed to be run **only on your own machine**.

---

## ⚠️ Ethical & Legal Notice

This application contains **real, exploitable vulnerabilities on purpose**.

- It binds to **`127.0.0.1` (localhost) only** and should never be exposed to a network or the internet.
- Only ever attack **this app, on a host you own**. Running these techniques against systems you do not own and have no written authorization to test is **illegal** (e.g. the US CFAA, the UK Computer Misuse Act, and equivalents worldwide).
- This project exists for **education, skills demonstration, and authorized self-study** — the same purpose as OWASP Juice Shop, DVWA, and WebGoat.

If you clone this, you accept responsibility for using it legally and ethically.

---

## What this project demonstrates

| # | Vulnerability | OWASP 2021 Category | Where |
|---|---|---|---|
| 01 | SQL Injection (auth bypass + data exfiltration) | A03: Injection | `/login`, `/search` |
| 02 | Broken Authentication (weak hashing, no lockout, guessable session) | A07: Identification & Auth Failures | `/login`, session cookie |
| 03 | IDOR / Broken Access Control | A01: Broken Access Control | `/application/<id>` |
| 04 | Stored & Reflected XSS | A03: Injection | job postings, `/search` |
| 05 | Server-Side Template Injection (SSTI) → RCE | A03: Injection | `/profile` bio render |
| 06 | OS Command Injection | A03: Injection | `/resume/convert` |
| 07 | Path Traversal / arbitrary file read | A01: Broken Access Control | `/resume/download` |
| 08 | SSRF | A10: Server-Side Request Forgery | `/jobs/import` |
| 09 | Sensitive Data Exposure (debug mode, plaintext secrets) | A05: Security Misconfiguration | app config |
| 10 | Missing security headers / no CSRF protection | A05: Security Misconfiguration | all responses |

See [`docs/REPORT.md`](docs/REPORT.md) for the full findings report and
[`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) for the testing methodology.

---

## Project layout

```
pentest-lab/
├── README.md                 # you are here
├── requirements.txt
├── app/
│   ├── app.py                # the vulnerable Flask application
│   ├── db.py                 # SQLite schema + seed data
│   ├── templates/            # Jinja2 templates (some intentionally unsafe)
│   └── uploads/              # resume storage (path-traversal target)
├── exploits/                 # proof-of-concept exploit scripts (one per finding)
│   ├── 01_sqli_login_bypass.py
│   ├── 02_sqli_data_exfil.py
│   ├── 03_idor.py
│   ├── 04_ssti_rce.py
│   ├── 05_command_injection.py
│   ├── 06_path_traversal.py
│   └── 07_ssrf.py
└── docs/
    ├── REPORT.md             # professional penetration-test report
    └── METHODOLOGY.md        # scope, methodology, tooling, references
```

---

## Setup

Requires Python 3.10+.

```bash
cd pentest-lab
python -m venv .venv
# Windows:  .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt
python app/app.py
```

The app starts on **http://127.0.0.1:5000**. The database is created and seeded automatically on first run.

### Seeded accounts

| Username | Password | Role |
|---|---|---|
| `admin` | `S3cr3tAdm1n!` | admin |
| `alice` | `password123` | user |
| `bob` | `hunter2` | user |

(You don't need these to start exploiting — bypassing auth is finding #1.)

---

## Running the exploits

Each script in `exploits/` is self-contained and targets the locally running app:

```bash
python exploits/01_sqli_login_bypass.py
python exploits/02_sqli_data_exfil.py
# ...etc
```

Every script prints what it's doing, the request it sends, and the result — so they double as a live demonstration of each finding in the report.

---

## How to present this in a portfolio

1. **Lead with the report** (`docs/REPORT.md`) — it reads like a real client deliverable: executive summary, risk ratings, findings with PoC, and remediation.
2. **Show the methodology** — demonstrates you follow a repeatable process (recon → mapping → exploitation → reporting), not just ad-hoc hacking.
3. **Point to the fixes** — each finding includes remediation, which is what separates a security engineer from a script kiddie.
4. **Optionally record a short demo** running a couple of the exploit scripts against the live app.
