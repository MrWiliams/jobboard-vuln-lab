# JobBoard Vulnerable Lab

I built this as a practice target to sharpen my web security skills, and then wrote it up the way I'd hand a report to a client. It's a small job-board app (Flask + SQLite) with a bunch of real vulnerabilities baked in on purpose. The idea was to not just find the bugs, but to explain why each one happens and how I'd fix it.

If you're here from my portfolio: the writeup in [`docs/REPORT.md`](docs/REPORT.md) is the main thing worth reading.

## Heads up before you run this

This app is vulnerable on purpose. Please keep that in mind:

- It only listens on `127.0.0.1`, so it's not reachable from anywhere but the machine it's running on. Keep it that way — don't stick it on a public server.
- The techniques in here are only legal against a box you own or have written permission to test. Pointed at anything else they'll get you in real trouble (CFAA in the US, the Computer Misuse Act in the UK, and so on). Don't.
- This is for learning, same category as Juice Shop, DVWA, or WebGoat.

## The bugs

Ten issues, mapped to the OWASP Top 10 so it's easy to follow along:

| # | Vulnerability | OWASP 2021 | Where |
|---|---|---|---|
| 01 | SQL injection (auth bypass + data dump) | A03: Injection | `/login`, `/search` |
| 02 | Broken auth (weak hashing, no lockout, guessable session) | A07: Auth Failures | `/login`, session cookie |
| 03 | IDOR | A01: Broken Access Control | `/application/<id>` |
| 04 | Stored & reflected XSS | A03: Injection | job postings, `/search` |
| 05 | SSTI leading to RCE | A03: Injection | `/profile` bio |
| 06 | OS command injection | A03: Injection | `/resume/convert` |
| 07 | Path traversal / arbitrary file read | A01: Broken Access Control | `/resume/download` |
| 08 | SSRF | A10: SSRF | `/jobs/import` |
| 09 | Sensitive data exposure (debug mode, plaintext secrets) | A05: Misconfiguration | app config |
| 10 | Missing security headers, no CSRF protection | A05: Misconfiguration | everywhere |

Full findings are in [`docs/REPORT.md`](docs/REPORT.md), and the process I followed is in [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md).

## What's where

```
pentest-lab/
├── app/
│   ├── app.py                # the vulnerable Flask app
│   ├── db.py                 # SQLite schema + seed data
│   ├── templates/            # some of these are unsafe on purpose
│   └── uploads/              # resume storage (the path-traversal target)
├── exploits/                 # a PoC script per finding
│   ├── 01_sqli_login_bypass.py
│   ├── 02_sqli_data_exfil.py
│   ├── 03_idor.py
│   ├── 04_ssti_rce.py
│   ├── 05_command_injection.py
│   ├── 06_path_traversal.py
│   └── 07_ssrf.py
└── docs/
    ├── REPORT.md             # the pentest report
    └── METHODOLOGY.md        # scope, approach, tooling
```

## Running it

You'll need Python 3.10 or newer.

```bash
cd pentest-lab
python -m venv .venv
# Windows:  .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt
python app/app.py
```

It comes up on http://127.0.0.1:5000 and seeds the database on first run, so there's no setup step beyond that.

There are three accounts to play with:

| Username | Password | Role |
|---|---|---|
| `admin` | `S3cr3tAdm1n!` | admin |
| `alice` | `password123` | user |
| `bob` | `hunter2` | user |

Though honestly you don't need any of them to get started — getting in without a password is finding #1.

## The exploit scripts

Each script in `exploits/` goes after one finding against your local instance:

```bash
python exploits/01_sqli_login_bypass.py
python exploits/02_sqli_data_exfil.py
# ...and so on
```

They print what they're sending and what comes back as they go, so you can watch each attack land instead of just taking my word for it. They pair with the matching section of the report.
