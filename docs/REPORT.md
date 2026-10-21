# Penetration Test Report — JobBoard Web Application

**Client:** JobBoard (internal lab target)
**Assessment type:** Grey-box web application penetration test
**Environment:** `http://127.0.0.1:5000` (local, non-production)
**Tester:** _<your name>_
**Date:** _<assessment date>_
**Report version:** 1.0

> **Authorization note.** This is a self-owned, intentionally vulnerable lab
> application. All testing was performed against a local instance owned by the
> tester. No third-party systems were in scope or touched.

---

## 1. Executive summary

JobBoard is a Flask-based job-board application allowing users to register,
browse and post jobs, apply to roles, and manage a profile. A grey-box
assessment identified **10 findings**, including **4 Critical** and
**3 High** severity issues that together allow a remote, unauthenticated or
low-privileged attacker to **fully compromise the application and the host it
runs on**.

Most notably:

- **Authentication can be bypassed entirely** via SQL injection, granting
  administrator access without credentials.
- **The database can be dumped** (usernames, password hashes, API keys) through
  a second injection point.
- **Arbitrary code executes on the server** through both Server-Side Template
  Injection and OS command injection, giving the attacker a shell.

The root causes are a small number of recurring anti-patterns: building SQL and
templates from unsanitized input, trusting client-supplied identifiers and file
paths, and insecure configuration. All are well-understood and inexpensive to
fix. **Remediation guidance is provided per finding in Section 4.**

### Risk summary

| Severity | Count |
|---|---|
| 🔴 Critical | 4 |
| 🟠 High | 3 |
| 🟡 Medium | 2 |
| 🔵 Low | 1 |

---

## 2. Scope & methodology (summary)

- **In scope:** the JobBoard web application and its host, local instance only.
- **Approach:** grey-box — source available, tester authenticated as a standard
  user for parts of the test.
- **Method:** reconnaissance → application mapping → authentication &
  authorization testing → input-handling / injection testing → server-side
  exploitation → impact validation → reporting. Full detail in
  [`METHODOLOGY.md`](METHODOLOGY.md).
- **Severity rating:** CVSS-style qualitative rating based on impact and
  exploitability (ease, privilege required, authentication required).

---

## 3. Findings overview

| ID | Finding | Severity | OWASP 2021 | CWE |
|----|---------|----------|------------|-----|
| JB-01 | SQL injection — authentication bypass | 🔴 Critical | A03 Injection | CWE-89 |
| JB-02 | SQL injection — database exfiltration | 🔴 Critical | A03 Injection | CWE-89 |
| JB-03 | Server-Side Template Injection → RCE | 🔴 Critical | A03 Injection | CWE-1336 |
| JB-04 | OS command injection | 🔴 Critical | A03 Injection | CWE-78 |
| JB-05 | IDOR / broken access control | 🟠 High | A01 Broken Access Control | CWE-639 |
| JB-06 | Path traversal — arbitrary file read | 🟠 High | A01 Broken Access Control | CWE-22 |
| JB-07 | Server-Side Request Forgery (SSRF) | 🟠 High | A10 SSRF | CWE-918 |
| JB-08 | Stored & reflected XSS | 🟡 Medium | A03 Injection | CWE-79 |
| JB-09 | Weak password storage (unsalted MD5) | 🟡 Medium | A02 Cryptographic Failures | CWE-916 |
| JB-10 | Security misconfiguration (debug, headers, secrets) | 🔵 Low | A05 Misconfiguration | CWE-16 |

---

## 4. Detailed findings

Each finding lists: description, affected location, reproduction steps / PoC,
impact, and remediation. PoC scripts live in [`../exploits/`](../exploits/).

---

### JB-01 — SQL injection: authentication bypass 🔴 Critical

**Location:** `POST /login` — `app/app.py`, `login()`

**Description.** The login query is built by string-formatting the username and
password hash directly into SQL:

```python
query = "SELECT * FROM users WHERE username = '%s' AND password_md5 = '%s'" % (username, pw_md5)
```

An attacker controls `username`, so they can alter the query's logic.

**Reproduction.** Submit:

```
username:  admin' -- 
password:  (anything)
```

The resulting query becomes:

```sql
SELECT * FROM users WHERE username = 'admin' -- ' AND password_md5 = '...'
```

The `--` comments out the password check, authenticating as `admin`.

**PoC:** `python exploits/01_sqli_login_bypass.py`

**Impact.** Complete authentication bypass; full administrative access without
any valid credential. **Critical.**

**Remediation.**
- Use **parameterized queries / prepared statements** exclusively:
  `db.execute("SELECT ... WHERE username = ? AND password_md5 = ?", (u, h))`.
- Never build SQL by string concatenation or `%`-formatting.
- Use an ORM (e.g. SQLAlchemy) which parameterizes by default.

---

### JB-02 — SQL injection: database exfiltration 🔴 Critical

**Location:** `GET /search?q=` — `app/app.py`, `search()`

**Description.** The search query interpolates `q` into a `LIKE` clause. Because
the `jobs` table has six columns, a `UNION SELECT` with six columns pulls data
from any table — including `users`.

**Reproduction / PoC:** `python exploits/02_sqli_data_exfil.py`

Payload:
```
zzz%' UNION SELECT id, username, password_md5, role, api_key, 0 FROM users -- 
```
Usernames, **MD5 password hashes**, roles, and API keys are rendered back in the
job results. The MD5 hashes (see JB-09) crack in seconds.

**Impact.** Full disclosure of all user credentials and secrets. Combined with
JB-09, leads to account takeover across the application. **Critical.**

**Remediation.** As JB-01: parameterized queries. Additionally apply
least-privilege DB accounts and avoid returning raw query errors (see JB-10).

---

### JB-03 — Server-Side Template Injection → RCE 🔴 Critical

**Location:** `GET/POST /profile` — `app/app.py`, `profile()`

**Description.** The user's stored `bio` is concatenated into a Jinja2 template
string and rendered with `render_template_string`:

```python
template = "{% extends 'profile.html' %}{% block bio %}" + bio + "{% endblock %}"
```

User input processed as template source means the attacker can evaluate
arbitrary expressions, and from there reach Python's runtime.

**Reproduction / PoC:** `python exploits/04_ssti_rce.py`

- Confirm: set bio to `{{ 7*7 }}` → renders `49`.
- Escalate: `{{ cycler.__init__.__globals__.os.popen('whoami').read() }}` →
  executes a shell command and returns its output.

**Impact.** Remote code execution as the application user. Full host compromise.
**Critical.**

**Remediation.**
- Never pass user input as template **source**. Render a fixed template and pass
  user data as a **context variable** (`render_template('profile.html', bio=bio)`),
  which auto-escapes.
- If user-authored rich text is required, render it as data (escaped) or use a
  sandboxed, allow-listed markup renderer (e.g. Markdown with sanitization).

---

### JB-04 — OS command injection 🔴 Critical

**Location:** `GET /resume/convert?file=` — `app/app.py`, `resume_convert()`

**Description.** The file name is interpolated into a shell command executed with
`shell=True`:

```python
cmd = "cat " + os.path.join(uploads, filename)
subprocess.check_output(cmd, shell=True, ...)
```

Shell metacharacters in `filename` run additional commands.

**Reproduction / PoC:** `python exploits/05_command_injection.py`

Payload: `alice_resume.txt & whoami` → the server runs `whoami` and returns its
output.

**Impact.** Arbitrary command execution on the host. **Critical.**

**Remediation.**
- Avoid shelling out. For reading a file, use Python I/O (`open()`), not `cat`.
- If a subprocess is unavoidable, call it with an **argument list** and
  `shell=False`: `subprocess.run(["convert", path], shell=False)`.
- Validate the filename against an allow-list / strict pattern; never pass raw
  user input to a shell.

---

### JB-05 — IDOR / broken access control 🟠 High

**Location:** `GET /application/<id>` — `app/app.py`, `view_application()`

**Description.** The endpoint checks only that *a* user is logged in, never that
the application record belongs to them. Any authenticated user can read any
other user's private cover letters and resumes by incrementing the id.

**Reproduction / PoC:** `python exploits/03_idor.py` (logs in as `bob`, reads
`alice`'s applications).

**Impact.** Horizontal privilege escalation; disclosure of all users' private
application data (PII). **High.**

**Remediation.**
- Enforce object-level authorization: `WHERE id = ? AND user_id = ?`, or verify
  `app_row.user_id == session.user_id` before returning data.
- Prefer unpredictable identifiers (UUIDs) as defence in depth, but **do not
  rely on them** — always check ownership server-side.

---

### JB-06 — Path traversal: arbitrary file read 🟠 High

**Location:** `GET /resume/download?file=` — `app/app.py`, `resume_download()`

**Description.** The supplied name is joined to the uploads directory without
normalization, so `../` sequences escape it:

```python
path = os.path.join(base, filename)   # filename = "../FLAG_secret_config.txt"
```

**Reproduction / PoC:** `python exploits/06_path_traversal.py` — reads the
out-of-scope `FLAG_secret_config.txt` containing DB credentials.

**Impact.** Disclosure of any file readable by the process (source, config,
secrets, `/etc/passwd`). **High.**

**Remediation.**
- Resolve the path and confirm it stays within the base dir:
  `os.path.realpath(path).startswith(os.path.realpath(base) + os.sep)`.
- Better: store an allow-list of valid files / ids and never accept raw paths;
  use `werkzeug.utils.secure_filename` for names.

---

### JB-07 — Server-Side Request Forgery (SSRF) 🟠 High

**Location:** `GET /jobs/import?url=` — `app/app.py`, `jobs_import()`

**Description.** The server fetches any URL the user provides, with no scheme or
host restrictions, letting an attacker reach internal-only services.

**Reproduction / PoC:** `python exploits/07_ssrf.py` — the server fetches an
internal loopback endpoint on the attacker's behalf.

**Impact.** Access to internal services, loopback admin panels, and — in cloud
deployments — the instance metadata service
(`http://169.254.169.254/`), which often yields credentials. **High.**

**Remediation.**
- Allow-list permitted hosts/domains; reject everything else.
- Block requests to private/loopback/link-local ranges (RFC 1918, 127.0.0.0/8,
  169.254.0.0/16) after DNS resolution (guard against DNS rebinding).
- Disable redirects, restrict schemes to `http(s)`, and require egress through a
  controlled proxy.

---

### JB-08 — Stored & reflected XSS 🟡 Medium

**Location:** job descriptions (stored) and `GET /search?q=` (reflected). Both
rendered with the Jinja `|safe` filter, disabling auto-escaping.

**Description.**
- **Stored:** a job description of `<script>alert(document.cookie)</script>`
  executes for every visitor of that job.
- **Reflected:** `/search?q=<script>alert(1)</script>` executes in the victim's
  browser.

**Impact.** Session theft, credential phishing, actions performed as the victim.
Combined with the hardcoded secret key (JB-10), session cookies are especially
valuable. **Medium.**

**Remediation.**
- Remove `|safe`; rely on Jinja2 auto-escaping (on by default).
- If HTML is needed, sanitize with an allow-list library (e.g. `bleach`).
- Add a `Content-Security-Policy` (see JB-10) and `HttpOnly` on cookies.

---

### JB-09 — Weak password storage (unsalted MD5) 🟡 Medium

**Location:** `app/db.py`, `md5()`

**Description.** Passwords are stored as unsalted MD5 hashes. MD5 is fast and
unsalted hashes fall to rainbow tables and GPU cracking instantly. Combined with
JB-02, every account is trivially compromised.

**Impact.** Mass account takeover once the DB is read. **Medium** (elevated by
JB-02).

**Remediation.** Use a slow, salted password hash designed for the purpose:
**argon2id** (preferred), **bcrypt**, or **scrypt** (e.g. `argon2-cffi`,
`werkzeug.security.generate_password_hash` with a strong method). Never MD5/SHA1
for passwords.

---

### JB-10 — Security misconfiguration 🔵 Low

**Location:** app configuration — `app/app.py`

**Description.** Multiple misconfigurations:
- `debug=True` exposes the Werkzeug interactive debugger and full stack traces.
- `app.secret_key` is a hardcoded, guessable value committed to source — session
  cookies can be forged offline.
- Verbose SQL errors are returned to the client, aiding injection (JB-01/02).
- No security headers: missing `Content-Security-Policy`,
  `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`.
- No CSRF protection on state-changing POST requests.

**Impact.** Information disclosure, session forgery, clickjacking, and easier
exploitation of other findings. **Low** individually, but a force multiplier.

**Remediation.**
- `debug=False` in all non-dev environments; never expose the debugger.
- Load `secret_key` from a secret manager / environment, generated randomly.
- Return generic error pages; log details server-side only.
- Set security headers (consider `flask-talisman`) and enable CSRF protection
  (e.g. `flask-wtf`). Mark cookies `HttpOnly`, `Secure`, `SameSite`.

---

## 5. Remediation priority

| Priority | Findings | Rationale |
|---|---|---|
| **P1 — immediate** | JB-01, JB-02, JB-03, JB-04 | Unauthenticated/low-priv full compromise & RCE |
| **P2 — high** | JB-05, JB-06, JB-07 | Data disclosure & internal pivot |
| **P3 — medium** | JB-08, JB-09 | Client-side & credential risk |
| **P4 — hardening** | JB-10 | Reduces blast radius of everything above |

**Overarching themes:** (1) never build SQL/templates/shell commands from
untrusted input — parameterize or use argument lists; (2) always enforce
authorization at the object level; (3) validate and constrain file paths and
outbound URLs; (4) ship secure configuration by default.

---

## 6. Appendix — tooling & artifacts

- **PoC scripts:** [`../exploits/`](../exploits/) — one runnable script per core finding.
- **Source:** [`../app/app.py`](../app/app.py) — every issue is marked with a `# VULN #NN` comment.
- **Manual tooling used in a real engagement would include:** Burp Suite /
  OWASP ZAP (proxying, Repeater, Intruder), `sqlmap` (injection confirmation),
  `nmap` (service discovery), and `ffuf`/`gobuster` (content discovery). See
  [`METHODOLOGY.md`](METHODOLOGY.md).
