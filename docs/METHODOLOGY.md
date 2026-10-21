# Testing Methodology

This document describes the repeatable process used to assess the JobBoard
application. It mirrors the structure of a real-world web application
penetration test so the project demonstrates **process**, not just individual
exploits.

---

## 1. Rules of engagement (scope)

| Item | Detail |
|---|---|
| Target | JobBoard web app, local instance `http://127.0.0.1:5000` |
| Ownership | Self-owned lab; no third-party systems in scope |
| Window | N/A (local, continuous) |
| Allowed | All web-layer testing, including injection and RCE PoCs |
| Prohibited | Any non-local target; destructive actions beyond the lab |
| Data handling | No real PII; all data is seeded/synthetic |

> In a real engagement this section is a signed authorization that defines
> targets, timing, permitted techniques, emergency contacts, and handling of
> any sensitive data discovered. **Testing without it is illegal.**

---

## 2. Methodology

The assessment follows a phased approach aligned with the **OWASP Web Security
Testing Guide (WSTG)** and the **PTES** (Penetration Testing Execution
Standard).

### Phase 1 — Reconnaissance & information gathering
- Identify the technology stack (Flask/Werkzeug via the `Server` header and
  error pages — see JB-10).
- Enumerate endpoints and parameters (`/`, `/login`, `/search`, `/jobs/*`,
  `/application/<id>`, `/profile`, `/resume/*`, `/jobs/import`, `/health`).
- Note authentication boundaries and roles (`user` vs `admin`).

*Real-world tools:* `nmap`, `whatweb`, `ffuf`/`gobuster`, browser dev tools,
Burp Suite / OWASP ZAP passive scan.

### Phase 2 — Application mapping
- Walk every page authenticated and unauthenticated.
- Catalogue each input: query params, form fields, path segments, headers,
  cookies.
- Build a parameter inventory to drive injection testing.

### Phase 3 — Authentication & session testing
- Test the login for injection and logic flaws → **JB-01**.
- Inspect session management: cookie integrity, secret strength, flags → **JB-10**.
- Review password storage → **JB-09**.

### Phase 4 — Authorization testing
- Attempt horizontal access (one user reading another's objects) → **JB-05 IDOR**.
- Attempt vertical access (user reaching admin-only functions).

### Phase 5 — Input handling / injection
- SQL injection on every parameter (error-based, UNION-based) → **JB-01, JB-02**.
- Template injection on reflected/stored values → **JB-03 SSTI**.
- OS command injection on anything touching the shell/filesystem → **JB-04**.
- Cross-site scripting, stored and reflected → **JB-08**.
- Path traversal on file parameters → **JB-06**.
- SSRF on URL parameters → **JB-07**.

*Real-world tools:* Burp Suite Repeater/Intruder, `sqlmap`, custom scripts
(as in [`../exploits/`](../exploits/)).

### Phase 6 — Exploitation & impact validation
- Chain findings to demonstrate real impact (e.g. JB-02 + JB-09 → mass account
  takeover; JB-03/JB-04 → host compromise).
- Capture minimal, non-destructive proof for each.

### Phase 7 — Reporting
- Rate each finding by severity (impact × exploitability).
- Document reproduction, impact, and actionable remediation.
- Prioritize fixes (see [`REPORT.md`](REPORT.md) §5).

---

## 3. Severity model

Qualitative rating informed by CVSS base-metric thinking:

| Severity | Meaning |
|---|---|
| 🔴 Critical | Full system/account compromise; little/no privilege or auth required |
| 🟠 High | Significant data exposure or privilege escalation |
| 🟡 Medium | Meaningful impact requiring some preconditions |
| 🔵 Low | Limited direct impact; hardening / defence-in-depth |

---

## 4. Mapping to OWASP Top 10 (2021)

| OWASP category | Findings |
|---|---|
| A01 Broken Access Control | JB-05, JB-06 |
| A02 Cryptographic Failures | JB-09 |
| A03 Injection | JB-01, JB-02, JB-03, JB-04, JB-08 |
| A05 Security Misconfiguration | JB-10 |
| A10 Server-Side Request Forgery | JB-07 |

---

## 5. References
- OWASP Web Security Testing Guide (WSTG)
- OWASP Top 10 (2021)
- PTES — Penetration Testing Execution Standard
- CWE — Common Weakness Enumeration (cwe.mitre.org)
- MITRE ATT&CK (for mapping post-exploitation, where relevant)
