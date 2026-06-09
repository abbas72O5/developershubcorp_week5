# WEEK 5 — Ethical Hacking & Exploitation (Brief)

**Internship Domain:** Cybersecurity  
**Project:** User Management System  
**Week:** 5 — Ethical hacking, exploitation testing, and mitigation

---

## Introduction
This week focused on ethical penetration testing in a controlled environment to discover weaknesses and apply fixes. Activities included reconnaissance, automated exploitation attempts, and implementing server-side mitigations for discovered issues.

---

## Tasks Completed

1. Ethical Hacking Basics
- Used Kali Linux toolset and recon tools (nmap, dirb, Nikto) against a local test instance.
- Collected open ports, service banners, and discovered exposed endpoints for further testing.

2. SQL Injection & Exploitation
- Ran SQLMap against suspected endpoints to probe for injectable parameters.
- Confirmed no SQL injection present in this project (MongoDB backend), but documented findings and applied best-practice mitigations for SQL-based backends.
- Implemented prepared statements / parameterized queries in example SQL code to demonstrate prevention.

Example (Node.js + mysql2 prepared statement):
```js
// mysql2 example - parameterized query prevents SQLi
const mysql = require('mysql2/promise');
const conn = await mysql.createConnection({ host:'127.0.0.1', user:'app', database:'test' });
const [rows] = await conn.execute('SELECT * FROM users WHERE email = ?', [email]);
```

3. Cross-Site Request Forgery (CSRF) Protection
- Implemented `csurf` middleware for server-rendered forms (signup, login, profile, logout).
- Injected `_csrf` hidden fields into forms and validated tokens on POST handlers.
- Added friendly 403 handler for invalid CSRF tokens.

Key CSRF snippet (server-side):
```js
const csrf = require('csurf');
const csrfProtection = csrf();
router.use(csrfProtection);
// in rendered form:
<form method="POST" action="/login">
  <input type="hidden" name="_csrf" value="${req.csrfToken()}">
  ...
</form>
```

---

## Testing & Validation (Burp Suite)
- Intercepted POST requests to `/signup` and `/login` with Burp Suite.
- Test 1: Remove `_csrf` parameter → server returns HTTP 403 (CSRF token missing/invalid).
- Test 2: Modify `_csrf` token to invalid value → server returns HTTP 403.
- Test 3: Replay request with valid `_csrf` → request succeeds.
- For SQLi: ran SQLMap against endpoints; where applicable, confirmed parameterized queries block injection.

---

## Outcomes
- Reconnaissance identified surface-level exposure for targeted testing only (no exploitation of sensitive endpoints).
- CSRF protection added to all server-rendered forms; Burp Suite tests validated the control.
- Documented SQLi prevention patterns (parameterized queries) for any parts of the stack using SQL databases.
- Logging and monitoring in place to detect suspicious exploitation attempts.

---

## Next Steps
- Integrate automated security scans (ZAP/Burp) into CI for test environments.
- If migrating to or integrating SQL services, apply parameterized queries and input validation across all data access layers.
- Add active alerting on repeated 403 CSRF failures and suspicious scanning activity in `security.log`.

---

## Conclusion
Week 5 combined hands-on offensive testing with immediate defensive improvements. The app now resists CSRF-based attacks for form flows and has documented best practices to prevent SQL injection in SQL-backed components.
