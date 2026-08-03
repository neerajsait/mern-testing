# MERN Backend Security Tester

A practical Node.js security testing script for any MERN (MongoDB + Express + React + Node.js) backend.

It focuses on high-impact vulnerabilities that are commonly missed by basic scanners.

---

## 📁 Project Structure

```text
mern-backend-security-tester/
│
├── README.md                     # Documentation
├── package.json                  # Project metadata
├── package-lock.json             # Dependency lock file
├── .gitignore
├── .env.example                  # Example configuration
│
├── mern-security-tester.js       # Main security testing script
│
├── payloads/                     # Optional payload files
│   ├── jwt.txt
│   ├── filenames.txt
│   ├── traversal.txt
│   └── passwords.txt
│
├── reports/                      # Generated reports
│   ├── latest-report.json
│   ├── latest-report.html
│   └── latest-report.txt
│
├── logs/                         # Runtime logs
│   └── tester.log
│
└── temp/                         # Temporary upload files
    └── ...
```

---

## Features

| Category | What it tests | Status |
|-----------|---------------|--------|
| JWT Security | `alg=none`, invalid token, missing signature, role escalation attempt | Automated |
| Unauthenticated Access | Protected & admin routes without any token | Automated |
| IDOR | Access another user's orders, profile, cart, etc. | Automated |
| Auth Bypass | Normal user accessing admin routes | Automated |
| Rate Limiting | Login + OTP + Password Reset endpoints | Automated |
| CORS | Overly permissive CORS policy | Automated |
| Security Headers | X-Content-Type-Options, X-Frame-Options, HSTS, CSP | Automated |
| File Upload | Dangerous extensions + path traversal | Automated |
| Secrets Leakage | JWT secrets, DB strings, stack traces in responses | Automated |

...
