# mern testing

> This file is used for MERN stack security testing

Built with JavaScript.

## About this project

This repository is part of **Neeraj Sai's** growing collection of software projects, experiments, and learning builds. It reflects a practical, curious approach to creating useful products and understanding how they work under the hood.

## Getting started

Clone the repository and follow the setup instructions for the project's framework or language:

```bash
git clone https://github.com/neerajsait/mern-testing.git
cd mern-testing
```

Check the project files for the available run commands and configuration requirements.

## Links

[Repository](https://github.com/neerajsait/mern-testing)

## Author

**Tiruveedhi Neeraj Venkata Sai**

- GitHub: [@neerajsait](https://github.com/neerajsait)
- Portfolio: [neeraj's portfolio](https://github.com/neerajsait/portfoliomain)


## Existing project documentation

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
