# MERN Backend Security Tester

A single Node.js script to quickly test common security issues in any MERN (MongoDB + Express + React + Node.js) backend.

It focuses on the most critical and frequently missed vulnerabilities that automated scanners often fail to catch properly.

---

# 📁 Project Structure

```
mern-security-tester/
│
├── mern-security-tester.js      # Main security testing script
├── package.json                 # Project metadata & dependencies
├── package-lock.json            # Auto-generated dependency lock file
├── .env.example                 # Example environment variables
├── .gitignore                   # Files ignored by Git
├── README.md                    # Documentation
│
├── payloads/                    # Test payloads
│   ├── jwt.txt
│   ├── upload-filenames.txt
│   └── common-passwords.txt
│
├── uploads/                     # Temporary files created during tests
│   └── (temporary files)
│
├── reports/                     # Generated reports
│   ├── report.json
│   ├── report.html
│   └── report.txt
│
└── logs/
    └── tester.log
```

---

# Features

- JWT Security Testing
- IDOR Detection
- Authentication Bypass Checks
- Rate Limiting Tests
- Security Header Validation
- CORS Validation
- File Upload Testing
- Secret Leakage Detection
- HTML & JSON Report Generation
- Colorized CLI Output

---

# What It Tests

| Category | Tests Performed | Status |
|-----------|----------------|--------|
| JWT Security | alg=none, expired token, payload tampering, role escalation | ✅ Automated |
| IDOR | Access another user's resources | ✅ Automated |
| Authentication | Admin route access with normal user | ✅ Automated |
| Rate Limiting | Login brute force | ✅ Automated |
| CORS | Wildcard origin, credentials | ✅ Automated |
| Security Headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options | ✅ Automated |
| File Upload | Dangerous extensions, traversal, oversized files | ✅ Automated |
| Secrets Leakage | JWT secrets, stack traces, DB URLs | ✅ Automated |

---

# Requirements

- Node.js 18+
- npm
- Running MERN Backend
- Two normal user accounts
- One admin account (optional but recommended)

---

# Installation

```bash
git clone <your-repository>

cd mern-security-tester

npm install
```

Or install manually

```bash
npm install axios jsonwebtoken form-data dotenv chalk ora cli-table3
```

---

# Configuration

Create a `.env` file using `.env.example`

Example:

```env
BASE_URL=http://localhost:5000

USER_A_EMAIL=user1@example.com
USER_A_PASSWORD=password123

USER_B_EMAIL=user2@example.com
USER_B_PASSWORD=password123

ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=admin123

LOGIN_PATH=/api/auth/login
UPLOAD_PATH=/api/upload
```

Or edit the CONFIG object directly inside `mern-security-tester.js`.

---

# Example Configuration

```javascript
const CONFIG = {
    BASE_URL: "http://localhost:5000",

    USER_A: {
        email: "user1@example.com",
        password: "password123"
    },

    USER_B: {
        email: "user2@example.com",
        password: "password123"
    },

    ADMIN: {
        email: "admin@example.com",
        password: "admin123"
    },

    LOGIN_PATH: "/api/auth/login",

    UPLOAD_PATH: "/api/upload",

    ADMIN_ROUTES: [
        "/api/admin/users",
        "/api/admin/orders",
        "/api/admin/dashboard"
    ],

    IDOR_ENDPOINTS: [
        {
            method: "GET",
            path: "/api/orders/{id}",
            desc: "Orders"
        },
        {
            method: "GET",
            path: "/api/users/{id}",
            desc: "User Profile"
        }
    ],

    USER_B_IDS: [
        "66a1f2c3e4b5d67890123456",
        "66a1f2c3e4b5d67890123457"
    ]
};
```

---

# Running

```bash
node mern-security-tester.js
```

---

# Sample Output

```text
🛡 MERN Backend Security Tester

✔ Logged in as USER_A

==========================
JWT TESTS
==========================

✔ alg=none rejected
✔ expired token rejected
✖ modified payload accepted

==========================
IDOR TESTS
==========================

✖ GET /orders/66a1... returned 200

✔ GET /users/66a1... returned 403

==========================
SUMMARY
==========================

Tests Run : 28

Passed    : 25

Failed    : 3

Warnings  : 0
```

---

# Reports

After execution the tester generates:

```
reports/

report.json
report.html
report.txt
```

These can be attached to bug reports or penetration testing documentation.

---

# PASS / FAIL Meaning

| Result | Meaning |
|---------|----------|
| ✅ PASS | Endpoint is properly protected |
| 🚨 FAIL | Vulnerability detected |
| ⚠ WARNING | Manual verification required |

---

# Limitations

This tool intentionally focuses on common backend security mistakes.

It does **NOT** replace a complete penetration test.

Additional testing should include:

| Test | Recommended Tool |
|------|-------------------|
| SQL Injection | sqlmap |
| NoSQL Injection | Manual + Burp Suite |
| Stored XSS | OWASP ZAP |
| Reflected XSS | OWASP ZAP |
| CSRF | OWASP ZAP |
| Dependency Scan | npm audit |
| SAST | Semgrep |
| TLS Configuration | testssl.sh |
| Business Logic | Manual Review |
| Race Conditions | Manual Testing |
| Session Management | Burp Suite |

---

# Recommended Workflow

1. Run this tester.
2. Fix all FAIL results.
3. Run npm audit.
4. Run Semgrep.
5. Crawl using OWASP ZAP.
6. Run sqlmap on user-controlled endpoints.
7. Perform manual privilege escalation testing.
8. Verify production HTTPS configuration.
9. Review logs and generated reports.

---

# Dependencies

```
axios
jsonwebtoken
form-data
dotenv
chalk
ora
cli-table3
fs
path
crypto
```

---

# Contributing

Contributions are welcome.

Feel free to improve:

- New security checks
- Better reporting
- More payloads
- Faster scanning
- Framework-specific plugins

---

# Disclaimer

This tool is intended **only** for testing systems that you own or have explicit authorization to assess.

Unauthorized testing of third-party systems may be illegal and unethical.

Use responsibly.

---

# License

MIT License
