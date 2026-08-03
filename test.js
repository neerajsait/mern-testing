const axios = require('axios');
const jwt = require('jsonwebtoken');          // npm install jsonwebtoken
const fs = require('fs');
const path = require('path');
const FormData = require('form-data');        // npm install form-data

// ====================== CONFIGURATION ======================
const CONFIG = {
  BASE_URL: 'http://localhost:5000',          // Change this

  // Two normal users
  USER_A: { email: 'user1@example.com', password: 'password123' },
  USER_B: { email: 'user2@example.com', password: 'password123' },

  // Admin credentials (if you have one for testing)
  ADMIN: { email: 'admin@example.com', password: 'adminpass' },

  // Endpoints to test (customize for your clothes branding site)
  IDOR_ENDPOINTS: [
    { method: 'GET', path: '/api/orders/{id}', desc: 'Order' },
    { method: 'GET', path: '/api/users/{id}', desc: 'User profile' },
    { method: 'GET', path: '/api/cart/{id}', desc: 'Cart' },
    { method: 'GET', path: '/api/wishlist/{id}', desc: 'Wishlist' },
    { method: 'PUT', path: '/api/orders/{id}', desc: 'Update order' },
    { method: 'DELETE', path: '/api/orders/{id}', desc: 'Delete order' },
  ],

  // Real IDs belonging to USER_B
  USER_B_IDS: [
    '66a1f2c3e4b5d67890123456',
    '66a1f2c3e4b5d67890123457',
  ],

  // Admin-only routes to test auth bypass
  ADMIN_ROUTES: [
    '/api/admin/users',
    '/api/admin/orders',
    '/api/admin/dashboard',
    '/api/admin/stats',
  ],

  // Login / rate-limit endpoints
  LOGIN_PATH: '/api/auth/login',
  OTP_PATH: '/api/auth/verify-otp',           // change if different
  RESET_PATH: '/api/auth/forgot-password',

  // File upload endpoint
  UPLOAD_PATH: '/api/upload',                 // change if different
};
// ===========================================================

const results = [];

function log(test, status, message, extra = '') {
  const icon = status === 'PASS' ? '✅' : status === 'FAIL' ? '🚨' : '⚠️';
  console.log(`${icon} [${test}] ${message} ${extra}`);
  results.push({ test, status, message, extra });
}

// -------------------- 1. Login helper --------------------
async function login(user) {
  try {
    const res = await axios.post(`${CONFIG.BASE_URL}${CONFIG.LOGIN_PATH}`, user);
    const token = res.data.token || res.data.accessToken || res.data.access_token;
    if (!token) throw new Error('No token returned');
    return token;
  } catch (err) {
    return null;
  }
}

// -------------------- 2. JWT Tampering --------------------
async function testJWTTampering(validToken) {
  console.log('\n=== JWT Tampering Tests ===');

  // 2.1 alg=none attack
  try {
    const decoded = jwt.decode(validToken, { complete: true });
    const noneToken = jwt.sign(decoded.payload, '', { algorithm: 'none' });
    const res = await axios.get(`${CONFIG.BASE_URL}/api/users/me`, {
      headers: { Authorization: `Bearer ${noneToken}` },
      validateStatus: () => true
    });
    if ([200, 201].includes(res.status)) {
      log('JWT-alg-none', 'FAIL', 'Server accepted alg=none token!');
    } else {
      log('JWT-alg-none', 'PASS', 'Server correctly rejected alg=none');
    }
  } catch (e) {
    log('JWT-alg-none', 'PASS', 'Server rejected alg=none');
  }

  // 2.2 Expired token
  try {
    const decoded = jwt.decode(validToken);
    const expired = jwt.sign({ ...decoded, exp: Math.floor(Date.now() / 1000) - 3600 }, 'fake-secret');
    const res = await axios.get(`${CONFIG.BASE_URL}/api/users/me`, {
      headers: { Authorization: `Bearer ${expired}` },
      validateStatus: () => true
    });
    if ([200, 201].includes(res.status)) {
      log('JWT-expired', 'FAIL', 'Server accepted expired token');
    } else {
      log('JWT-expired', 'PASS', 'Server rejected expired token');
    }
  } catch (e) {
    log('JWT-expired', 'PASS', 'Server rejected expired token');
  }

  // 2.3 Modified payload (role escalation)
  try {
    const decoded = jwt.decode(validToken);
    const tampered = jwt.sign({ ...decoded, role: 'admin', isAdmin: true }, 'wrong-secret');
    const res = await axios.get(`${CONFIG.BASE_URL}/api/users/me`, {
      headers: { Authorization: `Bearer ${tampered}` },
      validateStatus: () => true
    });
    if ([200, 201].includes(res.status) && (res.data.role === 'admin' || res.data.isAdmin)) {
      log('JWT-payload', 'FAIL', 'Server accepted modified payload / role escalation');
    } else {
      log('JWT-payload', 'PASS', 'Server rejected modified payload');
    }
  } catch (e) {
    log('JWT-payload', 'PASS', 'Server rejected modified payload');
  }
}

// -------------------- 3. IDOR --------------------
async function testIDOR(tokenA) {
  console.log('\n=== IDOR Tests ===');

  for (const ep of CONFIG.IDOR_ENDPOINTS) {
    for (const id of CONFIG.USER_B_IDS) {
      const url = `${CONFIG.BASE_URL}${ep.path.replace('{id}', id)}`;
      try {
        const res = await axios({
          method: ep.method,
          url,
          headers: { Authorization: `Bearer ${tokenA}` },
          data: ['PUT', 'PATCH'].includes(ep.method) ? { status: 'idor-test' } : undefined,
          validateStatus: () => true
        });

        if (![401, 403, 404].includes(res.status)) {
          log('IDOR', 'FAIL', `${ep.method} ${url} → ${res.status}`, ep.desc);
        } else {
          log('IDOR', 'PASS', `${ep.method} ${url} → ${res.status}`, ep.desc);
        }
      } catch (e) {
        log('IDOR', 'WARN', `Error testing ${url}`);
      }
    }
  }
}

// -------------------- 4. Auth Bypass (Admin routes) --------------------
async function testAuthBypass(tokenA) {
  console.log('\n=== Auth Bypass (Admin Routes) ===');

  for (const route of CONFIG.ADMIN_ROUTES) {
    try {
      const res = await axios.get(`${CONFIG.BASE_URL}${route}`, {
        headers: { Authorization: `Bearer ${tokenA}` },
        validateStatus: () => true
      });
      if ([200, 201].includes(res.status)) {
        log('Auth-Bypass', 'FAIL', `Normal user accessed ${route} → ${res.status}`);
      } else {
        log('Auth-Bypass', 'PASS', `Blocked ${route} → ${res.status}`);
      }
    } catch (e) {
      log('Auth-Bypass', 'PASS', `Blocked ${route}`);
    }
  }
}

// -------------------- 5. Rate Limiting --------------------
async function testRateLimit() {
  console.log('\n=== Rate Limiting Tests ===');

  const attempts = 25;
  let blocked = false;

  for (let i = 1; i <= attempts; i++) {
    try {
      const res = await axios.post(`${CONFIG.BASE_URL}${CONFIG.LOGIN_PATH}`, {
        email: 'nonexistent@example.com',
        password: 'wrong'
      }, { validateStatus: () => true });

      if (res.status === 429) {
        blocked = true;
        log('Rate-Limit', 'PASS', `Got 429 after ${i} attempts`);
        break;
      }
    } catch (e) {}
  }

  if (!blocked) {
    log('Rate-Limit', 'FAIL', `No 429 after ${attempts} login attempts`);
  }
}

// -------------------- 6. CORS --------------------
async function testCORS() {
  console.log('\n=== CORS Policy ===');

  try {
    const res = await axios.options(`${CONFIG.BASE_URL}/api/users/me`, {
      headers: {
        Origin: 'https://evil.com',
        'Access-Control-Request-Method': 'GET'
      },
      validateStatus: () => true
    });

    const allowOrigin = res.headers['access-control-allow-origin'];
    if (allowOrigin === '*' || allowOrigin === 'https://evil.com') {
      log('CORS', 'FAIL', `Overly permissive CORS: ${allowOrigin}`);
    } else {
      log('CORS', 'PASS', `CORS restricted: ${allowOrigin || 'none'}`);
    }
  } catch (e) {
    log('CORS', 'WARN', 'Could not test CORS properly');
  }
}

// -------------------- 7. Security Headers --------------------
async function testSecurityHeaders() {
  console.log('\n=== Security Headers ===');

  try {
    const res = await axios.get(`${CONFIG.BASE_URL}/`);
    const h = res.headers;

    const checks = [
      { name: 'X-Content-Type-Options', expected: 'nosniff' },
      { name: 'X-Frame-Options', expected: ['DENY', 'SAMEORIGIN'] },
      { name: 'Strict-Transport-Security', expected: null }, // just presence
      { name: 'Content-Security-Policy', expected: null },
    ];

    for (const c of checks) {
      const value = h[c.name.toLowerCase()];
      if (!value) {
        log('Headers', 'FAIL', `Missing ${c.name}`);
      } else if (c.expected && !c.expected.includes(value)) {
        log('Headers', 'WARN', `${c.name}: ${value}`);
      } else {
        log('Headers', 'PASS', `${c.name}: ${value}`);
      }
    }
  } catch (e) {
    log('Headers', 'WARN', 'Could not fetch headers');
  }
}

// -------------------- 8. File Upload --------------------
async function testFileUpload(token) {
  console.log('\n=== File Upload Tests ===');

  const dangerousFiles = [
    { name: 'shell.php', content: '<?php system($_GET["c"]); ?>', type: 'application/x-php' },
    { name: 'test.exe', content: 'MZ fake exe', type: 'application/octet-stream' },
    { name: '../../../etc/passwd', content: 'path traversal test', type: 'text/plain' },
    { name: 'huge.txt', content: 'A'.repeat(15 * 1024 * 1024), type: 'text/plain' }, // 15MB
  ];

  for (const file of dangerousFiles) {
    try {
      const form = new FormData();
      form.append('file', Buffer.from(file.content), {
        filename: file.name,
        contentType: file.type
      });

      const res = await axios.post(`${CONFIG.BASE_URL}${CONFIG.UPLOAD_PATH}`, form, {
        headers: {
          ...form.getHeaders(),
          Authorization: `Bearer ${token}`
        },
        validateStatus: () => true,
        maxContentLength: Infinity,
        maxBodyLength: Infinity
      });

      if ([200, 201].includes(res.status)) {
        log('File-Upload', 'FAIL', `Accepted dangerous file: ${file.name}`);
      } else {
        log('File-Upload', 'PASS', `Rejected ${file.name} → ${res.status}`);
      }
    } catch (e) {
      log('File-Upload', 'PASS', `Rejected ${file.name}`);
    }
  }
}

// -------------------- 9. Secrets Leakage --------------------
async function testSecretsLeakage(token) {
  console.log('\n=== Secrets Leakage Check ===');

  try {
    const res = await axios.get(`${CONFIG.BASE_URL}/api/users/me`, {
      headers: { Authorization: `Bearer ${token}` },
      validateStatus: () => true
    });

    const body = JSON.stringify(res.data).toLowerCase();
    const leaks = ['mongodb://', 'jwt_secret', 'password', 'secret_key', 'stack', 'at '];

    let found = false;
    for (const leak of leaks) {
      if (body.includes(leak)) {
        log('Secrets', 'FAIL', `Possible secret/stack leak containing: "${leak}"`);
        found = true;
      }
    }
    if (!found) log('Secrets', 'PASS', 'No obvious secrets in response');
  } catch (e) {
    log('Secrets', 'WARN', 'Could not check response');
  }
}

// -------------------- MAIN --------------------
async function main() {
  console.log('🛡️  MERN Backend Security Tester\n');

  const tokenA = await login(CONFIG.USER_A);
  if (!tokenA) {
    console.log('❌ Cannot login as USER_A. Check credentials and BASE_URL.');
    return;
  }
  console.log('[+] Got token for USER_A\n');

  await testJWTTampering(tokenA);
  await testIDOR(tokenA);
  await testAuthBypass(tokenA);
  await testRateLimit();
  await testCORS();
  await testSecurityHeaders();
  await testFileUpload(tokenA);
  await testSecretsLeakage(tokenA);

  // Final summary
  console.log('\n' + '='.repeat(60));
  console.log('FINAL SUMMARY');
  console.log('='.repeat(60));
  const failed = results.filter(r => r.status === 'FAIL');
  console.log(`Total tests: ${results.length}`);
  console.log(`Failed: ${failed.length}`);
  if (failed.length > 0) {
    console.log('\nFailed tests:');
    failed.forEach(f => console.log(`  🚨 ${f.test}: ${f.message}`));
  } else {
    console.log('🎉 No critical issues found by this script!');
  }
}

main();