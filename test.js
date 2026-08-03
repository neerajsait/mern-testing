const axios = require('axios');
const jwt = require('jsonwebtoken');
const FormData = require('form-data');

// ====================== CONFIGURATION ======================
const CONFIG = {
  BASE_URL: 'http://localhost:5000',

  USER_A: { email: 'user1@example.com', password: 'password123' },
  USER_B: { email: 'user2@example.com', password: 'password123' },

  // Endpoints that contain an ID
  IDOR_ENDPOINTS: [
    { method: 'GET',    path: '/api/orders/{id}',     desc: 'Order' },
    { method: 'GET',    path: '/api/users/{id}',      desc: 'User profile' },
    { method: 'GET',    path: '/api/cart/{id}',       desc: 'Cart' },
    { method: 'GET',    path: '/api/wishlist/{id}',   desc: 'Wishlist' },
    { method: 'PUT',    path: '/api/orders/{id}',     desc: 'Update order' },
    { method: 'DELETE', path: '/api/orders/{id}',     desc: 'Delete order' },
  ],

  // Real IDs that belong to USER_B
  USER_B_IDS: [
    '66a1f2c3e4b5d67890123456',
    '66a1f2c3e4b5d67890123457',
  ],

  // Admin-only routes
  ADMIN_ROUTES: [
    '/api/admin/users',
    '/api/admin/orders',
    '/api/admin/dashboard',
    '/api/admin/stats',
  ],

  // Protected routes (should reject requests without token)
  PROTECTED_ROUTES: [
    '/api/users/me',
    '/api/orders',
    '/api/cart',
    '/api/wishlist',
  ],

  // Auth endpoints for rate-limit testing
  LOGIN_PATH: '/api/auth/login',
  OTP_PATH: '/api/auth/verify-otp',
  RESET_PATH: '/api/auth/forgot-password',

  UPLOAD_PATH: '/api/upload',
};
// ===========================================================

const results = [];

function log(test, status, message, extra = '') {
  const icon = status === 'PASS' ? '✅' : status === 'FAIL' ? '🚨' : '⚠️';
  console.log(`${icon} [${test}] ${message}${extra ? ' → ' + extra : ''}`);
  results.push({ test, status, message, extra });
}

// -------------------- Login Helper --------------------
async function login(user) {
  try {
    const res = await axios.post(`${CONFIG.BASE_URL}${CONFIG.LOGIN_PATH}`, user);
    const token = res.data.token || res.data.accessToken || res.data.access_token || res.data.jwt;
    if (!token) throw new Error('No token found in response');
    return token;
  } catch (err) {
    console.log(`[!] Login failed for ${user.email}:`, err.response?.data?.message || err.message);
    return null;
  }
}

// -------------------- 1. Improved JWT Tests --------------------
async function testJWT(validToken) {
  console.log('\n=== JWT Security Tests ===');

  const decoded = jwt.decode(validToken, { complete: true });
  if (!decoded) {
    log('JWT', 'WARN', 'Could not decode token');
    return;
  }

  // 1.1 alg = none attack (most important)
  try {
    // Create a proper "none" token
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify(decoded.payload)).toString('base64url');
    const noneToken = `${header}.${payload}.`;

    const res = await axios.get(`${CONFIG.BASE_URL}/api/users/me`, {
      headers: { Authorization: `Bearer ${noneToken}` },
      validateStatus: () => true
    });

    if ([200, 201].includes(res.status)) {
      log('JWT-alg-none', 'FAIL', 'Server accepted alg=none token');
    } else {
      log('JWT-alg-none', 'PASS', `Rejected alg=none → ${res.status}`);
    }
  } catch (e) {
    log('JWT-alg-none', 'PASS', 'Rejected alg=none');
  }

  // 1.2 Completely invalid / garbage token
  try {
    const res = await axios.get(`${CONFIG.BASE_URL}/api/users/me`, {
      headers: { Authorization: 'Bearer FAKE.TOKEN.VALUE' },
      validateStatus: () => true
    });
    if ([200, 201].includes(res.status)) {
      log('JWT-invalid', 'FAIL', 'Server accepted invalid token');
    } else {
      log('JWT-invalid', 'PASS', `Rejected invalid token → ${res.status}`);
    }
  } catch (e) {
    log('JWT-invalid', 'PASS', 'Rejected invalid token');
  }

  // 1.3 Missing signature part
  try {
    const parts = validToken.split('.');
    const noSigToken = `${parts[0]}.${parts[1]}.`;
    const res = await axios.get(`${CONFIG.BASE_URL}/api/users/me`, {
      headers: { Authorization: `Bearer ${noSigToken}` },
      validateStatus: () => true
    });
    if ([200, 201].includes(res.status)) {
      log('JWT-no-signature', 'FAIL', 'Server accepted token without signature');
    } else {
      log('JWT-no-signature', 'PASS', `Rejected unsigned token → ${res.status}`);
    }
  } catch (e) {
    log('JWT-no-signature', 'PASS', 'Rejected unsigned token');
  }

  // 1.4 Role / privilege claim manipulation attempt
  // (We can't re-sign without the secret, so we test if the server trusts the claim blindly after decoding)
  try {
    const tamperedPayload = { ...decoded.payload, role: 'admin', isAdmin: true, isAdminUser: true };
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify(tamperedPayload)).toString('base64url');
    const tamperedNone = `${header}.${payload}.`;

    const res = await axios.get(`${CONFIG.BASE_URL}/api/users/me`, {
      headers: { Authorization: `Bearer ${tamperedNone}` },
      validateStatus: () => true
    });

    if ([200, 201].includes(res.status) && (res.data?.role === 'admin' || res.data?.isAdmin)) {
      log('JWT-role-escalation', 'FAIL', 'Server accepted elevated role via alg=none');
    } else {
      log('JWT-role-escalation', 'PASS', 'Role escalation via alg=none blocked');
    }
  } catch (e) {
    log('JWT-role-escalation', 'PASS', 'Role escalation blocked');
  }
}

// -------------------- 2. Unauthenticated Access --------------------
async function testUnauthenticated() {
  console.log('\n=== Unauthenticated Access Tests ===');

  const routesToTest = [...CONFIG.PROTECTED_ROUTES, ...CONFIG.ADMIN_ROUTES];

  for (const route of routesToTest) {
    try {
      const res = await axios.get(`${CONFIG.BASE_URL}${route}`, {
        validateStatus: () => true
      });

      if ([200, 201].includes(res.status)) {
        log('Unauth', 'FAIL', `Accessible without token → ${route}`, res.status);
      } else {
        log('Unauth', 'PASS', `Blocked without token → ${route}`, res.status);
      }
    } catch (e) {
      log('Unauth', 'PASS', `Blocked without token → ${route}`);
    }
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
          log('IDOR', 'FAIL', `${ep.method} ${url}`, `${res.status} (${ep.desc})`);
        } else {
          log('IDOR', 'PASS', `${ep.method} ${url}`, `${res.status} (${ep.desc})`);
        }
      } catch (e) {
        log('IDOR', 'WARN', `Error → ${url}`);
      }
    }
  }
}

// -------------------- 4. Auth Bypass (with valid user token) --------------------
async function testAuthBypass(tokenA) {
  console.log('\n=== Auth Bypass (Normal user → Admin routes) ===');

  for (const route of CONFIG.ADMIN_ROUTES) {
    try {
      const res = await axios.get(`${CONFIG.BASE_URL}${route}`, {
        headers: { Authorization: `Bearer ${tokenA}` },
        validateStatus: () => true
      });

      if ([200, 201].includes(res.status)) {
        log('Auth-Bypass', 'FAIL', `Normal user accessed ${route}`, res.status);
      } else {
        log('Auth-Bypass', 'PASS', `Blocked ${route}`, res.status);
      }
    } catch (e) {
      log('Auth-Bypass', 'PASS', `Blocked ${route}`);
    }
  }
}

// -------------------- 5. Rate Limiting (Login + OTP + Reset) --------------------
async function testRateLimit() {
  console.log('\n=== Rate Limiting Tests ===');

  const endpoints = [
    { name: 'Login', path: CONFIG.LOGIN_PATH, body: { email: 'test@evil.com', password: 'wrong' } },
    { name: 'OTP', path: CONFIG.OTP_PATH, body: { email: 'test@evil.com', otp: '000000' } },
    { name: 'Password-Reset', path: CONFIG.RESET_PATH, body: { email: 'test@evil.com' } },
  ];

  for (const ep of endpoints) {
    let blocked = false;
    const maxAttempts = 20;

    for (let i = 1; i <= maxAttempts; i++) {
      try {
        const res = await axios.post(`${CONFIG.BASE_URL}${ep.path}`, ep.body, {
          validateStatus: () => true
        });

        if (res.status === 429) {
          blocked = true;
          log('Rate-Limit', 'PASS', `${ep.name} blocked after ${i} attempts`);
          break;
        }
      } catch (e) {}
    }

    if (!blocked) {
      log('Rate-Limit', 'FAIL', `${ep.name} → No 429 after ${maxAttempts} attempts`);
    }
  }
}

// -------------------- 6. CORS --------------------
async function testCORS() {
  console.log('\n=== CORS Policy ===');

  try {
    const res = await axios.options(`${CONFIG.BASE_URL}/api/users/me`, {
      headers: {
        'Origin': 'https://evil-attacker.com',
        'Access-Control-Request-Method': 'GET'
      },
      validateStatus: () => true
    });

    const allowOrigin = res.headers['access-control-allow-origin'];
    if (allowOrigin === '*' || allowOrigin === 'https://evil-attacker.com') {
      log('CORS', 'FAIL', `Permissive CORS: ${allowOrigin}`);
    } else {
      log('CORS', 'PASS', `CORS is restricted: ${allowOrigin || 'not set'}`);
    }
  } catch (e) {
    log('CORS', 'WARN', 'Could not fully test CORS');
  }
}

// -------------------- 7. Security Headers --------------------
async function testSecurityHeaders() {
  console.log('\n=== Security Headers ===');

  try {
    const res = await axios.get(CONFIG.BASE_URL);
    const h = res.headers;

    const required = [
      { name: 'x-content-type-options', expected: 'nosniff' },
      { name: 'x-frame-options', expected: ['DENY', 'SAMEORIGIN'] },
      { name: 'strict-transport-security' },
      { name: 'content-security-policy' },
    ];

    for (const item of required) {
      const value = h[item.name];
      if (!value) {
        log('Headers', 'FAIL', `Missing → ${item.name}`);
      } else if (item.expected && !item.expected.includes(value)) {
        log('Headers', 'WARN', `${item.name}: ${value}`);
      } else {
        log('Headers', 'PASS', `${item.name}: ${value}`);
      }
    }
  } catch (e) {
    log('Headers', 'WARN', 'Could not fetch headers');
  }
}

// -------------------- 8. File Upload --------------------
async function testFileUpload(token) {
  console.log('\n=== File Upload Tests ===');

  const files = [
    { name: 'shell.php', content: '<?php system($_GET["cmd"]); ?>', type: 'application/x-php' },
    { name: 'test.exe', content: 'MZ', type: 'application/octet-stream' },
    { name: '../../../etc/passwd', content: 'path-traversal-test', type: 'text/plain' },
  ];

  for (const file of files) {
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
        validateStatus: () => true
      });

      if ([200, 201].includes(res.status)) {
        log('File-Upload', 'FAIL', `Accepted → ${file.name}`);
      } else {
        log('File-Upload', 'PASS', `Rejected → ${file.name} (${res.status})`);
      }
    } catch (e) {
      log('File-Upload', 'PASS', `Rejected → ${file.name}`);
    }
  }
}

// -------------------- 9. Secrets Leakage --------------------
async function testSecrets(token) {
  console.log('\n=== Secrets Leakage ===');

  try {
    const res = await axios.get(`${CONFIG.BASE_URL}/api/users/me`, {
      headers: { Authorization: `Bearer ${token}` },
      validateStatus: () => true
    });

    const body = JSON.stringify(res.data).toLowerCase();
    const dangerous = ['mongodb://', 'jwt_secret', 'secret_key', 'password', 'stack', 'at object'];

    let found = false;
    for (const word of dangerous) {
      if (body.includes(word)) {
        log('Secrets', 'FAIL', `Possible leak containing "${word}"`);
        found = true;
      }
    }
    if (!found) log('Secrets', 'PASS', 'No obvious secrets found');
  } catch (e) {
    log('Secrets', 'WARN', 'Could not check response body');
  }
}

// -------------------- MAIN --------------------
async function main() {
  console.log('🛡️  Improved MERN Backend Security Tester\n');

  const tokenA = await login(CONFIG.USER_A);
  if (!tokenA) {
    console.log('❌ Failed to login as USER_A. Please check credentials and BASE_URL.');
    return;
  }
  console.log('[+] Successfully logged in as USER_A\n');

  await testJWT(tokenA);
  await testUnauthenticated();
  await testIDOR(tokenA);
  await testAuthBypass(tokenA);
  await testRateLimit();
  await testCORS();
  await testSecurityHeaders();
  await testFileUpload(tokenA);
  await testSecrets(tokenA);

  // Summary
  console.log('\n' + '='.repeat(65));
  console.log('FINAL SUMMARY');
  console.log('='.repeat(65));

  const failed = results.filter(r => r.status === 'FAIL');
  const passed = results.filter(r => r.status === 'PASS');
  const warnings = results.filter(r => r.status === 'WARN');

  console.log(`Total checks : ${results.length}`);
  console.log(`Passed      : ${passed.length}`);
  console.log(`Failed      : ${failed.length}`);
  console.log(`Warnings    : ${warnings.length}`);

  if (failed.length > 0) {
    console.log('\n🚨 Failed Tests:');
    failed.forEach(f => console.log(`   • ${f.test}: ${f.message} ${f.extra || ''}`));
  } else {
    console.log('\n🎉 No critical issues found by this script!');
  }
}

main();
