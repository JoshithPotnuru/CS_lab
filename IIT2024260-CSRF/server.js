const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = 3000;

// Determine execution mode: Secure mode if '--secure' argument or MODE=secure env var is provided
const isSecure = process.argv.includes('--secure') || process.env.MODE === 'secure';
const MODE_NAME = isSecure ? 'SECURE MODE' : 'VULNERABLE MODE';

// Global in-memory balances
let balances = {
  koushik: 1000,
  attacker: 0
};

// Parse URL-encoded bodies and JSON
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Configure Session Cookie based on security mode
if (isSecure) {
  // SECURE MODE: HttpOnly enabled, SameSite=Strict enabled
  app.use(session({
    secret: 'secure-super-secret-key-iit2024260',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'strict', // Prevents browser from sending cookie on cross-site requests
      secure: false,      // Set to false for localhost HTTP testing
      maxAge: 3600000
    }
  }));
} else {
  // VULNERABLE MODE: SameSite disabled (or false), HttpOnly disabled
  // Permissive CORS headers so cross-origin GET requests can interact during demonstration
  app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', req.headers.origin || 'http://localhost:3001');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') {
      return res.sendStatus(200);
    }
    next();
  });

  app.use(session({
    secret: 'vulnerable-insecure-secret-key-iit2024260',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: false,
      sameSite: false, // Cookie sent in cross-site contexts
      secure: false,
      maxAge: 3600000
    }
  }));
}

// Ensure CSRF token is generated and attached to session in secure mode
app.use((req, res, next) => {
  if (isSecure && req.session && req.session.user && !req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  next();
});

// Basic CSS template used across views
const getStyles = () => `
  body {
    font-family: Arial, sans-serif;
    margin: 0;
    padding: 20px;
    background-color: #f7f9fb;
    color: #333;
  }
  .container {
    max-width: 650px;
    margin: 20px auto;
    background: #ffffff;
    padding: 25px 30px;
    border-radius: 8px;
    border: 1px solid #dcdfe6;
    box-shadow: 0 2px 8px rgba(0,0,0,0.06);
  }
  .banner {
    padding: 12px 18px;
    border-radius: 6px;
    font-weight: bold;
    font-size: 14px;
    margin-bottom: 20px;
    text-align: center;
  }
  .banner-vulnerable {
    background-color: #fff3cd;
    color: #856404;
    border: 1px solid #ffeeba;
  }
  .banner-secure {
    background-color: #d4edda;
    color: #155724;
    border: 1px solid #c3e6cb;
  }
  .header {
    border-bottom: 2px solid #eaeaea;
    padding-bottom: 12px;
    margin-bottom: 20px;
  }
  .header h1 {
    margin: 0 0 6px 0;
    font-size: 24px;
    color: #1a1a1a;
  }
  .meta {
    font-size: 13px;
    color: #666;
    line-height: 1.4;
  }
  .balance-card {
    display: flex;
    justify-content: space-around;
    background-color: #f8f9fa;
    border: 1px solid #e9ecef;
    border-radius: 6px;
    padding: 16px;
    margin-bottom: 25px;
    text-align: center;
  }
  .balance-item h3 {
    margin: 0 0 5px 0;
    font-size: 15px;
    color: #555;
  }
  .balance-item .amount {
    font-size: 24px;
    font-weight: bold;
    color: #2c3e50;
  }
  .form-group {
    margin-bottom: 16px;
  }
  label {
    display: block;
    margin-bottom: 6px;
    font-weight: bold;
    font-size: 14px;
  }
  input[type="text"], input[type="password"], input[type="number"], select {
    width: 100%;
    padding: 10px;
    border: 1px solid #ccc;
    border-radius: 4px;
    box-sizing: border-box;
    font-size: 14px;
  }
  button {
    background-color: #0066cc;
    color: white;
    border: none;
    padding: 10px 18px;
    font-size: 14px;
    border-radius: 4px;
    cursor: pointer;
    font-weight: bold;
  }
  button:hover {
    background-color: #0052a3;
  }
  .btn-secondary {
    background-color: #6c757d;
  }
  .btn-secondary:hover {
    background-color: #5a6268;
  }
  .btn-danger {
    background-color: #dc3545;
  }
  .btn-danger:hover {
    background-color: #bd2130;
  }
  .action-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-top: 25px;
    padding-top: 15px;
    border-top: 1px solid #eee;
  }
  .alert-box {
    padding: 10px 15px;
    border-radius: 4px;
    margin-bottom: 15px;
    font-size: 14px;
  }
  .alert-success {
    background-color: #d1e7dd;
    color: #0f5132;
    border: 1px solid #badbcc;
  }
  .alert-error {
    background-color: #f8d7da;
    color: #842029;
    border: 1px solid #f5c2c7;
  }
  .token-info {
    font-size: 12px;
    font-family: monospace;
    background: #f1f3f5;
    padding: 6px 10px;
    border-radius: 4px;
    word-break: break-all;
    margin-top: 6px;
  }
`;

// ==========================================
// ROUTES
// ==========================================

// Dashboard (Protected)
app.get('/', (req, res) => {
  if (!req.session || !req.session.user) {
    return res.redirect('/login');
  }

  const alertMsg = req.query.msg ? `<div class="alert-box alert-success">${req.query.msg}</div>` : '';
  const errorMsg = req.query.error ? `<div class="alert-box alert-error">${req.query.error}</div>` : '';

  const bannerHtml = isSecure
    ? `<div class="banner banner-secure">🔒 SECURE MODE ACTIVE — State-changing GET blocked (HTTP 405), SameSite=Strict enabled, CSRF protection active</div>`
    : `<div class="banner banner-vulnerable">⚠️ VULNERABLE MODE ACTIVE — GET-based transfer permitted, No CSRF token, SameSite disabled</div>`;

  const csrfFieldHtml = isSecure
    ? `<input type="hidden" name="_csrf" value="${req.session.csrfToken || ''}">
       <div class="form-group">
         <label>Active CSRF Token (Node.js crypto):</label>
         <div class="token-info">${req.session.csrfToken || 'None'}</div>
       </div>`
    : ``;

  const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>KIK National Bank - Dashboard</title>
      <style>${getStyles()}</style>
    </head>
    <body>
      <div class="container">
        ${bannerHtml}
        
        <div class="header">
          <h1>KIK National Bank</h1>
          <div class="meta">
            Logged in as: <strong>${req.session.user.username}</strong>
          </div>
        </div>

        ${alertMsg}
        ${errorMsg}

        <div class="balance-card">
          <div class="balance-item">
            <h3>Koushik's Balance</h3>
            <div class="amount" id="koushik-balance">₹${balances.koushik}</div>
          </div>
          <div class="balance-item">
            <h3>Attacker's Balance</h3>
            <div class="amount" id="attacker-balance">₹${balances.attacker}</div>
          </div>
        </div>

        <h3>Transfer Money</h3>
        <form action="/transfer" method="POST">
          ${csrfFieldHtml}
          <div class="form-group">
            <label for="to">Recipient Account:</label>
            <input type="text" id="to" name="to" value="attacker" required>
          </div>

          <div class="form-group">
            <label for="amount">Amount (₹):</label>
            <input type="number" id="amount" name="amount" value="500" min="1" max="${balances.koushik}" required>
          </div>

          <button type="submit">Transfer Funds</button>
        </form>

        <div class="action-row">
          <form action="/reset" method="POST" style="margin: 0;">
            <button type="submit" class="btn-secondary">Reset Balances (₹1000 / ₹0)</button>
          </form>
          <a href="/logout"><button type="button" class="btn-danger">Logout</button></a>
        </div>
      </div>
    </body>
    </html>
  `;

  res.send(html);
});

// Login Page
app.get('/login', (req, res) => {
  if (req.session && req.session.user) {
    return res.redirect('/');
  }

  const errorHtml = req.query.error === 'invalid'
    ? `<div class="alert-box alert-error">Invalid username or password. Please use demo credentials.</div>`
    : '';

  const bannerHtml = isSecure
    ? `<div class="banner banner-secure">🔒 SECURE MODE — Running on Port ${PORT}</div>`
    : `<div class="banner banner-vulnerable">⚠️ VULNERABLE MODE — Running on Port ${PORT}</div>`;

  const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Login - KIK National Bank</title>
      <style>${getStyles()}</style>
    </head>
    <body>
      <div class="container">
        ${bannerHtml}

        <div class="header">
          <h1>KIK National Bank Login</h1>
          <div class="meta">
            Secure Online Banking Portal
          </div>
        </div>

        ${errorHtml}

        <form action="/login" method="POST">
          <div class="form-group">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" value="koushik" required>
          </div>

          <div class="form-group">
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" value="Koushik@Secure2026" required>
          </div>

          <button type="submit">Sign In</button>
        </form>

        <div class="meta" style="margin-top: 20px; background: #eef2f7; padding: 10px; border-radius: 4px;">
          <strong>Demo Credentials:</strong><br>
          Username: <code>koushik</code><br>
          Password: <code>Koushik@Secure2026</code>
        </div>
      </div>
    </body>
    </html>
  `;

  res.send(html);
});

// Login POST Handler
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (username === 'koushik' && password === 'Koushik@Secure2026') {
    req.session.user = { username: 'koushik' };
    if (isSecure) {
      req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    console.log(`[AUTH] Koushik successfully logged in. Mode: ${MODE_NAME}`);
    return res.redirect('/');
  }

  console.log(`[AUTH FAILED] Failed login attempt with username: ${username}`);
  return res.redirect('/login?error=invalid');
});

// Logout Handler
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    console.log(`[AUTH] User logged out.`);
    res.redirect('/login');
  });
});

// Reset Balances
app.all('/reset', (req, res) => {
  balances.koushik = 1000;
  balances.attacker = 0;
  console.log(`[RESET] Balances restored: Koushik = ₹${balances.koushik}, Attacker = ₹${balances.attacker}`);

  if (req.accepts('html')) {
    return res.redirect('/?msg=Balances+successfully+reset+to+₹1000+and+₹0.');
  }
  res.json({ success: true, balances });
});

// Balances API (Useful for verification scripts)
app.get('/api/balances', (req, res) => {
  res.json(balances);
});

// ==========================================
// STATE-CHANGING GET ENDPOINT (VULNERABILITY CORE)
// ==========================================
app.get('/transfer', (req, res) => {
  // SECURE MODE PROTECTION: Reject state-changing GET requests with HTTP 405 Method Not Allowed
  if (isSecure) {
    console.log(`[SECURITY ALERT - 405 BLOCKED] State-changing GET /transfer request rejected with HTTP 405 Method Not Allowed.`);
    res.status(405);
    res.set('Allow', 'POST');
    return res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>405 Method Not Allowed</title><style>${getStyles()}</style></head>
      <body>
        <div class="container">
          <div class="banner banner-secure">🔒 HTTP 405 METHOD NOT ALLOWED</div>
          <h2>State-Changing GET Request Blocked</h2>
          <p>In <strong>Secure Mode</strong>, state-changing operations are strictly forbidden via HTTP GET requests.</p>
          <p>RFC 7231 specifies that GET requests must remain idempotent and safe (read-only). Transfers must use POST with a valid CSRF token.</p>
          <a href="/"><button type="button">Back to Banking Dashboard</button></a>
        </div>
      </body>
      </html>
    `);
  }

  // VULNERABLE MODE: Check authentication
  if (!req.session || !req.session.user) {
    console.log(`[TRANSFER REJECTED] Unauthenticated GET /transfer attempt.`);
    return res.status(401).send(`
      <!DOCTYPE html>
      <html>
      <head><title>401 Unauthorized</title><style>${getStyles()}</style></head>
      <body>
        <div class="container">
          <h2>401 Unauthorized</h2>
          <p>You must be logged in to transfer money.</p>
          <a href="/login"><button type="button">Go to Login</button></a>
        </div>
      </body>
      </html>
    `);
  }

  // Parse transfer parameters from query string
  const to = req.query.to || 'attacker';
  const amount = parseInt(req.query.amount, 10) || 500;

  if (isNaN(amount) || amount <= 0) {
    return res.status(400).send('Invalid transfer amount.');
  }

  if (balances.koushik < amount) {
    return res.status(400).send('Insufficient funds in Koushik account.');
  }

  // Execute state modification via GET
  balances.koushik -= amount;
  balances[to] = (balances[to] || 0) + amount;

  console.log(`[VULNERABLE GET TRANSFER] Koushik transferred ₹${amount} to ${to}. New Balances => Koushik: ₹${balances.koushik}, Attacker: ₹${balances.attacker}`);

  // Response allows browser or hidden image tag to complete
  return res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Transfer Success</title><style>${getStyles()}</style></head>
    <body>
      <div class="container">
        <div class="banner banner-vulnerable">⚠️ GET-BASED FORGED TRANSFER PROCESSED</div>
        <h2>Transfer Successful (GET)</h2>
        <p>Transferred <strong>₹${amount}</strong> to <strong>${to}</strong>.</p>
        <div class="balance-card">
          <div class="balance-item"><h3>Koushik Balance</h3><div class="amount">₹${balances.koushik}</div></div>
          <div class="balance-item"><h3>Attacker Balance</h3><div class="amount">₹${balances.attacker}</div></div>
        </div>
        <a href="/"><button type="button">Return to Dashboard</button></a>
      </div>
    </body>
    </html>
  `);
});

// ==========================================
// STATE-CHANGING POST ENDPOINT
// ==========================================
app.post('/transfer', (req, res) => {
  // Check authentication
  if (!req.session || !req.session.user) {
    console.log(`[TRANSFER REJECTED] Unauthenticated POST /transfer attempt.`);
    return res.status(401).send(`
      <!DOCTYPE html>
      <html>
      <head><title>401 Unauthorized</title><style>${getStyles()}</style></head>
      <body>
        <div class="container">
          <h2>401 Unauthorized</h2>
          <p>You must be logged in to transfer funds.</p>
          <a href="/login"><button type="button">Go to Login</button></a>
        </div>
      </body>
      </html>
    `);
  }

  // SECURE MODE PROTECTION: Validate CSRF Token
  if (isSecure) {
    const submittedToken = req.body._csrf || req.headers['x-csrf-token'];
    const expectedToken = req.session.csrfToken;

    if (!submittedToken || submittedToken !== expectedToken) {
      console.log(`[SECURITY ALERT - 403 FORBIDDEN] Missing or invalid CSRF token on POST /transfer.`);
      console.log(`  Expected:  ${expectedToken}`);
      console.log(`  Submitted: ${submittedToken || '(none provided)'}`);
      
      return res.status(403).send(`
        <!DOCTYPE html>
        <html>
        <head><title>403 Forbidden - CSRF Protection</title><style>${getStyles()}</style></head>
        <body>
          <div class="container">
            <div class="banner banner-secure">🔒 HTTP 403 FORBIDDEN — CSRF VALIDATION FAILED</div>
            <h2>Request Rejected</h2>
            <p>The state-changing POST request was rejected because the submitted CSRF token was missing or invalid.</p>
            <p><strong>Security Detail:</strong> The Synchronizer Token Pattern requires a cryptographically random token per session that cross-origin attackers cannot guess or read.</p>
            <a href="/"><button type="button">Back to Banking Dashboard</button></a>
          </div>
        </body>
        </html>
      `);
    }

    console.log(`[SECURE VALIDATION SUCCESS] Valid CSRF token verified.`);
  }

  // Process transfer
  const to = req.body.to || 'attacker';
  const amount = parseInt(req.body.amount, 10) || 500;

  if (isNaN(amount) || amount <= 0) {
    return res.redirect('/?error=Invalid+transfer+amount.');
  }

  if (balances.koushik < amount) {
    return res.redirect('/?error=Insufficient+funds.');
  }

  balances.koushik -= amount;
  balances[to] = (balances[to] || 0) + amount;

  const modeLabel = isSecure ? 'SECURE POST TRANSFER' : 'VULNERABLE POST TRANSFER';
  console.log(`[${modeLabel}] Koushik transferred ₹${amount} to ${to}. New Balances => Koushik: ₹${balances.koushik}, Attacker: ₹${balances.attacker}`);

  return res.redirect(`/?msg=Successfully+transferred+₹${amount}+to+${to}.`);
});

// Start Server
app.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(` Bank Application running at: http://localhost:${PORT}`);
  console.log(` Current Mode: [${MODE_NAME}]`);
  console.log(` Initial Balances => Koushik: ₹${balances.koushik}, Attacker: ₹${balances.attacker}`);
  console.log(`====================================================`);
});
