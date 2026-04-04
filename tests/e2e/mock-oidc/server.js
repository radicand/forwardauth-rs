'use strict';

/**
 * Minimal OIDC provider for forwardauth-rs end-to-end testing.
 *
 * Implements just enough of the OIDC spec to satisfy forwardauth-rs:
 *   GET  /.well-known/openid-configuration  → discovery document
 *   GET  /.well-known/jwks.json             → RSA public key (JWKS)
 *   GET  /authorize                         → auto-approve; redirect with code
 *   POST /oauth/token                       → exchange code for RS256 JWTs
 *   GET  /userinfo                          → user claims JSON
 *   GET  /logout                            → redirect to returnTo
 *
 * All tokens are signed with a 2048-bit RSA key generated at startup.
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('node:crypto');

// ── Configuration ─────────────────────────────────────────────────────────────
// ISSUER must match the `domain` field in forwardauth-rs application.yaml
// (including the trailing slash).
const ISSUER     = process.env.ISSUER      || 'http://mock-oidc:4444/';
const CLIENT_ID  = process.env.CLIENT_ID   || 'e2e-client';
const AUDIENCE   = process.env.AUDIENCE    || 'http://mock-oidc:4444/api';
const PORT       = parseInt(process.env.PORT || '4444', 10);

// Fixed test user
const TEST_USER = {
  sub:   'test-user-123',
  email: 'test@example.com',
  name:  'E2E Test User',
};

// ── Key generation ────────────────────────────────────────────────────────────
const KID = 'e2e-key-1';
const { privateKey: PRIVATE_KEY_PEM, publicKey: PUBLIC_KEY_PEM } =
  crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding:  { type: 'spki',  format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

// Export public key as JWK for the JWKS endpoint
const PUBLIC_JWK = {
  ...crypto.createPublicKey(PUBLIC_KEY_PEM).export({ format: 'jwk' }),
  kid: KID,
  use: 'sig',
  alg: 'RS256',
};

// ── In-memory auth-code store ─────────────────────────────────────────────────
// Maps code → { redirect_uri, state }  — codes expire in 60s
const CODES = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [code, entry] of CODES.entries()) {
    if (now > entry.expiresAt) CODES.delete(code);
  }
}, 10_000);

// ── Helpers ───────────────────────────────────────────────────────────────────
function issueTokens() {
  const accessToken = jwt.sign(
    { email: TEST_USER.email, name: TEST_USER.name, permissions: [] },
    PRIVATE_KEY_PEM,
    {
      algorithm: 'RS256',
      keyid:     KID,
      issuer:    ISSUER,
      subject:   TEST_USER.sub,
      audience:  AUDIENCE,
      expiresIn: 3600,
    },
  );

  const idToken = jwt.sign(
    { email: TEST_USER.email, name: TEST_USER.name },
    PRIVATE_KEY_PEM,
    {
      algorithm: 'RS256',
      keyid:     KID,
      issuer:    ISSUER,
      subject:   TEST_USER.sub,
      audience:  CLIENT_ID,
      expiresIn: 3600,
    },
  );

  return { accessToken, idToken };
}

// ── Express app ───────────────────────────────────────────────────────────────
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// OIDC discovery document
app.get('/.well-known/openid-configuration', (_req, res) => {
  const base = ISSUER.replace(/\/$/, '');
  res.json({
    issuer:                                ISSUER,
    authorization_endpoint:                `${base}/authorize`,
    token_endpoint:                        `${base}/oauth/token`,
    jwks_uri:                              `${base}/.well-known/jwks.json`,
    userinfo_endpoint:                     `${base}/userinfo`,
    response_types_supported:              ['code'],
    subject_types_supported:               ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported:                      ['openid', 'profile', 'email'],
    grant_types_supported:                 ['authorization_code'],
  });
});

// JWKS endpoint — exposes RSA public key so forwardauth-rs can verify tokens
app.get('/.well-known/jwks.json', (_req, res) => {
  res.json({ keys: [PUBLIC_JWK] });
});

// Authorization endpoint — immediately auto-approves by redirecting with a code.
// In a real provider this would show a login form.
app.get('/authorize', (req, res) => {
  const { redirect_uri, state } = req.query;
  if (!redirect_uri) {
    return res.status(400).send('missing redirect_uri');
  }

  const code = crypto.randomBytes(16).toString('hex');
  CODES.set(code, {
    redirectUri: redirect_uri,
    state:       state || '',
    expiresAt:   Date.now() + 60_000,
  });

  const callbackUrl = new URL(redirect_uri);
  callbackUrl.searchParams.set('code',  code);
  if (state) callbackUrl.searchParams.set('state', state);

  return res.redirect(302, callbackUrl.toString());
});

// Token endpoint — exchange authorization code for access_token + id_token
app.post('/oauth/token', (req, res) => {
  const { grant_type, code } = req.body;

  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }
  if (!code || !CODES.has(code)) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'Unknown or expired code' });
  }

  CODES.delete(code);
  const { accessToken, idToken } = issueTokens();

  return res.json({
    access_token: accessToken,
    id_token:     idToken,
    token_type:   'Bearer',
    expires_in:   3600,
  });
});

// Userinfo endpoint
app.get('/userinfo', (_req, res) => {
  res.json(TEST_USER);
});

// Logout endpoint
app.get('/logout', (req, res) => {
  const returnTo = req.query.returnTo || req.query.return_to || '/';
  // Validate redirect target to prevent open redirect (CWE-601).
  // In this test mock, only allow relative paths or known test hosts.
  try {
    const parsed = new URL(returnTo, `http://${req.headers.host}`);
    const allowedHosts = [req.headers.host, 'localhost', 'forwardauth', 'nginx', 'traefik'];
    if (!allowedHosts.some(h => parsed.hostname === h || parsed.hostname.endsWith(`.${h}`))) {
      console.warn(`Blocked redirect to disallowed host: ${parsed.hostname}`);
      return res.redirect(302, '/');
    }
  } catch {
    return res.redirect(302, '/');
  }
  res.redirect(302, returnTo);
});

// ── Start server ──────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Mock OIDC provider listening on port ${PORT}`);
  console.log(`  Issuer:   ${ISSUER}`);
  console.log(`  Audience: ${AUDIENCE}`);
  console.log(`  Discovery: http://localhost:${PORT}/.well-known/openid-configuration`);
});
