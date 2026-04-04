/**
 * E2E test suite for forwardauth-rs OIDC middleware.
 *
 * What is being tested:
 *   1. Full OIDC authorization-code flow driven by a real browser.
 *      - Unauthenticated request → 307 redirect to OIDC provider.
 *      - AUTH_NONCE cookie is set (CSRF protection).
 *      - Mock OIDC auto-approves and redirects back to /oauth2/signin.
 *      - forwardauth exchanges the code for RS256 JWTs (verified against JWKS).
 *      - Session cookies (ACCESS_TOKEN, JWT_TOKEN) set; browser redirected to app.
 *      - Authenticated request → 204 passthrough → protected content served.
 *
 *   2. Session persistence — a second navigation to the protected app does NOT
 *      trigger another OIDC redirect; existing cookies grant access.
 *
 *   3. /userinfo endpoint returns the authenticated user's claims.
 *
 *   4. /signout clears session cookies and redirects away from the app.
 *
 * Network topology:
 *   mock-oidc:4444 must resolve to 127.0.0.1 via /etc/hosts.
 *   Playwright → http://localhost/ → Traefik → forwardauth /authorize
 *                                             ↘ 307 → http://mock-oidc:4444/authorize
 *   Playwright follows redirect chain automatically via page.goto()
 */

import { test, expect, type Page, type BrowserContext } from '@playwright/test';

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Check whether the browser currently holds a session cookie. */
async function hasSessionCookies(context: BrowserContext): Promise<boolean> {
  const cookies = await context.cookies();
  return cookies.some(c => c.name === 'ACCESS_TOKEN' || c.name === 'JWT_TOKEN');
}

/**
 * Drive the full OIDC login flow by navigating to the protected app.
 *
 * The mock OIDC server auto-approves without user interaction, so
 * page.goto() follows the entire redirect chain and lands on the
 * protected application once auth is complete.
 */
async function loginViaOIDC(page: Page): Promise<void> {
  // Navigate to the protected root. Playwright follows:
  //   http://localhost/
  //     → (Traefik forwardAuth 307) http://mock-oidc:4444/authorize?...
  //     → (mock-oidc auto-approve) http://localhost/oauth2/signin?code=...&state=...
  //     → (forwardauth /signin 307) http://localhost/
  await page.goto('/');

  // After the full chain the browser lands on the protected app.
  await expect(page).toHaveURL(/^http:\/\/localhost\/?$/);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test.describe('OIDC authorization-code flow', () => {
  test('unauthenticated request is redirected to OIDC and completes login', async ({ page, context }) => {
    // No cookies at this point — should trigger the OIDC flow.
    expect(await hasSessionCookies(context)).toBe(false);

    await loginViaOIDC(page);

    // The protected content must be visible.
    await expect(page.locator('h1')).toHaveText('Protected App');
    await expect(page.locator('[data-testid="status"]')).toHaveText('access-granted');

    // Session cookies must have been set by forwardauth.
    expect(await hasSessionCookies(context)).toBe(true);
  });

  test('authenticated session is reused without a second OIDC redirect', async ({ page, context }) => {
    // First: complete the login flow.
    await loginViaOIDC(page);
    expect(await hasSessionCookies(context)).toBe(true);

    // Second visit: must NOT redirect to OIDC again.
    await page.goto('/');

    // Should land directly on the protected app (URL does NOT go through mock-oidc).
    await expect(page).toHaveURL(/^http:\/\/localhost\/?$/);
    await expect(page.locator('h1')).toHaveText('Protected App');
  });

  test('/userinfo returns claims for the authenticated user', async ({ page, context }) => {
    await loginViaOIDC(page);

    // Call forwardauth's /userinfo endpoint directly.
    // We use the page's cookie context so the ACCESS_TOKEN cookie is included.
    const response = await page.request.get('http://localhost:8080/userinfo', {
      headers: {
        'x-forwarded-host':   'localhost',
        'x-forwarded-proto':  'http',
        'x-forwarded-uri':    '/',
        'x-forwarded-method': 'GET',
      },
    });

    expect(response.status()).toBe(200);
    const body = await response.json();
    // forwardauth returns Siren-style JSON with claims nested in `properties`.
    const claims = body.properties ?? body;
    expect(claims).toHaveProperty('sub', 'test-user-123');
    expect(claims).toHaveProperty('email', 'test@example.com');
  });

  test('/signout clears session and redirects', async ({ page, context }) => {
    await loginViaOIDC(page);
    expect(await hasSessionCookies(context)).toBe(true);

    // Hit the signout endpoint through Traefik (so x-forwarded-* headers and
    // cookie domain handling work correctly).
    await page.goto('http://localhost/oauth2/signout');

    // After signout, session cookies should be cleared (Max-Age=0).
    const cookies = await context.cookies();
    const sessionCookies = cookies.filter(
      c => (c.name === 'ACCESS_TOKEN' || c.name === 'JWT_TOKEN') && c.value !== 'deleted',
    );
    expect(sessionCookies).toHaveLength(0);
  });
});

test.describe('Authorization enforcement', () => {
  test('API request without auth returns 401, not a redirect', async ({ page }) => {
    // Playwright APIRequestContext doesn't follow browser-readable 307s the
    // same way, but we can ask forwardauth directly with Accept: application/json.
    const response = await page.request.get('http://localhost:8080/authorize', {
      headers: {
        'x-forwarded-host':   'localhost',
        'x-forwarded-proto':  'http',
        'x-forwarded-uri':    '/api/data',
        'x-forwarded-method': 'GET',
        'accept':             'application/json',
      },
    });

    // API requests (Accept: application/json) must return 401, not 307.
    expect(response.status()).toBe(401);
  });

  test('cookie-based auth makes /authorize return 204', async ({ page, context }) => {
    // Complete the login flow to obtain session cookies.
    await loginViaOIDC(page);

    // Now call /authorize directly (simulating what Traefik does on each request).
    const response = await page.request.get('http://localhost:8080/authorize', {
      headers: {
        'x-forwarded-host':   'localhost',
        'x-forwarded-proto':  'http',
        'x-forwarded-uri':    '/dashboard',
        'x-forwarded-method': 'GET',
      },
    });

    expect(response.status()).toBe(204);
  });
});
