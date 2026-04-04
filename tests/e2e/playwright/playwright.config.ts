import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright configuration for forwardauth-rs E2E tests.
 *
 * The test stack uses Docker Compose. All service hostnames resolve to
 * 127.0.0.1 on the CI runner via /etc/hosts. Port 80 is Traefik (the entry
 * point for the protected application).
 */
export default defineConfig({
  testDir: './tests',

  // Fail fast in CI; run tests serially (single worker) to avoid cookie races.
  workers: 1,
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  reporter: [['list'], ['html', { open: 'never' }]],

  use: {
    // Traefik entry point. Uses localhost so cookies avoid the Secure flag
    // (forwardauth skips Secure for localhost, and we run over plain HTTP).
    baseURL: 'http://localhost',

    // Follow redirects — the full OIDC flow is a redirect chain.
    // Playwright's page.goto() follows all HTTP redirects automatically.

    // Allow extra time for the complete OIDC redirect round-trip.
    navigationTimeout: 30_000,
    actionTimeout:     15_000,

    // Single browser: Chromium (amd64-compatible, fast)
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  outputDir: './test-results',
});
