import { defineConfig, devices } from '@playwright/test';

// The cloud dev container ships a pre-installed Chromium; fall back to Playwright's own
// download location everywhere else.
const executablePath = process.env.PW_CHROMIUM_PATH;

const allBrowsers = !!process.env.PW_ALL_BROWSERS;
const viewport = { width: 1440, height: 900 };

export default defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  fullyParallel: false,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: 'http://127.0.0.1:4173',
    trace: 'retain-on-failure',
    // The app's service worker is blocked by default so tests always exercise fresh files;
    // the offline test opts back in.
    serviceWorkers: 'block',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'], viewport, launchOptions: executablePath ? { executablePath } : {} } },
    // Firefox and WebKit: PW_ALL_BROWSERS=1 after `npx playwright install firefox webkit` (CI runs them as a non-blocking step).
    ...(allBrowsers
      ? [
          { name: 'firefox', use: { ...devices['Desktop Firefox'], viewport } },
          { name: 'webkit', use: { ...devices['Desktop Safari'], viewport } },
        ]
      : []),
  ],
  webServer: {
    command: 'npm run build && npx vite preview --port 4173 --strictPort --host 127.0.0.1',
    url: 'http://127.0.0.1:4173',
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
  },
});
