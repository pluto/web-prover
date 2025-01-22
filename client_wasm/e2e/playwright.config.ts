import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: '.',
  use: {
    browserName: 'chromium',
    headless: true,
    ignoreHTTPSErrors: true,
    navigationTimeout: 30000,
    contextOptions: {
      ignoreHTTPSErrors: true
    }
  },
  projects: [
    {
      name: 'Chromium',
      use: {
        ...devices['Desktop Chrome'],
        ignoreHTTPSErrors: true,
        launchOptions: {
          args: ['--ignore-certificate-errors', '--ignore-certificate-errors-spki-list', '--ignore-ssl-errors']
        }
      }
    }
  ]
})
