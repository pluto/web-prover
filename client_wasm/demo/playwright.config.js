const { defineConfig } = require('@playwright/test')

module.exports = defineConfig({
  testDir: './tests',
  timeout: 300000,
  use: {
    baseURL: 'https://localhost:8090',
    ignoreHTTPSErrors: true
  },
  webServer: {
    command: 'npm start',
    url: 'https://localhost:8090',
    reuseExistingServer: !process.env.CI,
    ignoreHTTPSErrors: true,
    timeout: 300000
  }
})
