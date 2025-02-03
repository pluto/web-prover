const { test, expect } = require('@playwright/test')

test('should generate proof', async ({ page }) => {
  test.setTimeout(300000) // 5 min

  // Add page error handler
  page.on('pageerror', (error) => {
    console.error('pageerror:', error.message)
  })

  // Add more detailed console logging
  page.on('console', (msg) => {
    console.log(`console [${msg.type()}]:`, msg.text())
  })

  // Go to the page
  await page.goto('/')
  console.log('page loaded')

  // Wait for initialization (30 sec)
  await page.waitForFunction(
    () => window.witness !== undefined,
    { timeout: 30000 }
  ).catch((e) => {
    console.error('Witness initialization failed:', e);
    throw e;
  });

  // Wait for the proof message (5 min)
  await page.waitForEvent('console', {
    timeout: 300000, // will fail test if timeout hits
    predicate: (msg) => msg.text().startsWith('proof generated!')
  });
})
