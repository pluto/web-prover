const { test, expect } = require('@playwright/test')

test('should generate proof', async ({ page }) => {
  test.setTimeout(300000)

  // Add page error handler
  page.on('pageerror', (error) => {
    console.error('Page error:', error.message)
  })

  // Add more detailed console logging
  page.on('console', (msg) => {
    const text = msg.text()
    console.log(`Browser console [${msg.type()}]:`, text)
  })

  // Create a promise that will resolve when we see the proof
  const proofPromise = new Promise((resolve) => {
    page.on('console', (msg) => {
      console.log('console', msg.text())
      if (msg.text().startsWith('proof generated!')) {
        resolve(msg.text())
      }
    })
  })

  // Go to the page
  await page.goto('/')
  console.log('page loaded')

  // Wait for initialization
  await page
    .waitForFunction(
      () => {
        return window.witness !== undefined
      },
      { timeout: 30000 }
    )
    .catch((e) => {
      console.error('Witness initialization failed:', e)
      throw e
    })

  // Wait for the proof message
  const proofMessage = await Promise.race([
    proofPromise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout waiting for proof')), 300000))
  ])

  // Verify we got the proof
  expect(proofMessage).toContain('proof generated!')
})
