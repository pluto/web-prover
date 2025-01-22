import { test, expect } from '@playwright/test'

test.describe('WASM concurrency + Worker test', () => {
  test('should init, initThreadPool, and setup_tracing in a Worker', async ({ page }) => {
    await page.goto('https://localhost:3000/test.html', { waitUntil: 'networkidle' })

    page.on('console', (msg) => {
      console.log('PAGE LOG:', msg.text())
    })

    const result = await page.evaluate(() => window.runWasmTest())
    expect(result).toBe('worker success')
  })
})
