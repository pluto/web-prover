import express from 'express'
import https from 'https'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()
const PORT = 3000

// Set COOP/COEP to allow SharedArrayBuffer usage in Chrome
app.use((_req, res, next) => {
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin')
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp')
  next()
})

console.log('dirname', __dirname)

app.use(express.static(path.join(__dirname, '../public')))
// app.use('/pkg', express.static(path.join(__dirname, '../../pkg')))
app.use('/pkg', express.static(path.join(__dirname, '../pkg')))

const options = {
  key: fs.readFileSync(path.join(__dirname, '../../fixture/certs/server-key.pem')),
  cert: fs.readFileSync(path.join(__dirname, '../../fixture/certs/server-cert.pem'))
}

https.createServer(options, app).listen(PORT, () => {
  console.log(`HTTPS server running at https://localhost:${PORT}`)
})
