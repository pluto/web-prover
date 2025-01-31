const fs = require('fs')
const path = require('path')

// Read Cargo.toml and extract version
const cargoPath = path.resolve(__dirname, '../../../Cargo.toml')
const cargoContent = fs.readFileSync(cargoPath, 'utf8')
// const versionMatch = cargoContent.match(/serde_json\s*=\s*"([^"]+)"/)
const versionMatch = cargoContent.match(/web_prover_circuits_version\s*=\s*"([^"]+)"/)
const version = versionMatch ? versionMatch[1] : '0.8.0'

// Generate config.js with the version
const configContent = `// Generated file - do not edit directly
export const WEB_PROVER_VERSION = '${version}'
`

const configPath = path.resolve(__dirname, '../js/config.js')
fs.writeFileSync(configPath, configContent)
