const fs = require('fs')
const path = require('path')

// Read Cargo.toml and extract version
const cargoPath = path.resolve(__dirname, '../../../Cargo.toml')
const cargoContent = fs.readFileSync(cargoPath, 'utf8')
const versionMatch = cargoContent.match(/web_prover_circuits_version\s*=\s*"([^"]+)"/)
if (!versionMatch || versionMatch.length < 1) {
	throw new Error("Could not parse Cargo.toml's web_prover_circuits_version variable")
}
const version = versionMatch[1];

// Generate config.js with the version
const configContent = `// Generated file - do not edit directly
export const WEB_PROVER_CIRCUITS_VERSION = '${version}'
`

const configPath = path.resolve(__dirname, '../js/config.js')
fs.writeFileSync(configPath, configContent)
