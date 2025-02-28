const { spawn } = require('child_process');

const DEFAULT_MODE = "tee"

const mode = process.argv[2] || DEFAULT_MODE; // Default to tee if no argument provided
process.env.MODE = mode;

// Run the playwright test
spawn('npx', ['playwright', 'test', '--browser=chromium'], {
    stdio: 'inherit',
    env: process.env
});