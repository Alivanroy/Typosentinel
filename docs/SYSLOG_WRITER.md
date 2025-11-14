# Syslog Writer

- RFC 5424-compliant formatting
- Levels: DEBUG, INFO, WARNING, ERROR, CRITICAL mapped to standard syslog
- Fields: timestamp, hostname, application name, process id, message id
- Destinations: UDP, TCP, TLS, stdout, file path
- Thread-safe buffered writes

## Configuration
- protocol: `udp|tcp|tls`
- address: `host:port`
- app_name: application identifier
- hostname: override host name
- facility: `user|local0|...` or integer
- stdout: boolean
- file_path: path to log file

## Example
```
NewSyslogAuditWriter(map[string]interface{}{
  "protocol": "udp",
  "address": "127.0.0.1:514",
  "app_name": "typosentinel",
  "facility": "local0",
})
```

