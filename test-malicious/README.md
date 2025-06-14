# Malicious Package Test Cases

This directory contains test cases demonstrating various malicious package attack vectors that Typosentinel should detect.

## Attack Vectors Demonstrated

### 1. Typosquatting
- **Package Name**: `lodahs` (mimics `lodash`)
- **Technique**: Similar name to popular package with slight misspelling
- **Risk**: Users may accidentally install this instead of the legitimate package

### 2. Malicious Postinstall Scripts
- **File**: `malicious.js`
- **Execution**: Runs automatically after `npm install`
- **Actions**:
  - Environment variable harvesting (tokens, keys, secrets)
  - File system reconnaissance (.ssh, .aws directories)
  - Network interface enumeration
  - Process listing
  - Data exfiltration to hidden files
  - Persistence mechanisms (bashrc modification)

### 3. Code Injection on Import
- **File**: `index.js`
- **Technique**: Executes malicious code when package is required/imported
- **Actions**:
  - System information collection
  - Silent data writing to temp directories
  - Disguised as legitimate utility functions

## Detection Strategies

### Static Analysis Indicators
1. **Suspicious API Usage**:
   - `os.userInfo()`, `os.hostname()`, `process.env`
   - File system operations in sensitive directories
   - Network interface access
   - Process execution (`execSync`)

2. **Behavioral Patterns**:
   - Postinstall scripts with system calls
   - Hidden file creation (dotfiles in temp/home directories)
   - Environment variable enumeration
   - SSH/AWS directory access

3. **Package Metadata**:
   - Name similarity to popular packages
   - Suspicious author information
   - Unusual dependency patterns

### Dynamic Analysis Indicators
1. **File System Activity**:
   - Creation of hidden files in temp directories
   - Access to sensitive configuration directories
   - Modification of shell configuration files

2. **Network Activity**:
   - Outbound connections to suspicious domains
   - Data exfiltration attempts

3. **Process Behavior**:
   - Spawning of unexpected child processes
   - System command execution

## Testing with Typosentinel

```bash
# Test local package scanning
./typosentinel scan --local ./test-malicious/package.json --verbose

# Test with different output formats
./typosentinel scan --local ./test-malicious/package.json --format table
./typosentinel scan --local ./test-malicious/package.json --format yaml

# Generate detailed report
./typosentinel scan --local ./test-malicious/package.json --save-report --output malicious-test-report.json
```

## Expected Detection Results

Typosentinel should identify:
- High risk score due to suspicious system calls
- Typosquatting similarity to 'lodash'
- Malicious postinstall script patterns
- Environment variable access
- File system reconnaissance activities
- Potential data exfiltration mechanisms

## Mitigation Recommendations

1. **Package Name Verification**: Always verify package names carefully
2. **Dependency Auditing**: Regular security audits of dependencies
3. **Sandboxed Installation**: Use containerized environments for testing
4. **Permission Restrictions**: Limit file system and network access
5. **Monitoring**: Implement runtime monitoring for suspicious activities

---

**Note**: This is a demonstration package for security testing purposes only. Do not use in production environments.