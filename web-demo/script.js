// Navigation functionality
const navToggle = document.querySelector('.nav-toggle');
const navMenu = document.querySelector('.nav-menu');

navToggle.addEventListener('click', () => {
    navMenu.classList.toggle('active');
});

// Close mobile menu when clicking on a link
navMenu.addEventListener('click', (e) => {
    if (e.target.tagName === 'A') {
        navMenu.classList.remove('active');
    }
});

// Smooth scrolling for navigation links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});
    
    // CLI Command Execution
    function executeCommand(command) {
        addCliLine(command, 'command');
        
        const parts = command.split(' ');
        const mainCmd = parts[0];
        
        if (mainCmd === 'help') {
            showHelp();
        } else if (mainCmd === 'typosentinel') {
            handleTyposentinelCommand(parts.slice(1));
        } else if (mainCmd === 'clear') {
            clearCli();
        } else {
            addCliLine(`Command not found: ${mainCmd}. Type 'help' for available commands.`, 'error');
        }
    }
    
    function addCliLine(text, type = 'text') {
        const line = document.createElement('div');
        line.className = 'cli-line';
        
        if (type === 'command') {
            line.innerHTML = `<span class="cli-prompt">$</span><span class="cli-command">${text}</span>`;
        } else {
            const className = type === 'error' ? 'cli-error' : 
                             type === 'success' ? 'cli-success' : 
                             type === 'warning' ? 'cli-warning' : 
                             type === 'info' ? 'cli-info' : 
                             type === 'json' ? 'cli-json' : 'cli-text';
            line.innerHTML = `<span class="cli-prompt"></span><span class="${className}">${text}</span>`;
        }
        
        cliOutput.appendChild(line);
        cliOutput.scrollTop = cliOutput.scrollHeight;
    }
    
    function showHelp() {
        const helpText = `Available commands:

typosentinel scan <package>     - Scan a single package
typosentinel bulk-scan <pkg1,pkg2,...> - Scan multiple packages
typosentinel stats             - Show scan statistics
typosentinel health            - Check API health
clear                          - Clear terminal
help                           - Show this help

Examples:
  typosentinel scan lodash
  typosentinel scan malicious-package
  typosentinel bulk-scan lodash,requests,beautifulsoup`;
        
        addCliLine(helpText, 'info');
    }
    
    function clearCli() {
        cliOutput.innerHTML = `
            <div class="cli-line">
                <span class="cli-prompt">$</span>
                <span class="cli-text">Terminal cleared</span>
            </div>
        `;
    }
    
    async function handleTyposentinelCommand(args) {
        if (args.length === 0) {
            addCliLine('Usage: typosentinel <command> [options]', 'error');
            addCliLine('Type "help" for available commands', 'info');
            return;
        }
        
        const subCommand = args[0];
        
        switch (subCommand) {
            case 'scan':
                if (args.length < 2) {
                    addCliLine('Usage: typosentinel scan <package-name>', 'error');
                    return;
                }
                await scanPackage(args[1]);
                break;
                
            case 'bulk-scan':
                if (args.length < 2) {
                    addCliLine('Usage: typosentinel bulk-scan <package1,package2,...>', 'error');
                    return;
                }
                const packages = args[1].split(',').map(p => p.trim());
                await bulkScanPackages(packages);
                break;
                
            case 'stats':
                await getStats();
                break;
                
            case 'health':
                await checkHealth();
                break;
                
            default:
                addCliLine(`Unknown typosentinel command: ${subCommand}`, 'error');
                addCliLine('Type "help" for available commands', 'info');
        }
    }
    
    async function scanPackage(packageName) {
        addCliLine(`Scanning package: ${packageName}`, 'info');
        addCliLine('Initiating scan...', 'loading');
        
        try {
            // Simulate API delay
            await new Promise(resolve => setTimeout(resolve, 1000));
            
            // Use mock data instead of API call - try multiple ecosystems
            let mockResult = getMockScanResult(packageName, 'npm');
            let ecosystem = 'npm';
            
            // If not found in npm, try other ecosystems
            if (!mockResult) {
                const ecosystems = ['pypi', 'go', 'maven', 'nuget', 'rubygems'];
                for (const eco of ecosystems) {
                    mockResult = getMockScanResult(packageName, eco);
                    if (mockResult) {
                        ecosystem = eco;
                        break;
                    }
                }
            }
            
            if (mockResult) {
                const scanId = `scan_${Date.now()}`;
                addCliLine(`Scan initiated with ID: ${scanId}`, 'success');
                addCliLine('Waiting for scan to complete...', 'info');
                
                // Simulate scan processing time
                await new Promise(resolve => setTimeout(resolve, 2000));
                
                addCliLine('Scan completed!', 'success');
                addCliLine(`Package: ${packageName} (${ecosystem})`, 'info');
                addCliLine(`Risk Level: ${mockResult.risk || mockResult.status}`, mockResult.risk === 'critical' || mockResult.risk === 'high' ? 'error' : 'success');
                
                if (mockResult.threats && mockResult.threats.length > 0) {
                    // Handle both string arrays and object arrays for threats
                    const threatDisplay = mockResult.threats.map(threat => {
                        if (typeof threat === 'string') {
                            return threat;
                        } else if (typeof threat === 'object' && threat.type) {
                            return `${threat.type} (${threat.severity}): ${threat.description}`;
                        }
                        return threat.toString();
                    }).join('\n                         ');
                    addCliLine(`Threats found: ${threatDisplay}`, 'error');
                } else {
                    addCliLine('No threats detected', 'success');
                }
            } else {
                addCliLine('Package not found in database', 'error');
            }
            
        } catch (error) {
            addCliLine(`Error: ${error.message}`, 'error');
        }
    }
    

    
    async function bulkScanPackages(packages) {
        addCliLine(`Bulk scanning ${packages.length} packages: ${packages.join(', ')}`, 'info');
        
        try {
            // Simulate API delay
            await new Promise(resolve => setTimeout(resolve, 1000));
            
            addCliLine(`Initiated ${packages.length} scans`, 'success');
            
            // Process each package with mock data
            for (let i = 0; i < packages.length; i++) {
                const packageName = packages[i].trim();
                let mockResult = getMockScanResult(packageName, 'npm');
                let ecosystem = 'npm';
                
                // If not found in npm, try other ecosystems
                if (!mockResult) {
                    const ecosystems = ['pypi', 'go', 'maven', 'nuget', 'rubygems'];
                    for (const eco of ecosystems) {
                        mockResult = getMockScanResult(packageName, eco);
                        if (mockResult) {
                            ecosystem = eco;
                            break;
                        }
                    }
                }
                
                await new Promise(resolve => setTimeout(resolve, 500)); // Simulate processing time
                
                if (mockResult) {
                    const riskLevel = mockResult.risk || mockResult.status;
                    addCliLine(`✓ ${packageName} (${ecosystem}): ${riskLevel}`, 
                        mockResult.risk === 'critical' || mockResult.risk === 'high' ? 'error' : 'success');
                    
                    // Show threats if any
                    if (mockResult.threats && mockResult.threats.length > 0) {
                        const threatDisplay = mockResult.threats.map(threat => {
                            if (typeof threat === 'string') {
                                return threat;
                            } else if (typeof threat === 'object' && threat.type) {
                                return `${threat.type} (${threat.severity})`;
                            }
                            return threat.toString();
                        }).join(', ');
                        addCliLine(`  Threats: ${threatDisplay}`, 'error');
                    }
                } else {
                    addCliLine(`✗ ${packageName}: Not found`, 'warning');
                }
            }
            
            addCliLine('Bulk scan completed!', 'success');
            
        } catch (error) {
            addCliLine(`Error: ${error.message}`, 'error');
        }
    }
    
    async function getStats() {
        addCliLine('Fetching scan statistics...', 'info');
        
        try {
            // Simulate API delay
            await new Promise(resolve => setTimeout(resolve, 500));
            
            const mockStats = {
                totalScans: 15847,
                threatsDetected: 342,
                packagesAnalyzed: 12456,
                lastUpdate: new Date().toISOString(),
                ecosystems: {
                    npm: 8234,
                    pypi: 3456,
                    maven: 1234,
                    nuget: 987,
                    rubygems: 654,
                    go: 321
                }
            };
            
            addCliLine('Scan Statistics:', 'success');
            addCliLine(JSON.stringify(mockStats, null, 2), 'json');
            
        } catch (error) {
            addCliLine(`Error: ${error.message}`, 'error');
        }
    }
    
    async function checkHealth() {
        addCliLine('Checking API health...', 'info');
        
        try {
            // Simulate API delay
            await new Promise(resolve => setTimeout(resolve, 300));
            
            const mockHealth = {
                status: 'healthy',
                version: '1.0.0',
                uptime: '7 days, 14 hours, 23 minutes',
                database: 'connected',
                lastUpdate: new Date().toISOString(),
                services: {
                    scanner: 'operational',
                    analyzer: 'operational',
                    database: 'operational',
                    cache: 'operational'
                }
            };
            
            addCliLine('API Health Status:', 'success');
            addCliLine(JSON.stringify(mockHealth, null, 2), 'json');
            
        } catch (error) {
            addCliLine(`Error: ${error.message}`, 'error');
        }
    }

// Navbar background on scroll
window.addEventListener('scroll', () => {
    const navbar = document.querySelector('.navbar');
    if (window.scrollY > 50) {
        navbar.style.background = 'rgba(255, 255, 255, 0.98)';
        navbar.style.boxShadow = '0 2px 20px rgba(0, 0, 0, 0.1)';
    } else {
        navbar.style.background = 'rgba(255, 255, 255, 0.95)';
        navbar.style.boxShadow = 'none';
    }
});

// Demo functionality
const packageInput = document.getElementById('packageInput');
const scanBtn = document.getElementById('scanBtn');
const scanResults = document.getElementById('scanResults');

// CLI Demo functionality
const cliInput = document.getElementById('cliInput');
const cliOutput = document.getElementById('cliOutput');
const exampleCommands = document.querySelectorAll('.example-cmd');

// CLI Demo Event Listeners
if (cliInput) {
    cliInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            const command = this.value.trim();
            if (command) {
                executeCommand(command);
                this.value = '';
            }
        }
    });
}

if (exampleCommands) {
    exampleCommands.forEach(btn => {
        btn.addEventListener('click', function() {
            const command = this.dataset.cmd;
            if (cliInput) {
                cliInput.value = command;
                executeCommand(command);
                cliInput.value = '';
            }
        });
    });
}

// API base URL
const API_BASE = window.location.origin + '/api';

const packageNameInput = document.getElementById('packageName');
const ecosystemSelect = document.getElementById('ecosystem');
const packageVersion = document.getElementById('packageVersion');
const bulkScanBtn = document.getElementById('bulkScanBtn');
const bulkPackages = document.getElementById('bulkPackages');
const exportBtn = document.getElementById('exportBtn');
const clearBtn = document.getElementById('clearBtn');
const exampleTags = document.querySelectorAll('.tag');

// Advanced options
const toggleAdvanced = document.getElementById('toggleAdvanced');
const advancedPanel = document.getElementById('advancedPanel');
const mlAnalysis = document.getElementById('mlAnalysis');
const staticAnalysis = document.getElementById('staticAnalysis');
const dynamicAnalysis = document.getElementById('dynamicAnalysis');
const provenanceAnalysis = document.getElementById('provenanceAnalysis');
const dependencyDepth = document.getElementById('dependencyDepth');

// Toggle advanced options
if (toggleAdvanced) {
    toggleAdvanced.addEventListener('click', () => {
        advancedPanel.classList.toggle('active');
        const icon = toggleAdvanced.querySelector('i');
        if (advancedPanel.classList.contains('active')) {
            icon.className = 'fas fa-chevron-up';
        } else {
            icon.className = 'fas fa-chevron-down';
        }
    });
}

// Example tag click handlers
exampleTags.forEach(tag => {
    tag.addEventListener('click', () => {
        const ecosystem = tag.dataset.ecosystem;
        const packageName = tag.dataset.package;
        
        ecosystemSelect.value = ecosystem;
        packageNameInput.value = packageName;
        
        // Trigger scan
        performScan(ecosystem, packageName);
    });
});

// Scan button click handler
scanBtn.addEventListener('click', () => {
    const ecosystem = ecosystemSelect.value;
    const packageName = packageNameInput.value.trim();
    const version = packageVersion ? packageVersion.value.trim() : 'latest';
    
    if (!packageName) {
        showError('Please enter a package name');
        return;
    }
    
    const options = {
        mlAnalysis: mlAnalysis ? mlAnalysis.checked : true,
        staticAnalysis: staticAnalysis ? staticAnalysis.checked : true,
        dynamicAnalysis: dynamicAnalysis ? dynamicAnalysis.checked : false,
        provenanceAnalysis: provenanceAnalysis ? provenanceAnalysis.checked : true,
        dependencyDepth: dependencyDepth ? parseInt(dependencyDepth.value) : 3
    };
    
    performScan(ecosystem, packageName, version, options);
});

// Bulk scan functionality
if (bulkScanBtn) {
    bulkScanBtn.addEventListener('click', () => {
        const packages = bulkPackages.value.trim();
        
        if (!packages) {
            showError('Please enter packages to scan');
            return;
        }
        
        const options = {
            mlAnalysis: mlAnalysis ? mlAnalysis.checked : true,
            staticAnalysis: staticAnalysis ? staticAnalysis.checked : true,
            dynamicAnalysis: dynamicAnalysis ? dynamicAnalysis.checked : false,
            provenanceAnalysis: provenanceAnalysis ? provenanceAnalysis.checked : true,
            dependencyDepth: dependencyDepth ? parseInt(dependencyDepth.value) : 3
        };
        
        performBulkScan(packages, options);
    });
}

// Export functionality
if (exportBtn) {
    exportBtn.addEventListener('click', () => {
        if (window.currentResults) {
            const dataStr = JSON.stringify(window.currentResults, null, 2);
            const dataBlob = new Blob([dataStr], {type: 'application/json'});
            const url = URL.createObjectURL(dataBlob);
            const link = document.createElement('a');
            link.href = url;
            link.download = `typosentinel-scan-${Date.now()}.json`;
            link.click();
            URL.revokeObjectURL(url);
        }
    });
}

// Clear functionality
if (clearBtn) {
    clearBtn.addEventListener('click', () => {
        scanResults.innerHTML = `
            <div class="placeholder">
                <i class="fas fa-search"></i>
                <p>Enter a package name and click scan to see results</p>
                <small>Results will appear here with detailed security analysis</small>
            </div>
        `;
        window.currentResults = null;
        if (exportBtn) exportBtn.disabled = true;
        clearBtn.disabled = true;
    });
}

// Enter key handler for package input
packageNameInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        scanBtn.click();
    }
});

// Helper function to get mock scan result
function getMockScanResult(packageName, ecosystem = 'npm') {
    if (mockScanData[ecosystem] && mockScanData[ecosystem][packageName]) {
        return mockScanData[ecosystem][packageName];
    }
    return null;
}

// Mock scan data for different ecosystems
const mockScanData = {
    npm: {
        'lodash': { risk: 'low', status: 'safe', threats: [], metadata: { downloads: '50M+', maintainers: 4, version: 'latest' } },
        'express': { risk: 'low', status: 'safe', threats: [], metadata: { downloads: '20M+', maintainers: 8, version: 'latest' } },
        'malicious-package': { risk: 'critical', status: 'malicious', threats: ['Code injection', 'Data exfiltration'], metadata: { downloads: '1K', maintainers: 1, version: 'latest' } },
        'typosquatting-lib': { risk: 'high', status: 'suspicious', threats: ['Typosquatting', 'Potential malware'], metadata: { downloads: '100', maintainers: 1, version: 'latest' } },
        'reqeusts': {
            riskScore: 0.95,
            status: 'high-risk',
            threats: [
                {
                    type: 'Typosquatting',
                    severity: 'high',
                    description: 'Package name is a typo of popular "requests" library',
                    confidence: 0.98
                },
                {
                    type: 'Suspicious Code',
                    severity: 'medium',
                    description: 'Contains obfuscated JavaScript code',
                    confidence: 0.75
                }
            ],
            metadata: {
                downloads: 1250,
                maintainer: 'suspicious-user',
                created: '2024-01-15',
                lastUpdate: '2024-01-15'
            }
        }
    },
    pypi: {
        'requests': { risk: 'low', status: 'safe', threats: [], metadata: { downloads: '100M+', maintainers: 6, version: 'latest' } },
        'django': { risk: 'low', status: 'safe', threats: [], metadata: { downloads: '5M+', maintainers: 12, version: 'latest' } },
        'suspicious-lib': { risk: 'medium', status: 'suspicious', threats: ['Obfuscated code'], metadata: { downloads: '500', maintainers: 1, version: 'latest' } },
        'numpy': { risk: 'low', status: 'safe', threats: [], metadata: { downloads: '200M+', maintainers: 15, version: 'latest' } },
        'beautifulsoup': {
            riskScore: 0.85,
            status: 'high-risk',
            threats: [
                {
                    type: 'Typosquatting',
                    severity: 'high',
                    description: 'Package name is a typo of "beautifulsoup4"',
                    confidence: 0.92
                },
                {
                    type: 'Malicious Code',
                    severity: 'high',
                    description: 'Contains code that sends data to external servers',
                    confidence: 0.88
                }
            ],
            metadata: {
                downloads: 850,
                maintainer: 'fake-maintainer',
                created: '2024-01-20',
                lastUpdate: '2024-01-20'
            }
        }
    },
    go: {
        'gin': { risk: 'low', status: 'safe', threats: [], metadata: { stars: '65K+', contributors: 400, version: 'latest' } },
        'gorilla/mux': { risk: 'low', status: 'safe', threats: [], metadata: { stars: '18K+', contributors: 200, version: 'latest' } },
        'fiber': { risk: 'low', status: 'safe', threats: [], metadata: { stars: '25K+', contributors: 300, version: 'latest' } },
        'github.com/gin-gonic/gin': {
            riskScore: 0.04,
            status: 'safe',
            threats: [],
            metadata: {
                downloads: 'N/A (Go modules)',
                maintainer: 'gin-gonic',
                created: '2014-06-16',
                lastUpdate: '2024-01-12'
            }
        }
    },
    maven: {
        'spring-boot': { risk: 'low', status: 'safe', threats: [], metadata: { usage: 'Very High', maintainers: 20, version: 'latest' } },
        'log4j': { risk: 'high', status: 'vulnerable', threats: ['Remote code execution'], metadata: { usage: 'High', maintainers: 5, version: 'latest' } },
        'jackson-core': { risk: 'low', status: 'safe', threats: [], metadata: { usage: 'High', maintainers: 8, version: 'latest' } },
        'org.springframework:spring-core': {
            riskScore: 0.02,
            status: 'safe',
            threats: [],
            metadata: {
                downloads: 'High',
                maintainer: 'Spring Team',
                created: '2003-06-01',
                lastUpdate: '2024-01-10'
            }
        }
    },
    nuget: {
        'newtonsoft.json': { risk: 'low', status: 'safe', threats: [], metadata: { downloads: '2B+', maintainers: 3, version: 'latest' } },
        'entityframework': { risk: 'low', status: 'safe', threats: [], metadata: { downloads: '500M+', maintainers: 10, version: 'latest' } }
    },
    rubygems: {
        'rails': { risk: 'low', status: 'safe', threats: [], metadata: { downloads: '300M+', maintainers: 50, version: 'latest' } },
        'devise': { risk: 'low', status: 'safe', threats: [], metadata: { downloads: '100M+', maintainers: 15, version: 'latest' } }
    }
};

// Store current results for export
window.currentResults = null;

// Perform scan function
function performScan(ecosystem, packageName, version = 'latest', options = {}) {
    const scanResults = document.getElementById('scanResults');
    
    // Show loading state
    scanResults.innerHTML = `
        <div class="loading">
            <i class="fas fa-spinner fa-spin"></i>
            <p>Scanning ${packageName}${version !== 'latest' ? `@${version}` : ''}...</p>
            <small>Analyzing with ${Object.values(options).filter(Boolean).length} analysis engines</small>
        </div>
    `;
    
    // Simulate API delay based on analysis options
    const delay = 1500 + (Object.values(options).filter(Boolean).length * 500);
    
    setTimeout(() => {
        const ecosystemData = mockScanData[ecosystem] || {};
        let result = ecosystemData[packageName] || {
            risk: 'unknown',
            status: 'not_found',
            threats: ['Package not found in database'],
            metadata: { note: 'This package may be new or not widely used', version: version }
        };
        
        // Enhance result with analysis options
        result = enhanceResultWithOptions(result, options);
        result.metadata.version = version;
        result.metadata.scanOptions = options;
        
        window.currentResults = {
            type: 'single',
            ecosystem,
            packageName,
            version,
            options,
            result,
            timestamp: new Date().toISOString()
        };
        
        if (result.riskScore !== undefined) {
            displayScanResults(packageName, ecosystem, result);
        } else {
            displayScanResult(result, ecosystem, packageName, version);
        }
        
        // Enable export and clear buttons
        const exportBtn = document.getElementById('exportBtn');
        const clearBtn = document.getElementById('clearBtn');
        if (exportBtn) exportBtn.disabled = false;
        if (clearBtn) clearBtn.disabled = false;
    }, delay);
}

// Perform bulk scan function
function performBulkScan(packagesText, options = {}) {
    const scanResults = document.getElementById('scanResults');
    
    // Parse packages from text
    const packages = packagesText.split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#'))
        .map(line => {
            const parts = line.split(/[@\s]+/);
            const [ecosystem, name] = parts[0].includes('/') ? parts[0].split('/') : ['npm', parts[0]];
            const version = parts[1] || 'latest';
            return { ecosystem, name, version };
        });
    
    if (packages.length === 0) {
        showError('No valid packages found to scan');
        return;
    }
    
    // Show loading state
    scanResults.innerHTML = `
        <div class="loading">
            <i class="fas fa-spinner fa-spin"></i>
            <p>Bulk scanning ${packages.length} packages...</p>
            <small>This may take a few moments</small>
        </div>
    `;
    
    // Simulate bulk scan with progressive results
    const results = [];
    let completed = 0;
    
    const scanPackage = (pkg, index) => {
        setTimeout(() => {
            const ecosystemData = mockScanData[pkg.ecosystem] || {};
            let result = ecosystemData[pkg.name] || {
                risk: 'unknown',
                status: 'not_found',
                threats: ['Package not found in database'],
                metadata: { note: 'This package may be new or not widely used', version: pkg.version }
            };
            
            result = enhanceResultWithOptions(result, options);
            result.metadata.version = pkg.version;
            
            results.push({
                ecosystem: pkg.ecosystem,
                name: pkg.name,
                version: pkg.version,
                result
            });
            
            completed++;
            
            if (completed === packages.length) {
                window.currentResults = {
                    type: 'bulk',
                    packages: results,
                    options,
                    timestamp: new Date().toISOString()
                };
                
                displayBulkScanResults(results);
                
                // Enable export and clear buttons
                const exportBtn = document.getElementById('exportBtn');
                const clearBtn = document.getElementById('clearBtn');
                if (exportBtn) exportBtn.disabled = false;
                if (clearBtn) clearBtn.disabled = false;
            }
        }, index * 300 + Math.random() * 500);
    };
    
    packages.forEach(scanPackage);
}

// Enhance result with analysis options
function enhanceResultWithOptions(result, options) {
    const enhanced = { ...result };
    
    if (options.mlAnalysis) {
        enhanced.mlScore = Math.random() * 100;
        enhanced.mlConfidence = Math.random() * 100;
    }
    
    if (options.staticAnalysis) {
        enhanced.staticFindings = Math.floor(Math.random() * 5);
    }
    
    if (options.dynamicAnalysis) {
        enhanced.behaviorAnalysis = {
            networkCalls: Math.floor(Math.random() * 10),
            fileOperations: Math.floor(Math.random() * 5),
            processSpawning: Math.floor(Math.random() * 3)
        };
    }
    
    if (options.provenanceAnalysis) {
        enhanced.provenance = {
            verified: Math.random() > 0.3,
            signatureValid: Math.random() > 0.2,
            buildReproducible: Math.random() > 0.4
        };
    }
    
    return enhanced;
}

function showLoading() {
    scanResults.innerHTML = `
        <div class="loading-container">
            <div class="loading"></div>
            <p style="margin-top: 1rem; color: #64748b;">Scanning package...</p>
        </div>
    `;
}

function showError(message) {
    const scanResults = document.getElementById('scanResults');
    scanResults.innerHTML = `
        <div class="error-message">
            <i class="fas fa-exclamation-triangle"></i>
            <p>${message}</p>
        </div>
    `;
}

function displayScanResult(result, ecosystem, packageName, version) {
    const scanResults = document.getElementById('scanResults');
    
    const getRiskColor = (risk) => {
        switch(risk) {
            case 'low': return '#10b981';
            case 'medium': return '#f59e0b';
            case 'high': return '#ef4444';
            case 'critical': return '#dc2626';
            default: return '#6b7280';
        }
    };
    
    const getStatusIcon = (status) => {
        switch(status) {
            case 'safe': return '✅';
            case 'suspicious': return '⚠️';
            case 'malicious': return '🚨';
            case 'vulnerable': return '🔓';
            default: return '❓';
        }
    };
    
    const threatsHtml = result.threats && result.threats.length > 0 ? 
        `<div class="threats">
            <h4>🚨 Threats Detected:</h4>
            <ul>${result.threats.map(threat => `<li>${threat}</li>`).join('')}</ul>
        </div>` : 
        '<div class="safe-indicator">✅ No threats detected</div>';
    
    const analysisHtml = generateAnalysisSection(result);
    
    scanResults.innerHTML = `
        <div class="scan-result">
            <div class="result-header">
                <h3>${getStatusIcon(result.status)} ${packageName}@${version}</h3>
                <div class="ecosystem-badge">${ecosystem}</div>
                <div class="risk-badge risk-${result.risk}" style="background-color: ${getRiskColor(result.risk)}">
                    ${result.risk.toUpperCase()}
                </div>
            </div>
            
            <div class="status-indicator" style="color: ${getRiskColor(result.risk)}">
                Status: ${result.status.toUpperCase()}
            </div>
            
            ${threatsHtml}
            
            ${analysisHtml}
            
            <div class="metadata">
                <h4>📊 Package Information:</h4>
                <div class="metadata-grid">
                    ${Object.entries(result.metadata).map(([key, value]) => 
                        `<div><strong>${key}:</strong> ${value}</div>`
                    ).join('')}
                </div>
            </div>
        </div>
    `;
}

function displayBulkScanResults(results) {
    const scanResults = document.getElementById('scanResults');
    
    const summary = {
        total: results.length,
        safe: results.filter(r => r.result.status === 'safe').length,
        suspicious: results.filter(r => r.result.status === 'suspicious').length,
        malicious: results.filter(r => r.result.status === 'malicious').length,
        vulnerable: results.filter(r => r.result.status === 'vulnerable').length,
        unknown: results.filter(r => r.result.status === 'not_found').length
    };
    
    const resultsHtml = results.map(pkg => {
        const riskColor = getRiskColor(pkg.result.risk);
        const statusIcon = getStatusIcon(pkg.result.status);
        
        return `
            <div class="bulk-result-item">
                <div class="bulk-item-header">
                    <span class="package-name">${statusIcon} ${pkg.name}@${pkg.version}</span>
                    <span class="ecosystem-tag">${pkg.ecosystem}</span>
                    <span class="risk-indicator" style="background-color: ${riskColor}">
                        ${pkg.result.risk.toUpperCase()}
                    </span>
                </div>
                ${pkg.result.threats && pkg.result.threats.length > 0 ? 
                    `<div class="threats-summary">
                        ${pkg.result.threats.slice(0, 2).join(', ')}
                        ${pkg.result.threats.length > 2 ? ` (+${pkg.result.threats.length - 2} more)` : ''}
                    </div>` : ''}
            </div>
        `;
    }).join('');
    
    scanResults.innerHTML = `
        <div class="bulk-scan-results">
            <div class="bulk-summary">
                <h3>📊 Bulk Scan Summary</h3>
                <div class="summary-stats">
                    <div class="stat safe">✅ Safe: ${summary.safe}</div>
                    <div class="stat suspicious">⚠️ Suspicious: ${summary.suspicious}</div>
                    <div class="stat malicious">🚨 Malicious: ${summary.malicious}</div>
                    <div class="stat vulnerable">🔓 Vulnerable: ${summary.vulnerable}</div>
                    <div class="stat unknown">❓ Unknown: ${summary.unknown}</div>
                </div>
            </div>
            
            <div class="bulk-results-list">
                <h4>📦 Package Results (${results.length} total)</h4>
                ${resultsHtml}
            </div>
        </div>
    `;
}

function generateAnalysisSection(result) {
    let html = '';
    
    if (result.mlScore !== undefined) {
        html += `
            <div class="analysis-section">
                <h4>🤖 ML Analysis</h4>
                <div class="analysis-item">
                    <span>ML Risk Score: ${result.mlScore.toFixed(1)}%</span>
                    <span>Confidence: ${result.mlConfidence.toFixed(1)}%</span>
                </div>
            </div>
        `;
    }
    
    if (result.staticFindings !== undefined) {
        html += `
            <div class="analysis-section">
                <h4>🔍 Static Analysis</h4>
                <div class="analysis-item">
                    <span>Findings: ${result.staticFindings}</span>
                </div>
            </div>
        `;
    }
    
    if (result.behaviorAnalysis) {
        html += `
            <div class="analysis-section">
                <h4>⚡ Dynamic Analysis</h4>
                <div class="analysis-item">
                    <span>Network Calls: ${result.behaviorAnalysis.networkCalls}</span>
                    <span>File Operations: ${result.behaviorAnalysis.fileOperations}</span>
                    <span>Process Spawning: ${result.behaviorAnalysis.processSpawning}</span>
                </div>
            </div>
        `;
    }
    
    if (result.provenance) {
        html += `
            <div class="analysis-section">
                <h4>🔐 Provenance Analysis</h4>
                <div class="analysis-item">
                    <span>Verified: ${result.provenance.verified ? '✅' : '❌'}</span>
                    <span>Signature Valid: ${result.provenance.signatureValid ? '✅' : '❌'}</span>
                    <span>Build Reproducible: ${result.provenance.buildReproducible ? '✅' : '❌'}</span>
                </div>
            </div>
        `;
    }
    
    return html;
}

function getRiskColor(risk) {
    switch(risk) {
        case 'low': return '#10b981';
        case 'medium': return '#f59e0b';
        case 'high': return '#ef4444';
        case 'critical': return '#dc2626';
        default: return '#6b7280';
    }
}

function getStatusIcon(status) {
    switch(status) {
        case 'safe': return '✅';
        case 'suspicious': return '⚠️';
        case 'malicious': return '🚨';
        case 'vulnerable': return '🔓';
        default: return '❓';
    }
}

function displayScanResults(packageName, ecosystem, data) {
    const statusClass = data.status === 'safe' ? 'result-safe' : 
                       data.riskScore > 0.7 ? 'result-danger' : 'result-warning';
    
    const statusIcon = data.status === 'safe' ? 'fa-check-circle' : 
                      data.riskScore > 0.7 ? 'fa-exclamation-triangle' : 'fa-exclamation-circle';
    
    const statusText = data.status === 'safe' ? 'Safe' : 
                      data.riskScore > 0.7 ? 'High Risk' : 'Medium Risk';
    
    let threatsHtml = '';
    if (data.threats && data.threats.length > 0) {
        threatsHtml = `
            <div class="threats-section">
                <h4><i class="fas fa-shield-alt"></i> Detected Threats:</h4>
                ${data.threats.map(threat => `
                    <div class="threat-item">
                        <div class="threat-header">
                            <span class="threat-type">${threat.type}</span>
                            <span class="threat-severity severity-${threat.severity}">${threat.severity.toUpperCase()}</span>
                        </div>
                        <p class="threat-description">${threat.description}</p>
                        <div class="threat-confidence">Confidence: ${(threat.confidence * 100).toFixed(0)}%</div>
                    </div>
                `).join('')}
            </div>
        `;
    }
    
    scanResults.innerHTML = `
        <div class="scan-result ${statusClass}">
            <div class="result-header">
                <i class="fas ${statusIcon}"></i>
                <div>
                    <strong>${packageName}</strong> (${ecosystem})
                    <div class="status-badge">${statusText}</div>
                </div>
                <div class="risk-score">
                    Risk Score: <strong>${(data.riskScore * 100).toFixed(0)}%</strong>
                </div>
            </div>
            
            ${threatsHtml}
            
            <div class="metadata-section">
                <h4><i class="fas fa-info-circle"></i> Package Metadata:</h4>
                <div class="metadata-grid">
                    <div class="metadata-item">
                        <span class="label">Downloads:</span>
                        <span class="value">${data.metadata.downloads.toLocaleString ? data.metadata.downloads.toLocaleString() : data.metadata.downloads}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="label">Maintainer:</span>
                        <span class="value">${data.metadata.maintainer}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="label">Created:</span>
                        <span class="value">${data.metadata.created}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="label">Last Update:</span>
                        <span class="value">${data.metadata.lastUpdate}</span>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function displayGenericResult(packageName, ecosystem) {
    // Generate a random but consistent result based on package name
    const hash = packageName.split('').reduce((a, b) => {
        a = ((a << 5) - a) + b.charCodeAt(0);
        return a & a;
    }, 0);
    
    const riskScore = Math.abs(hash % 30) / 100; // 0-0.3 range for most packages
    const isPopular = Math.abs(hash % 10) > 7; // 20% chance of being "popular"
    
    const statusClass = riskScore < 0.1 ? 'result-safe' : 
                       riskScore < 0.2 ? 'result-warning' : 'result-danger';
    
    const statusIcon = riskScore < 0.1 ? 'fa-check-circle' : 
                      riskScore < 0.2 ? 'fa-exclamation-circle' : 'fa-exclamation-triangle';
    
    const statusText = riskScore < 0.1 ? 'Safe' : 
                      riskScore < 0.2 ? 'Low Risk' : 'Medium Risk';
    
    const downloads = isPopular ? Math.floor(Math.random() * 1000000) + 100000 : 
                     Math.floor(Math.random() * 10000) + 100;
    
    scanResults.innerHTML = `
        <div class="scan-result ${statusClass}">
            <div class="result-header">
                <i class="fas ${statusIcon}"></i>
                <div>
                    <strong>${packageName}</strong> (${ecosystem})
                    <div class="status-badge">${statusText}</div>
                </div>
                <div class="risk-score">
                    Risk Score: <strong>${(riskScore * 100).toFixed(0)}%</strong>
                </div>
            </div>
            
            <div class="scan-summary">
                <p>Package analysis completed. ${riskScore < 0.1 ? 'No significant threats detected.' : 
                  riskScore < 0.2 ? 'Minor security concerns identified.' : 'Some security issues found.'}</p>
            </div>
            
            <div class="metadata-section">
                <h4><i class="fas fa-info-circle"></i> Package Metadata:</h4>
                <div class="metadata-grid">
                    <div class="metadata-item">
                        <span class="label">Downloads:</span>
                        <span class="value">${downloads.toLocaleString()}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="label">Status:</span>
                        <span class="value">${isPopular ? 'Popular' : 'Standard'}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="label">Ecosystem:</span>
                        <span class="value">${ecosystem.toUpperCase()}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="label">Scan Time:</span>
                        <span class="value">${new Date().toLocaleTimeString()}</span>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Contact form functionality
const contactForm = document.getElementById('contactForm');
if (contactForm) {
    contactForm.addEventListener('submit', (e) => {
        e.preventDefault();
        
        // Get form data
        const formData = new FormData(contactForm);
        const data = Object.fromEntries(formData);
        
        // Show success message (in a real app, you'd send this to a server)
        showContactSuccess();
        
        // Reset form
        contactForm.reset();
    });
}

function showContactSuccess() {
    const form = document.querySelector('.contact-form');
    const originalContent = form.innerHTML;
    
    form.innerHTML = `
        <div class="success-message">
            <i class="fas fa-check-circle" style="font-size: 3rem; color: #22c55e; margin-bottom: 1rem;"></i>
            <h3>Message Sent!</h3>
            <p>Thank you for your interest in TypoSentinel. We'll get back to you soon.</p>
            <button class="btn btn-primary" onclick="resetContactForm()">Send Another Message</button>
        </div>
    `;
    
    // Store original content for reset
    form.dataset.originalContent = originalContent;
}

function resetContactForm() {
    const form = document.querySelector('.contact-form');
    form.innerHTML = form.dataset.originalContent;
    
    // Re-attach event listener
    const newForm = document.getElementById('contactForm');
    newForm.addEventListener('submit', (e) => {
        e.preventDefault();
        showContactSuccess();
        newForm.reset();
    });
}

// Intersection Observer for animations
const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.style.opacity = '1';
            entry.target.style.transform = 'translateY(0)';
        }
    });
}, observerOptions);

// Observe elements for animation
document.querySelectorAll('.feature-card, .api-endpoint').forEach(el => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(20px)';
    el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
    observer.observe(el);
});

// Terminal typing animation
function typeTerminalContent() {
    const terminalLines = document.querySelectorAll('.terminal-line');
    
    terminalLines.forEach((line, index) => {
        line.style.opacity = '0';
        setTimeout(() => {
            line.style.opacity = '1';
            line.style.animation = 'typewriter 0.5s ease';
        }, index * 800);
    });
}

// Start terminal animation when page loads
window.addEventListener('load', () => {
    setTimeout(typeTerminalContent, 1000);
});

// Add CSS for additional styling
const additionalStyles = `
    .loading-container {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        height: 200px;
    }
    
    .result-header {
        display: flex;
        align-items: center;
        gap: 1rem;
        margin-bottom: 1rem;
        padding-bottom: 1rem;
        border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    .result-header i {
        font-size: 1.5rem;
    }
    
    .status-badge {
        font-size: 0.8rem;
        opacity: 0.8;
        margin-top: 0.25rem;
    }
    
    .risk-score {
        margin-left: auto;
        text-align: right;
    }
    
    .threats-section {
        margin: 1.5rem 0;
    }
    
    .threats-section h4 {
        margin-bottom: 1rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    
    .threat-item {
        background: rgba(0, 0, 0, 0.2);
        padding: 1rem;
        border-radius: 8px;
        margin-bottom: 0.5rem;
    }
    
    .threat-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 0.5rem;
    }
    
    .threat-type {
        font-weight: 600;
    }
    
    .threat-severity {
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.7rem;
        font-weight: 600;
        text-transform: uppercase;
    }
    
    .severity-high {
        background: #ef4444;
        color: white;
    }
    
    .severity-medium {
        background: #f59e0b;
        color: white;
    }
    
    .severity-low {
        background: #10b981;
        color: white;
    }
    
    .threat-description {
        margin: 0.5rem 0;
        opacity: 0.9;
    }
    
    .threat-confidence {
        font-size: 0.8rem;
        opacity: 0.7;
    }
    
    .metadata-section h4 {
        margin-bottom: 1rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    
    .metadata-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 0.5rem;
    }
    
    .metadata-item {
        display: flex;
        justify-content: space-between;
        padding: 0.5rem 0;
        border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    .metadata-item .label {
        opacity: 0.7;
    }
    
    .metadata-item .value {
        font-weight: 500;
    }
    
    .scan-summary {
        margin: 1rem 0;
        padding: 1rem;
        background: rgba(0, 0, 0, 0.1);
        border-radius: 8px;
    }
    
    .success-message {
        text-align: center;
        padding: 2rem;
    }
    
    .success-message h3 {
        margin-bottom: 1rem;
        color: #22c55e;
    }
    
    .success-message p {
        margin-bottom: 2rem;
        opacity: 0.9;
    }
`;

// Inject additional styles
const styleSheet = document.createElement('style');
styleSheet.textContent = additionalStyles;
document.head.appendChild(styleSheet);

// Make resetContactForm globally available
window.resetContactForm = resetContactForm;