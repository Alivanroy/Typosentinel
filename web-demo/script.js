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
            const response = await fetch(`${API_BASE}/scan`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    package: packageName,
                    version: 'latest'
                })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const result = await response.json();
            addCliLine(`Scan initiated with ID: ${result.id}`, 'success');
            addCliLine('Waiting for scan to complete...', 'info');
            
            // Poll for results
            await pollScanResult(result.id);
            
        } catch (error) {
            addCliLine(`Error: ${error.message}`, 'error');
        }
    }
    
    async function pollScanResult(scanId) {
        const maxAttempts = 30;
        let attempts = 0;
        
        const poll = async () => {
            try {
                const response = await fetch(`${API_BASE}/scans/${scanId}`);
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                const result = await response.json();
                
                if (result.status === 'completed') {
                    addCliLine('Scan completed!', 'success');
                    addCliLine('Results:', 'info');
                    addCliLine(JSON.stringify(result.result, null, 2), 'json');
                    return;
                } else if (result.status === 'failed') {
                    addCliLine('Scan failed!', 'error');
                    if (result.result && result.result.error) {
                        addCliLine(`Error: ${result.result.error}`, 'error');
                    }
                    return;
                } else if (attempts >= maxAttempts) {
                    addCliLine('Scan timeout - check status later', 'warning');
                    return;
                }
                
                attempts++;
                setTimeout(poll, 1000);
                
            } catch (error) {
                addCliLine(`Error polling results: ${error.message}`, 'error');
            }
        };
        
        poll();
    }
    
    async function bulkScanPackages(packages) {
        addCliLine(`Bulk scanning ${packages.length} packages: ${packages.join(', ')}`, 'info');
        
        try {
            const scanRequests = packages.map(pkg => ({
                package: pkg.trim(),
                version: 'latest'
            }));
            
            const response = await fetch(`${API_BASE}/scan/bulk`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    packages: scanRequests
                })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const results = await response.json();
            addCliLine(`Initiated ${results.length} scans`, 'success');
            
            // Poll each scan
            for (const result of results) {
                addCliLine(`Polling scan ${result.id} for package ${result.package}...`, 'info');
                await pollScanResult(result.id);
            }
            
        } catch (error) {
            addCliLine(`Error: ${error.message}`, 'error');
        }
    }
    
    async function getStats() {
        addCliLine('Fetching scan statistics...', 'info');
        
        try {
            const response = await fetch(`${API_BASE}/stats`);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const stats = await response.json();
            addCliLine('Scan Statistics:', 'success');
            addCliLine(JSON.stringify(stats, null, 2), 'json');
            
        } catch (error) {
            addCliLine(`Error: ${error.message}`, 'error');
        }
    }
    
    async function checkHealth() {
        addCliLine('Checking API health...', 'info');
        
        try {
            const response = await fetch(`${API_BASE}/health`);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const health = await response.json();
            addCliLine('API Health Status:', 'success');
            addCliLine(JSON.stringify(health, null, 2), 'json');
            
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
const exampleTags = document.querySelectorAll('.tag');

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
    
    if (!packageName) {
        showError('Please enter a package name');
        return;
    }
    
    performScan(ecosystem, packageName);
});

// Enter key handler for package input
packageNameInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        scanBtn.click();
    }
});

// Mock scan data for demo purposes
const mockScanData = {
    'npm': {
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
        },
        'lodash': {
            riskScore: 0.05,
            status: 'safe',
            threats: [],
            metadata: {
                downloads: 25000000,
                maintainer: 'lodash-team',
                created: '2012-04-23',
                lastUpdate: '2024-01-10'
            }
        },
        'express': {
            riskScore: 0.02,
            status: 'safe',
            threats: [],
            metadata: {
                downloads: 18000000,
                maintainer: 'expressjs',
                created: '2010-12-29',
                lastUpdate: '2024-01-08'
            }
        }
    },
    'pypi': {
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
        },
        'requests': {
            riskScore: 0.03,
            status: 'safe',
            threats: [],
            metadata: {
                downloads: 50000000,
                maintainer: 'psf',
                created: '2011-02-13',
                lastUpdate: '2024-01-05'
            }
        }
    },
    'go': {
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
    'maven': {
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
    }
};

function performScan(ecosystem, packageName) {
    // Show loading state
    showLoading();
    
    // Simulate API delay
    setTimeout(() => {
        const scanData = mockScanData[ecosystem]?.[packageName];
        
        if (scanData) {
            displayScanResults(packageName, ecosystem, scanData);
        } else {
            displayGenericResult(packageName, ecosystem);
        }
    }, 1500);
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
    scanResults.innerHTML = `
        <div class="scan-result result-danger">
            <div class="result-header">
                <i class="fas fa-exclamation-triangle"></i>
                <strong>Error</strong>
            </div>
            <p>${message}</p>
        </div>
    `;
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