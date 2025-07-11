import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { 
  BookOpenIcon,
  CodeBracketIcon,
  CommandLineIcon,
  CogIcon,
  DocumentTextIcon,
  PlayIcon,
  ChevronRightIcon,
  ClipboardDocumentIcon,
  ShieldCheckIcon,
  CpuChipIcon,
  ServerIcon,
  CloudIcon,
  EyeIcon,
  BugAntIcon
} from '@heroicons/react/24/outline'

const Documentation: React.FC = () => {
  const [activeSection, setActiveSection] = useState('getting-started')
  const [copiedCode, setCopiedCode] = useState('')

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text)
    setCopiedCode(id)
    setTimeout(() => setCopiedCode(''), 2000)
  }

  const sections = [
    {
      id: 'getting-started',
      title: 'Getting Started',
      icon: PlayIcon,
      subsections: [
        { id: 'installation', title: 'Installation' },
        { id: 'quick-start', title: 'Quick Start' },
        { id: 'authentication', title: 'Authentication' }
      ]
    },
    {
      id: 'analyzers',
      title: 'Security Analyzers',
      icon: ShieldCheckIcon,
      subsections: [
        { id: 'typosquatting', title: 'Typosquatting Detection' },
        { id: 'dependency-confusion', title: 'Dependency Confusion' },
        { id: 'homoglyph', title: 'Homoglyph Detection' },
        { id: 'vulnerability-scanning', title: 'Vulnerability Scanning' }
      ]
    },
    {
      id: 'language-support',
      title: 'Language Support',
      icon: CpuChipIcon,
      subsections: [
        { id: 'nodejs', title: 'Node.js/npm' },
        { id: 'python', title: 'Python/pip' },
        { id: 'golang', title: 'Go Modules' },
        { id: 'generic', title: 'Generic Analysis' }
      ]
    },
    {
      id: 'deployment',
      title: 'Deployment Options',
      icon: ServerIcon,
      subsections: [
        { id: 'cli-tool', title: 'CLI Tool (Free)' },
        { id: 'on-premise', title: 'On-Premise API (Free)' },
        { id: 'saas-api', title: 'SaaS API' },
        { id: 'enterprise', title: 'Enterprise Features' }
      ]
    },
    {
      id: 'cli',
      title: 'CLI Reference',
      icon: CommandLineIcon,
      subsections: [
        { id: 'cli-installation', title: 'CLI Installation' },
        { id: 'cli-commands', title: 'Commands' },
        { id: 'cli-configuration', title: 'Configuration' }
      ]
    },
    {
      id: 'api',
      title: 'API Reference',
      icon: CodeBracketIcon,
      subsections: [
        { id: 'api-overview', title: 'API Overview' },
        { id: 'api-endpoints', title: 'Endpoints' },
        { id: 'api-examples', title: 'Examples' }
      ]
    },
    {
      id: 'integrations',
      title: 'Integrations',
      icon: CogIcon,
      subsections: [
        { id: 'ci-cd', title: 'CI/CD Integration' },
        { id: 'webhooks', title: 'Webhooks' },
        { id: 'third-party', title: 'Third-party Tools' }
      ]
    },
    {
      id: 'guides',
      title: 'Guides',
      icon: BookOpenIcon,
      subsections: [
        { id: 'best-practices', title: 'Best Practices' },
        { id: 'troubleshooting', title: 'Troubleshooting' },
        { id: 'migration', title: 'Migration Guide' }
      ]
    }
  ]

  const codeExamples = {
    installation: {
      npm: 'npm install -g typosentinel',
      yarn: 'yarn global add typosentinel',
      pip: 'pip install typosentinel'
    },
    quickStart: {
      scan: 'typosentinel scan package.json',
      monitor: 'typosentinel monitor --continuous',
      report: 'typosentinel report --format json'
    },
    api: {
      curl: `curl -X POST https://api.typosentinel.com/v1/scan \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "packages": ["express@4.18.0", "lodash@4.17.21"],
    "options": {
      "deep_scan": true,
      "include_dev": false
    }
  }'`,
      javascript: `const typosentinel = require('typosentinel');

const client = new typosentinel.Client({
  apiKey: process.env.TYPOSENTINEL_API_KEY
});

async function scanPackages() {
  try {
    const result = await client.scan({
      packages: ['express@4.18.0', 'lodash@4.17.21'],
      options: {
        deepScan: true,
        includeDev: false
      }
    });
    
    console.log('Scan results:', result);
  } catch (error) {
    console.error('Scan failed:', error);
  }
}`,
      python: `import typosentinel

client = typosentinel.Client(
    api_key=os.environ['TYPOSENTINEL_API_KEY']
)

def scan_packages():
    try:
        result = client.scan(
            packages=['express@4.18.0', 'lodash@4.17.21'],
            options={
                'deep_scan': True,
                'include_dev': False
            }
        )
        print('Scan results:', result)
    except Exception as error:
        print('Scan failed:', error)`
    }
  }

  const renderContent = () => {
    switch (activeSection) {
      case 'getting-started':
        return (
          <div className="space-y-8">
            <div>
              <h2 className="text-3xl font-bold text-ghost-white mb-4">Getting Started</h2>
              <p className="text-silver text-lg mb-6">
                Welcome to TypoSentinel! This guide will help you get up and running quickly 
                with our AI-powered supply chain security platform.
              </p>
            </div>

            <div id="installation">
              <h3 className="text-2xl font-semibold text-ghost-white mb-4">Installation</h3>
              <p className="text-silver mb-4">
                TypoSentinel can be installed via multiple package managers:
              </p>
              
              <div className="space-y-4">
                {Object.entries(codeExamples.installation).map(([manager, command]) => (
                  <div key={manager} className="glass rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-electric-blue font-medium uppercase text-sm">
                        {manager}
                      </span>
                      <button
                        onClick={() => copyToClipboard(command, `install-${manager}`)}
                        className="flex items-center space-x-1 text-silver hover:text-ghost-white transition-colors"
                      >
                        <ClipboardDocumentIcon className="h-4 w-4" />
                        <span className="text-sm">
                          {copiedCode === `install-${manager}` ? 'Copied!' : 'Copy'}
                        </span>
                      </button>
                    </div>
                    <code className="text-success-green font-mono">{command}</code>
                  </div>
                ))}
              </div>
            </div>

            <div id="quick-start">
              <h3 className="text-2xl font-semibold text-ghost-white mb-4">Quick Start</h3>
              <p className="text-silver mb-4">
                Once installed, you can start scanning your packages immediately:
              </p>
              
              <div className="space-y-4">
                {Object.entries(codeExamples.quickStart).map(([action, command]) => (
                  <div key={action} className="glass rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-electric-blue font-medium capitalize">
                        {action.replace(/([A-Z])/g, ' $1').trim()}
                      </span>
                      <button
                        onClick={() => copyToClipboard(command, `quick-${action}`)}
                        className="flex items-center space-x-1 text-silver hover:text-ghost-white transition-colors"
                      >
                        <ClipboardDocumentIcon className="h-4 w-4" />
                        <span className="text-sm">
                          {copiedCode === `quick-${action}` ? 'Copied!' : 'Copy'}
                        </span>
                      </button>
                    </div>
                    <code className="text-success-green font-mono">{command}</code>
                  </div>
                ))}
              </div>
            </div>

            <div id="authentication">
              <h3 className="text-2xl font-semibold text-ghost-white mb-4">Authentication</h3>
              <p className="text-silver mb-4">
                To use TypoSentinel's advanced features, you'll need an API key:
              </p>
              
              <div className="glass rounded-lg p-6">
                <ol className="space-y-3 text-silver">
                  <li className="flex items-start space-x-3">
                    <span className="flex-shrink-0 w-6 h-6 bg-electric-blue rounded-full flex items-center justify-center text-white text-sm font-bold">
                      1
                    </span>
                    <span>Sign up for a free account at typosentinel.com</span>
                  </li>
                  <li className="flex items-start space-x-3">
                    <span className="flex-shrink-0 w-6 h-6 bg-electric-blue rounded-full flex items-center justify-center text-white text-sm font-bold">
                      2
                    </span>
                    <span>Navigate to your dashboard and generate an API key</span>
                  </li>
                  <li className="flex items-start space-x-3">
                    <span className="flex-shrink-0 w-6 h-6 bg-electric-blue rounded-full flex items-center justify-center text-white text-sm font-bold">
                      3
                    </span>
                    <span>Set your API key as an environment variable:</span>
                  </li>
                </ol>
                
                <div className="mt-4 glass rounded-lg p-4">
                  <code className="text-success-green font-mono">
                    export TYPOSENTINEL_API_KEY=your_api_key_here
                  </code>
                </div>
              </div>
            </div>
          </div>
        )

      case 'analyzers':
        return (
          <div className="space-y-8">
            <div>
              <h2 className="text-3xl font-bold text-ghost-white mb-4">Security Analyzers</h2>
              <p className="text-silver text-lg mb-6">
                TypoSentinel employs multiple AI-powered analyzers to detect various types of 
                supply chain attacks and vulnerabilities in your dependencies.
              </p>
            </div>

            <div id="typosquatting">
              <h3 className="text-2xl font-semibold text-ghost-white mb-4">Typosquatting Detection</h3>
              <div className="glass rounded-lg p-6 mb-6">
                <p className="text-silver mb-4">
                  Detects packages with names similar to popular packages, using advanced algorithms:
                </p>
                <ul className="space-y-2 text-silver">
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>Edit Distance Analysis:</strong> Levenshtein distance calculations</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>Phonetic Similarity:</strong> Soundex and Metaphone algorithms</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>Visual Similarity:</strong> Character substitution detection</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>Popularity Scoring:</strong> Download count and reputation analysis</span>
                  </li>
                </ul>
              </div>
            </div>

            <div id="dependency-confusion">
              <h3 className="text-2xl font-semibold text-ghost-white mb-4">Dependency Confusion</h3>
              <div className="glass rounded-lg p-6 mb-6">
                <p className="text-silver mb-4">
                  Identifies potential dependency confusion attacks by analyzing:
                </p>
                <ul className="space-y-2 text-silver">
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>Namespace Conflicts:</strong> Public vs private package names</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>Version Anomalies:</strong> Suspicious version jumps</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>Registry Analysis:</strong> Cross-registry package comparison</span>
                  </li>
                </ul>
              </div>
            </div>

            <div id="homoglyph">
              <h3 className="text-2xl font-semibold text-ghost-white mb-4">Homoglyph Detection</h3>
              <div className="glass rounded-lg p-6 mb-6">
                <p className="text-silver mb-4">
                  Detects packages using visually similar characters from different Unicode blocks:
                </p>
                <ul className="space-y-2 text-silver">
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>Unicode Analysis:</strong> Cyrillic, Greek, and other character sets</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>Mixed Script Detection:</strong> Multiple writing systems in one name</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>Confusable Characters:</strong> Visually identical character pairs</span>
                  </li>
                </ul>
              </div>
            </div>

            <div id="vulnerability-scanning">
              <h3 className="text-2xl font-semibold text-ghost-white mb-4">Vulnerability Scanning</h3>
              <div className="glass rounded-lg p-6">
                <p className="text-silver mb-4">
                  Comprehensive vulnerability detection using multiple databases:
                </p>
                <ul className="space-y-2 text-silver">
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>CVE Database:</strong> Common Vulnerabilities and Exposures</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>OSV Database:</strong> Open Source Vulnerabilities</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>Advisory Feeds:</strong> Security advisories from package registries</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>CVSS Scoring:</strong> Risk assessment and prioritization</span>
                  </li>
                </ul>
              </div>
            </div>
          </div>
        )

      case 'language-support':
        return (
          <div className="space-y-8">
            <div>
              <h2 className="text-3xl font-bold text-ghost-white mb-4">Language Support</h2>
              <p className="text-silver text-lg mb-6">
                TypoSentinel supports multiple programming languages and package managers 
                with specialized analyzers for each ecosystem.
              </p>
            </div>

            <div id="nodejs">
              <h3 className="text-2xl font-semibold text-ghost-white mb-4">Node.js/npm</h3>
              <div className="glass rounded-lg p-6 mb-6">
                <p className="text-silver mb-4">Comprehensive analysis for JavaScript/TypeScript projects:</p>
                <ul className="space-y-2 text-silver">
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>package.json parsing:</strong> Dependencies and devDependencies</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>package-lock.json analysis:</strong> Exact version resolution</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>npm registry integration:</strong> Real-time package metadata</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>Scoped packages:</strong> Organization and user scopes</span>
                  </li>
                </ul>
              </div>
            </div>

            <div id="python">
              <h3 className="text-2xl font-semibold text-ghost-white mb-4">Python/pip</h3>
              <div className="glass rounded-lg p-6 mb-6">
                <p className="text-silver mb-4">Advanced Python package ecosystem analysis:</p>
                <ul className="space-y-2 text-silver">
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>requirements.txt parsing:</strong> Standard dependency files</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>Pipfile/Pipfile.lock:</strong> Pipenv project support</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>pyproject.toml:</strong> Modern Python packaging</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>PyPI integration:</strong> Python Package Index analysis</span>
                  </li>
                </ul>
              </div>
            </div>

            <div id="golang">
              <h3 className="text-2xl font-semibold text-ghost-white mb-4">Go Modules</h3>
              <div className="glass rounded-lg p-6 mb-6">
                <p className="text-silver mb-4">Go module system analysis and security:</p>
                <ul className="space-y-2 text-silver">
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>go.mod parsing:</strong> Module dependencies and versions</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>go.sum verification:</strong> Cryptographic checksums</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>Module proxy analysis:</strong> GOPROXY and module resolution</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>VCS integration:</strong> Git repository analysis</span>
                  </li>
                </ul>
              </div>
            </div>

            <div id="generic">
              <h3 className="text-2xl font-semibold text-ghost-white mb-4">Generic Analysis</h3>
              <div className="glass rounded-lg p-6">
                <p className="text-silver mb-4">Universal analysis capabilities for any package manager:</p>
                <ul className="space-y-2 text-silver">
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>File pattern detection:</strong> Automatic ecosystem identification</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>Custom analyzers:</strong> Extensible analysis framework</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>Multi-language projects:</strong> Polyglot repository support</span>
                  </li>
                </ul>
              </div>
            </div>
          </div>
        )

      case 'deployment':
        return (
          <div className="space-y-8">
            <div>
              <h2 className="text-3xl font-bold text-ghost-white mb-4">Deployment Options</h2>
              <p className="text-silver text-lg mb-6">
                TypoSentinel offers flexible deployment options to meet your security and 
                compliance requirements, from free open-source tools to enterprise SaaS.
              </p>
            </div>

            <div id="cli-tool">
              <h3 className="text-2xl font-semibold text-ghost-white mb-4">
                <span className="text-success-green">FREE</span> CLI Tool
              </h3>
              <div className="glass rounded-lg p-6 mb-6">
                <p className="text-silver mb-4">
                  <strong className="text-success-green">100% Free and Open Source</strong> - 
                  Full-featured command-line tool for local development and CI/CD.
                </p>
                <ul className="space-y-2 text-silver">
                  <li className="flex items-start space-x-2">
                    <span className="text-success-green">✓</span>
                    <span>All security analyzers included</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-success-green">✓</span>
                    <span>Cross-platform support (Windows, macOS, Linux)</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-success-green">✓</span>
                    <span>No API key required</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-success-green">✓</span>
                    <span>Offline operation</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-success-green">✓</span>
                    <span>CI/CD integration ready</span>
                  </li>
                </ul>
                <div className="mt-4 glass rounded-lg p-4">
                  <code className="text-success-green font-mono">
                    go install github.com/Alivanroy/Typosentinel/cmd/typosentinel@latest
                  </code>
                </div>
              </div>
            </div>

            <div id="on-premise">
              <h3 className="text-2xl font-semibold text-ghost-white mb-4">
                <span className="text-success-green">FREE</span> On-Premise API
              </h3>
              <div className="glass rounded-lg p-6 mb-6">
                <p className="text-silver mb-4">
                  <strong className="text-success-green">Free Self-Hosted API</strong> - 
                  Deploy TypoSentinel API in your own infrastructure.
                </p>
                <ul className="space-y-2 text-silver">
                  <li className="flex items-start space-x-2">
                    <span className="text-success-green">✓</span>
                    <span>Full API functionality</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-success-green">✓</span>
                    <span>Docker deployment</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-success-green">✓</span>
                    <span>Kubernetes support</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-success-green">✓</span>
                    <span>Complete data control</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-success-green">✓</span>
                    <span>No external dependencies</span>
                  </li>
                </ul>
              </div>
            </div>

            <div id="saas-api">
              <h3 className="text-2xl font-semibold text-ghost-white mb-4">
                <span className="text-electric-blue">PAID</span> SaaS API
              </h3>
              <div className="glass rounded-lg p-6 mb-6">
                <p className="text-silver mb-4">
                  Managed cloud API service with enhanced features and support.
                </p>
                <ul className="space-y-2 text-silver">
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span>Hosted and managed infrastructure</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span>Global CDN and edge locations</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span>99.9% uptime SLA</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span>Real-time threat intelligence updates</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span>Advanced analytics and reporting</span>
                  </li>
                </ul>
              </div>
            </div>

            <div id="enterprise">
              <h3 className="text-2xl font-semibold text-ghost-white mb-4">
                <span className="text-warning-orange">ENTERPRISE</span> Features
              </h3>
              <div className="glass rounded-lg p-6">
                <p className="text-silver mb-4">
                  Enterprise-grade features for large organizations and compliance requirements.
                </p>
                <ul className="space-y-2 text-silver">
                  <li className="flex items-start space-x-2">
                    <span className="text-warning-orange">★</span>
                    <span>Single Sign-On (SSO) integration</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-warning-orange">★</span>
                    <span>RBAC (Role-Based Access Control)</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-warning-orange">★</span>
                    <span>Compliance reporting (SOC2, ISO27001)</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-warning-orange">★</span>
                    <span>Custom integrations and webhooks</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-warning-orange">★</span>
                    <span>Dedicated support and SLA</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-warning-orange">★</span>
                    <span>On-premise deployment with enterprise features</span>
                  </li>
                </ul>
              </div>
            </div>
          </div>
        )

      case 'api':
        return (
          <div className="space-y-8">
            <div>
              <h2 className="text-3xl font-bold text-ghost-white mb-4">API Reference</h2>
              <p className="text-silver text-lg mb-6">
                TypoSentinel provides a comprehensive REST API for integrating security 
                scanning into your applications and workflows.
              </p>
            </div>

            <div id="api-overview">
              <h3 className="text-2xl font-semibold text-ghost-white mb-4">API Overview</h3>
              <div className="glass rounded-lg p-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <h4 className="text-lg font-semibold text-ghost-white mb-2">Base URL</h4>
                    <code className="text-electric-blue">https://api.typosentinel.com/v1</code>
                  </div>
                  <div>
                    <h4 className="text-lg font-semibold text-ghost-white mb-2">Authentication</h4>
                    <code className="text-electric-blue">Bearer Token</code>
                  </div>
                  <div>
                    <h4 className="text-lg font-semibold text-ghost-white mb-2">Rate Limits</h4>
                    <span className="text-silver">1000 requests/hour</span>
                  </div>
                  <div>
                    <h4 className="text-lg font-semibold text-ghost-white mb-2">Response Format</h4>
                    <code className="text-electric-blue">JSON</code>
                  </div>
                </div>
              </div>
            </div>

            <div id="api-endpoints">
              <h3 className="text-2xl font-semibold text-ghost-white mb-4">API Endpoints</h3>
              
              <div className="space-y-6">
                <div className="glass rounded-lg p-6">
                  <h4 className="text-lg font-semibold text-ghost-white mb-3">POST /v1/scan</h4>
                  <p className="text-silver mb-4">Scan packages for security threats</p>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                    <div>
                      <h5 className="font-semibold text-ghost-white mb-2">Request Body</h5>
                      <div className="glass rounded-lg p-3">
                        <pre className="text-success-green font-mono text-sm">
                          <code>{`{
  "packages": ["express@4.18.0"],
  "options": {
    "deep_scan": true,
    "include_dev": false,
    "analyzers": ["typosquatting", "homoglyph"]
  }
}`}</code>
                        </pre>
                      </div>
                    </div>
                    <div>
                      <h5 className="font-semibold text-ghost-white mb-2">Response</h5>
                      <div className="glass rounded-lg p-3">
                        <pre className="text-success-green font-mono text-sm">
                          <code>{`{
  "scan_id": "scan_123",
  "status": "completed",
  "threats_found": 2,
  "results": [...]
}`}</code>
                        </pre>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="glass rounded-lg p-6">
                  <h4 className="text-lg font-semibold text-ghost-white mb-3">GET /v1/scan/{'{scan_id}'}</h4>
                  <p className="text-silver mb-4">Retrieve scan results by ID</p>
                  
                  <div className="glass rounded-lg p-3">
                    <h5 className="font-semibold text-ghost-white mb-2">Response</h5>
                    <pre className="text-success-green font-mono text-sm">
                      <code>{`{
  "scan_id": "scan_123",
  "status": "completed",
  "created_at": "2024-01-15T10:30:00Z",
  "completed_at": "2024-01-15T10:30:45Z",
  "threats": [
    {
      "type": "typosquatting",
      "package": "expres",
      "severity": "high",
      "confidence": 0.95,
      "description": "Potential typosquatting of 'express'"
    }
  ]
}`}</code>
                    </pre>
                  </div>
                </div>

                <div className="glass rounded-lg p-6">
                  <h4 className="text-lg font-semibold text-ghost-white mb-3">POST /v1/monitor</h4>
                  <p className="text-silver mb-4">Set up continuous monitoring for a project</p>
                  
                  <div className="glass rounded-lg p-3">
                    <h5 className="font-semibold text-ghost-white mb-2">Request Body</h5>
                    <pre className="text-success-green font-mono text-sm">
                      <code>{`{
  "project_name": "my-app",
  "repository_url": "https://github.com/user/repo",
  "scan_frequency": "daily",
  "notification_webhook": "https://hooks.slack.com/..."
}`}</code>
                    </pre>
                  </div>
                </div>


              </div>
            </div>

            <div id="api-examples">
              <h3 className="text-2xl font-semibold text-ghost-white mb-4">Code Examples</h3>
              
              <div className="space-y-6">
                {Object.entries(codeExamples.api).map(([lang, code]) => (
                  <div key={lang} className="glass rounded-lg p-4">
                    <div className="flex items-center justify-between mb-4">
                      <span className="text-electric-blue font-medium uppercase">
                        {lang === 'curl' ? 'cURL' : lang}
                      </span>
                      <button
                        onClick={() => copyToClipboard(code, `api-${lang}`)}
                        className="flex items-center space-x-1 text-silver hover:text-ghost-white transition-colors"
                      >
                        <ClipboardDocumentIcon className="h-4 w-4" />
                        <span className="text-sm">
                          {copiedCode === `api-${lang}` ? 'Copied!' : 'Copy'}
                        </span>
                      </button>
                    </div>
                    <pre className="text-success-green font-mono text-sm overflow-x-auto">
                      <code>{code}</code>
                    </pre>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )

      case 'cli':
        return (
          <div className="space-y-8">
            <div>
              <h2 className="text-3xl font-bold text-ghost-white mb-4">CLI Reference</h2>
              <p className="text-silver text-lg mb-6">
                The TypoSentinel CLI is a powerful, free command-line tool for detecting 
                supply chain security threats in your dependencies.
              </p>
            </div>

            <div id="cli-installation">
              <h3 className="text-2xl font-semibold text-ghost-white mb-4">Installation</h3>
              <div className="space-y-4">
                <div className="glass rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-electric-blue font-medium">Go Install (Recommended)</span>
                    <button
                      onClick={() => copyToClipboard('go install github.com/Alivanroy/Typosentinel/cmd/typosentinel@latest', 'cli-go-install')}
                      className="flex items-center space-x-1 text-silver hover:text-ghost-white transition-colors"
                    >
                      <ClipboardDocumentIcon className="h-4 w-4" />
                      <span className="text-sm">
                        {copiedCode === 'cli-go-install' ? 'Copied!' : 'Copy'}
                      </span>
                    </button>
                  </div>
                  <code className="text-success-green font-mono">go install github.com/Alivanroy/Typosentinel/cmd/typosentinel@latest</code>
                </div>
                
                <div className="glass rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-electric-blue font-medium">Homebrew (macOS/Linux)</span>
                    <button
                      onClick={() => copyToClipboard('brew install typosentinel', 'cli-brew')}
                      className="flex items-center space-x-1 text-silver hover:text-ghost-white transition-colors"
                    >
                      <ClipboardDocumentIcon className="h-4 w-4" />
                      <span className="text-sm">
                        {copiedCode === 'cli-brew' ? 'Copied!' : 'Copy'}
                      </span>
                    </button>
                  </div>
                  <code className="text-success-green font-mono">brew install typosentinel</code>
                </div>

                <div className="glass rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-electric-blue font-medium">Docker</span>
                    <button
                      onClick={() => copyToClipboard('docker run --rm -v $(pwd):/workspace typosentinel/cli scan /workspace', 'cli-docker')}
                      className="flex items-center space-x-1 text-silver hover:text-ghost-white transition-colors"
                    >
                      <ClipboardDocumentIcon className="h-4 w-4" />
                      <span className="text-sm">
                        {copiedCode === 'cli-docker' ? 'Copied!' : 'Copy'}
                      </span>
                    </button>
                  </div>
                  <code className="text-success-green font-mono">docker run --rm -v $(pwd):/workspace typosentinel/cli scan /workspace</code>
                </div>
              </div>
            </div>

            <div id="cli-commands">
              <h3 className="text-2xl font-semibold text-ghost-white mb-4">Commands</h3>
              <div className="space-y-6">
                <div className="glass rounded-lg p-6">
                  <h4 className="text-lg font-semibold text-ghost-white mb-3">typosentinel scan</h4>
                  <p className="text-silver mb-4">Scan dependencies for security threats</p>
                  
                  <div className="space-y-4">
                    <div>
                      <h5 className="font-semibold text-ghost-white mb-2">Basic Usage</h5>
                      <div className="space-y-2">
                        <div className="flex items-start space-x-2">
                          <span className="text-electric-blue">•</span>
                          <code className="text-success-green">typosentinel scan package.json</code> - Scan Node.js project
                        </div>
                        <div className="flex items-start space-x-2">
                          <span className="text-electric-blue">•</span>
                          <code className="text-success-green">typosentinel scan requirements.txt</code> - Scan Python project
                        </div>
                        <div className="flex items-start space-x-2">
                          <span className="text-electric-blue">•</span>
                          <code className="text-success-green">typosentinel scan go.mod</code> - Scan Go project
                        </div>
                        <div className="flex items-start space-x-2">
                          <span className="text-electric-blue">•</span>
                          <code className="text-success-green">typosentinel scan .</code> - Auto-detect and scan current directory
                        </div>
                      </div>
                    </div>
                    
                    <div>
                      <h5 className="font-semibold text-ghost-white mb-2">Advanced Options</h5>
                      <div className="space-y-2 text-sm">
                        <div className="flex items-start space-x-2">
                          <span className="text-electric-blue">•</span>
                          <code className="text-success-green">--format json|html|pdf</code> - Output format
                        </div>
                        <div className="flex items-start space-x-2">
                          <span className="text-electric-blue">•</span>
                          <code className="text-success-green">--output filename</code> - Save results to file
                        </div>
                        <div className="flex items-start space-x-2">
                          <span className="text-electric-blue">•</span>
                          <code className="text-success-green">--threshold 0.8</code> - Detection sensitivity (0.0-1.0)
                        </div>
                        <div className="flex items-start space-x-2">
                          <span className="text-electric-blue">•</span>
                          <code className="text-success-green">--analyzers typosquatting,homoglyph</code> - Specific analyzers
                        </div>
                        <div className="flex items-start space-x-2">
                          <span className="text-electric-blue">•</span>
                          <code className="text-success-green">--exclude-dev</code> - Skip development dependencies
                        </div>
                        <div className="flex items-start space-x-2">
                          <span className="text-electric-blue">•</span>
                          <code className="text-success-green">--offline</code> - Run without network access
                        </div>
                        <div className="flex items-start space-x-2">
                          <span className="text-electric-blue">•</span>
                          <code className="text-success-green">--config config.yaml</code> - Use custom configuration
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="glass rounded-lg p-6">
                  <h4 className="text-lg font-semibold text-ghost-white mb-3">typosentinel monitor</h4>
                  <p className="text-silver mb-4">Continuous monitoring of dependencies</p>
                  
                  <div className="space-y-4">
                    <div>
                      <h5 className="font-semibold text-ghost-white mb-2">Monitoring Modes</h5>
                      <div className="space-y-2">
                        <div className="flex items-start space-x-2">
                          <span className="text-electric-blue">•</span>
                          <code className="text-success-green">typosentinel monitor --continuous</code> - Watch for file changes
                        </div>
                        <div className="flex items-start space-x-2">
                          <span className="text-electric-blue">•</span>
                          <code className="text-success-green">typosentinel monitor --interval 1h</code> - Periodic scanning
                        </div>
                        <div className="flex items-start space-x-2">
                          <span className="text-electric-blue">•</span>
                          <code className="text-success-green">typosentinel monitor --daemon</code> - Run as background service
                        </div>
                      </div>
                    </div>
                    
                    <div>
                      <h5 className="font-semibold text-ghost-white mb-2">Notification Options</h5>
                      <div className="space-y-2 text-sm">
                        <div className="flex items-start space-x-2">
                          <span className="text-electric-blue">•</span>
                          <code className="text-success-green">--webhook https://hooks.slack.com/...</code> - Slack notifications
                        </div>
                        <div className="flex items-start space-x-2">
                          <span className="text-electric-blue">•</span>
                          <code className="text-success-green">--email security@company.com</code> - Email alerts
                        </div>
                        <div className="flex items-start space-x-2">
                          <span className="text-electric-blue">•</span>
                          <code className="text-success-green">--severity high,critical</code> - Filter by severity
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="glass rounded-lg p-6">
                  <h4 className="text-lg font-semibold text-ghost-white mb-3">typosentinel report</h4>
                  <p className="text-silver mb-4">Generate detailed security reports</p>
                  
                  <div className="space-y-4">
                    <div>
                      <h5 className="font-semibold text-ghost-white mb-2">Report Formats</h5>
                      <div className="space-y-2">
                        <div className="flex items-start space-x-2">
                          <span className="text-electric-blue">•</span>
                          <code className="text-success-green">typosentinel report --format json</code> - Machine-readable JSON
                        </div>
                        <div className="flex items-start space-x-2">
                          <span className="text-electric-blue">•</span>
                          <code className="text-success-green">typosentinel report --format html</code> - Interactive HTML report
                        </div>
                        <div className="flex items-start space-x-2">
                          <span className="text-electric-blue">•</span>
                          <code className="text-success-green">typosentinel report --format pdf</code> - Executive PDF summary
                        </div>
                        <div className="flex items-start space-x-2">
                          <span className="text-electric-blue">•</span>
                          <code className="text-success-green">typosentinel report --format sarif</code> - SARIF for security tools
                        </div>
                      </div>
                    </div>
                    
                    <div>
                      <h5 className="font-semibold text-ghost-white mb-2">Report Options</h5>
                      <div className="space-y-2 text-sm">
                        <div className="flex items-start space-x-2">
                          <span className="text-electric-blue">•</span>
                          <code className="text-success-green">--output filename</code> - Save to specific file
                        </div>
                        <div className="flex items-start space-x-2">
                          <span className="text-electric-blue">•</span>
                          <code className="text-success-green">--template custom.tmpl</code> - Use custom template
                        </div>
                        <div className="flex items-start space-x-2">
                          <span className="text-electric-blue">•</span>
                          <code className="text-success-green">--include-summary</code> - Add executive summary
                        </div>
                        <div className="flex items-start space-x-2">
                          <span className="text-electric-blue">•</span>
                          <code className="text-success-green">--historical</code> - Include trend analysis
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
                
                <div className="glass rounded-lg p-6">
                  <h4 className="text-lg font-semibold text-ghost-white mb-3">typosentinel update</h4>
                  <p className="text-silver mb-4">Update threat intelligence databases</p>
                  
                  <div className="space-y-2">
                    <div className="flex items-start space-x-2">
                      <span className="text-electric-blue">•</span>
                      <code className="text-success-green">typosentinel update</code> - Update all databases
                    </div>
                    <div className="flex items-start space-x-2">
                      <span className="text-electric-blue">•</span>
                      <code className="text-success-green">typosentinel update --source osv</code> - Update specific source
                    </div>
                    <div className="flex items-start space-x-2">
                      <span className="text-electric-blue">•</span>
                      <code className="text-success-green">typosentinel update --force</code> - Force update even if recent
                    </div>
                  </div>
                </div>
                
                <div className="glass rounded-lg p-6">
                  <h4 className="text-lg font-semibold text-ghost-white mb-3">typosentinel server</h4>
                  <p className="text-silver mb-4">Start local API server (on-premise deployment)</p>
                  
                  <div className="space-y-2">
                    <div className="flex items-start space-x-2">
                      <span className="text-electric-blue">•</span>
                      <code className="text-success-green">typosentinel server</code> - Start on default port 8080
                    </div>
                    <div className="flex items-start space-x-2">
                      <span className="text-electric-blue">•</span>
                      <code className="text-success-green">typosentinel server --port 3000</code> - Custom port
                    </div>
                    <div className="flex items-start space-x-2">
                      <span className="text-electric-blue">•</span>
                      <code className="text-success-green">typosentinel server --tls-cert cert.pem --tls-key key.pem</code> - HTTPS
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div id="cli-configuration">
              <h3 className="text-2xl font-semibold text-ghost-white mb-4">Configuration</h3>
              <div className="glass rounded-lg p-6">
                <p className="text-silver mb-4">Configure TypoSentinel using a YAML configuration file:</p>
                <div className="glass rounded-lg p-4 mb-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-electric-blue font-medium">typosentinel.yaml</span>
                    <button
                      onClick={() => copyToClipboard(`# TypoSentinel Configuration\ndetection:\n  typosquatting:\n    enabled: true\n    threshold: 0.8\n  dependency_confusion:\n    enabled: true\n  homoglyph:\n    enabled: true\n\noutput:\n  format: json\n  file: results.json\n\nintegrations:\n  slack:\n    webhook_url: https://hooks.slack.com/...\n  github:\n    token: ghp_...`, 'cli-config')}
                      className="flex items-center space-x-1 text-silver hover:text-ghost-white transition-colors"
                    >
                      <ClipboardDocumentIcon className="h-4 w-4" />
                      <span className="text-sm">
                        {copiedCode === 'cli-config' ? 'Copied!' : 'Copy'}
                      </span>
                    </button>
                  </div>
                  <pre className="text-success-green font-mono text-sm overflow-x-auto">
                    <code>{`# TypoSentinel Configuration
detection:
  typosquatting:
    enabled: true
    threshold: 0.8
  dependency_confusion:
    enabled: true
  homoglyph:
    enabled: true

output:
  format: json
  file: results.json

integrations:
  slack:
    webhook_url: https://hooks.slack.com/...
  github:
    token: ghp_...`}</code>
                  </pre>
                </div>
              </div>
            </div>
          </div>
        )

      case 'integrations':
        return (
          <div className="space-y-8">
            <div>
              <h2 className="text-3xl font-bold text-ghost-white mb-4">Integrations</h2>
              <p className="text-silver text-lg mb-6">
                TypoSentinel integrates seamlessly with your existing development workflow 
                and security tools.
              </p>
            </div>

            <div id="ci-cd">
              <h3 className="text-2xl font-semibold text-ghost-white mb-4">CI/CD Integration</h3>
              
              <div className="space-y-6">
                <div className="glass rounded-lg p-6">
                  <h4 className="text-lg font-semibold text-ghost-white mb-3">GitHub Actions</h4>
                  <div className="glass rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-electric-blue font-medium">.github/workflows/security.yml</span>
                      <button
                        onClick={() => copyToClipboard(`name: Security Scan\n\non:\n  push:\n    branches: [ main ]\n  pull_request:\n    branches: [ main ]\n\njobs:\n  security-scan:\n    runs-on: ubuntu-latest\n    steps:\n    - uses: actions/checkout@v3\n    - name: Setup Go\n      uses: actions/setup-go@v3\n      with:\n        go-version: 1.21\n    - name: Install TypoSentinel\n      run: go install github.com/Alivanroy/Typosentinel/cmd/typosentinel@latest\n    - name: Run Security Scan\n      run: typosentinel scan . --format json --output security-report.json\n    - name: Upload Results\n      uses: actions/upload-artifact@v3\n      with:\n        name: security-report\n        path: security-report.json`, 'github-actions')}
                        className="flex items-center space-x-1 text-silver hover:text-ghost-white transition-colors"
                      >
                        <ClipboardDocumentIcon className="h-4 w-4" />
                        <span className="text-sm">
                          {copiedCode === 'github-actions' ? 'Copied!' : 'Copy'}
                        </span>
                      </button>
                    </div>
                    <pre className="text-success-green font-mono text-sm overflow-x-auto">
                      <code>{`name: Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Setup Go
      uses: actions/setup-go@v3
      with:
        go-version: 1.21
    - name: Install TypoSentinel
      run: go install github.com/Alivanroy/Typosentinel/cmd/typosentinel@latest
    - name: Run Security Scan
      run: typosentinel scan . --format json --output security-report.json
    - name: Upload Results
      uses: actions/upload-artifact@v3
      with:
        name: security-report
        path: security-report.json`}</code>
                    </pre>
                  </div>
                </div>

                <div className="glass rounded-lg p-6">
                  <h4 className="text-lg font-semibold text-ghost-white mb-3">GitLab CI</h4>
                  <div className="glass rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-electric-blue font-medium">.gitlab-ci.yml</span>
                      <button
                        onClick={() => copyToClipboard(`stages:\n  - security\n\nsecurity-scan:\n  stage: security\n  image: golang:1.21\n  before_script:\n    - go install github.com/Alivanroy/Typosentinel/cmd/typosentinel@latest\n  script:\n    - typosentinel scan . --format json --output security-report.json\n  artifacts:\n    reports:\n      junit: security-report.json\n    paths:\n      - security-report.json\n  only:\n    - merge_requests\n    - main`, 'gitlab-ci')}
                        className="flex items-center space-x-1 text-silver hover:text-ghost-white transition-colors"
                      >
                        <ClipboardDocumentIcon className="h-4 w-4" />
                        <span className="text-sm">
                          {copiedCode === 'gitlab-ci' ? 'Copied!' : 'Copy'}
                        </span>
                      </button>
                    </div>
                    <pre className="text-success-green font-mono text-sm overflow-x-auto">
                      <code>{`stages:
  - security

security-scan:
  stage: security
  image: golang:1.21
  before_script:
    - go install github.com/Alivanroy/Typosentinel/cmd/typosentinel@latest
  script:
    - typosentinel scan . --format json --output security-report.json
  artifacts:
    reports:
      junit: security-report.json
    paths:
      - security-report.json
  only:
    - merge_requests
    - main`}</code>
                    </pre>
                  </div>
                </div>

                <div className="glass rounded-lg p-6">
                  <h4 className="text-lg font-semibold text-ghost-white mb-3">Jenkins</h4>
                  <div className="glass rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-electric-blue font-medium">Jenkinsfile</span>
                      <button
                        onClick={() => copyToClipboard(`pipeline {\n    agent any\n    \n    stages {\n        stage('Security Scan') {\n            steps {\n                sh 'go install github.com/Alivanroy/Typosentinel/cmd/typosentinel@latest'\n                sh 'typosentinel scan . --format json --output security-report.json'\n                archiveArtifacts artifacts: 'security-report.json', fingerprint: true\n                publishHTML([\n                    allowMissing: false,\n                    alwaysLinkToLastBuild: true,\n                    keepAll: true,\n                    reportDir: '.',\n                    reportFiles: 'security-report.json',\n                    reportName: 'Security Report'\n                ])\n            }\n        }\n    }\n}`, 'jenkins')}
                        className="flex items-center space-x-1 text-silver hover:text-ghost-white transition-colors"
                      >
                        <ClipboardDocumentIcon className="h-4 w-4" />
                        <span className="text-sm">
                          {copiedCode === 'jenkins' ? 'Copied!' : 'Copy'}
                        </span>
                      </button>
                    </div>
                    <pre className="text-success-green font-mono text-sm overflow-x-auto">
                      <code>{`pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                sh 'go install github.com/Alivanroy/Typosentinel/cmd/typosentinel@latest'
                sh 'typosentinel scan . --format json --output security-report.json'
                archiveArtifacts artifacts: 'security-report.json', fingerprint: true
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: '.',
                    reportFiles: 'security-report.json',
                    reportName: 'Security Report'
                ])
            }
        }
    }
}`}</code>
                    </pre>
                  </div>
                </div>
              </div>
            </div>

            <div id="webhooks">
              <h3 className="text-2xl font-semibold text-ghost-white mb-4">Webhooks</h3>
              <div className="glass rounded-lg p-6">
                <p className="text-silver mb-4">
                  Configure webhooks to receive real-time notifications when threats are detected:
                </p>
                <ul className="space-y-2 text-silver mb-4">
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>Slack Integration:</strong> Instant alerts to your security channel</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>Microsoft Teams:</strong> Notifications with threat details</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>Discord:</strong> Community and team notifications</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-electric-blue">•</span>
                    <span><strong>Custom Webhooks:</strong> HTTP POST to your endpoints</span>
                  </li>
                </ul>
              </div>
            </div>

            <div id="third-party">
              <h3 className="text-2xl font-semibold text-ghost-white mb-4">Third-party Tools</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="glass rounded-lg p-6">
                  <h4 className="text-lg font-semibold text-ghost-white mb-3">SIEM Integration</h4>
                  <ul className="space-y-2 text-silver">
                    <li className="flex items-start space-x-2">
                      <span className="text-electric-blue">•</span>
                      <span>Splunk</span>
                    </li>
                    <li className="flex items-start space-x-2">
                      <span className="text-electric-blue">•</span>
                      <span>Elastic Security</span>
                    </li>
                    <li className="flex items-start space-x-2">
                      <span className="text-electric-blue">•</span>
                      <span>IBM QRadar</span>
                    </li>
                    <li className="flex items-start space-x-2">
                      <span className="text-electric-blue">•</span>
                      <span>Azure Sentinel</span>
                    </li>
                  </ul>
                </div>
                
                <div className="glass rounded-lg p-6">
                  <h4 className="text-lg font-semibold text-ghost-white mb-3">Security Platforms</h4>
                  <ul className="space-y-2 text-silver">
                    <li className="flex items-start space-x-2">
                      <span className="text-electric-blue">•</span>
                      <span>Snyk</span>
                    </li>
                    <li className="flex items-start space-x-2">
                      <span className="text-electric-blue">•</span>
                      <span>WhiteSource</span>
                    </li>
                    <li className="flex items-start space-x-2">
                      <span className="text-electric-blue">•</span>
                      <span>Veracode</span>
                    </li>
                    <li className="flex items-start space-x-2">
                      <span className="text-electric-blue">•</span>
                      <span>Checkmarx</span>
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        )

      case 'guides':
        return (
          <div className="space-y-8">
            <div>
              <h2 className="text-3xl font-bold text-ghost-white mb-4">Guides</h2>
              <p className="text-silver text-lg mb-6">
                Best practices, troubleshooting tips, and migration guides to help you 
                get the most out of TypoSentinel.
              </p>
            </div>

            <div id="best-practices">
              <h3 className="text-2xl font-semibold text-ghost-white mb-4">Best Practices</h3>
              
              <div className="space-y-6">
                <div className="glass rounded-lg p-6">
                  <h4 className="text-lg font-semibold text-ghost-white mb-3">Development Workflow</h4>
                  
                  <div className="space-y-4">
                    <div>
                      <h5 className="font-semibold text-ghost-white mb-2">Pre-commit Hook Setup</h5>
                      <div className="glass rounded-lg p-4 mb-2">
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-electric-blue font-medium">.pre-commit-config.yaml</span>
                          <button
                            onClick={() => copyToClipboard(`repos:\n  - repo: local\n    hooks:\n      - id: typosentinel\n        name: TypoSentinel Security Scan\n        entry: typosentinel scan\n        language: system\n        files: '(package\\.json|requirements\\.txt|go\\.mod)$'\n        pass_filenames: false`, 'precommit')}
                            className="flex items-center space-x-1 text-silver hover:text-ghost-white transition-colors"
                          >
                            <ClipboardDocumentIcon className="h-4 w-4" />
                            <span className="text-sm">
                              {copiedCode === 'precommit' ? 'Copied!' : 'Copy'}
                            </span>
                          </button>
                        </div>
                        <pre className="text-success-green font-mono text-sm overflow-x-auto">
                          <code>{`repos:
  - repo: local
    hooks:
      - id: typosentinel
        name: TypoSentinel Security Scan
        entry: typosentinel scan
        language: system
        files: '(package\\.json|requirements\\.txt|go\\.mod)$'
        pass_filenames: false`}</code>
                        </pre>
                      </div>
                    </div>
                    
                    <div>
                      <h5 className="font-semibold text-ghost-white mb-2">Package.json Scripts</h5>
                      <div className="glass rounded-lg p-4 mb-2">
                        <pre className="text-success-green font-mono text-sm overflow-x-auto">
                          <code>{`{
  "scripts": {
    "security:scan": "typosentinel scan .",
    "security:monitor": "typosentinel monitor --continuous",
    "security:report": "typosentinel report --format html",
    "preinstall": "typosentinel scan package.json",
    "postinstall": "typosentinel scan package-lock.json"
  }
}`}</code>
                        </pre>
                      </div>
                    </div>
                    
                    <div>
                      <h5 className="font-semibold text-ghost-white mb-2">VS Code Integration</h5>
                      <div className="glass rounded-lg p-4 mb-2">
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-electric-blue font-medium">.vscode/tasks.json</span>
                        </div>
                        <pre className="text-success-green font-mono text-sm overflow-x-auto">
                          <code>{`{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "TypoSentinel Scan",
      "type": "shell",
      "command": "typosentinel",
      "args": ["scan", "."],
      "group": "build",
      "presentation": {
        "echo": true,
        "reveal": "always",
        "focus": false,
        "panel": "shared"
      }
    }
  ]
}`}</code>
                        </pre>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="glass rounded-lg p-6">
                  <h4 className="text-lg font-semibold text-ghost-white mb-3">Configuration Optimization</h4>
                  
                  <div className="space-y-4">
                    <div>
                      <h5 className="font-semibold text-ghost-white mb-2">Complete Configuration Example</h5>
                      <div className="glass rounded-lg p-4 mb-2">
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-electric-blue font-medium">typosentinel.yaml</span>
                          <button
                            onClick={() => copyToClipboard(`version: "1.0"\n\n# Global settings\nsettings:\n  threshold: 0.85\n  max_concurrent_scans: 10\n  cache_duration: "24h"\n  offline_mode: false\n\n# Analyzer configuration\nanalyzers:\n  typosquatting:\n    enabled: true\n    edit_distance_threshold: 2\n    phonetic_similarity: true\n    visual_similarity: true\n    popularity_threshold: 1000\n    \n  dependency_confusion:\n    enabled: true\n    check_internal_registries: true\n    namespace_validation: true\n    \n  homoglyph:\n    enabled: true\n    unicode_categories: ["Ll", "Lu", "Nd"]\n    mixed_script_detection: true\n    \n  vulnerability:\n    enabled: true\n    sources: ["osv", "nvd", "ghsa"]\n    severity_threshold: "medium"\n\n# Language-specific settings\nlanguages:\n  nodejs:\n    package_files: ["package.json", "package-lock.json"]\n    exclude_dev_dependencies: false\n    check_peer_dependencies: true\n    \n  python:\n    package_files: ["requirements.txt", "Pipfile", "pyproject.toml"]\n    check_extras: true\n    \n  go:\n    package_files: ["go.mod", "go.sum"]\n    check_indirect: true\n\n# Exclusions\nexclusions:\n  packages:\n    - "@types/*"  # TypeScript definitions\n    - "eslint-*"  # ESLint plugins\n  paths:\n    - "test/"\n    - "docs/"`, 'config')}
                            className="flex items-center space-x-1 text-silver hover:text-ghost-white transition-colors"
                          >
                            <ClipboardDocumentIcon className="h-4 w-4" />
                            <span className="text-sm">
                              {copiedCode === 'config' ? 'Copied!' : 'Copy'}
                            </span>
                          </button>
                        </div>
                        <pre className="text-success-green font-mono text-sm overflow-x-auto max-h-64">
                          <code>{`version: "1.0"

# Global settings
settings:
  threshold: 0.85
  max_concurrent_scans: 10
  cache_duration: "24h"
  offline_mode: false

# Analyzer configuration
analyzers:
  typosquatting:
    enabled: true
    edit_distance_threshold: 2
    phonetic_similarity: true
    visual_similarity: true
    popularity_threshold: 1000
    
  dependency_confusion:
    enabled: true
    check_internal_registries: true
    namespace_validation: true
    
  homoglyph:
    enabled: true
    unicode_categories: ["Ll", "Lu", "Nd"]
    mixed_script_detection: true
    
  vulnerability:
    enabled: true
    sources: ["osv", "nvd", "ghsa"]
    severity_threshold: "medium"

# Language-specific settings
languages:
  nodejs:
    package_files: ["package.json", "package-lock.json"]
    exclude_dev_dependencies: false
    check_peer_dependencies: true
    
  python:
    package_files: ["requirements.txt", "Pipfile", "pyproject.toml"]
    check_extras: true
    
  go:
    package_files: ["go.mod", "go.sum"]
    check_indirect: true

# Exclusions
exclusions:
  packages:
    - "@types/*"  # TypeScript definitions
    - "eslint-*"  # ESLint plugins
  paths:
    - "test/"
    - "docs/"`}</code>
                        </pre>
                      </div>
                    </div>
                    
                    <div>
                      <h5 className="font-semibold text-ghost-white mb-2">Environment-Specific Configs</h5>
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div className="glass rounded p-3">
                          <h6 className="font-medium text-ghost-white mb-1">Development</h6>
                          <p className="text-silver text-sm">Lower thresholds, include dev dependencies</p>
                        </div>
                        <div className="glass rounded p-3">
                          <h6 className="font-medium text-ghost-white mb-1">Staging</h6>
                          <p className="text-silver text-sm">Production-like settings with detailed reporting</p>
                        </div>
                        <div className="glass rounded p-3">
                          <h6 className="font-medium text-ghost-white mb-1">Production</h6>
                          <p className="text-silver text-sm">High thresholds, critical alerts only</p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="glass rounded-lg p-6">
                  <h4 className="text-lg font-semibold text-ghost-white mb-3">Incident Response</h4>
                  
                  <div className="space-y-4">
                    <div>
                      <h5 className="font-semibold text-ghost-white mb-2">Emergency Response Script</h5>
                      <div className="glass rounded-lg p-4 mb-2">
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-electric-blue font-medium">emergency-response.sh</span>
                          <button
                            onClick={() => copyToClipboard(`#!/bin/bash\n# TypoSentinel Emergency Response\n\necho "🚨 TypoSentinel Emergency Response"\necho "================================="\n\n# 1. Generate immediate report\necho "📊 Generating security report..."\ntyposentinel scan . --format json --output emergency-report.json\n\n# 2. Check for active threats\necho "🔍 Checking for active threats..."\ntyposentinel scan . --analyzers vulnerability --severity critical\n\n# 3. Backup current state\necho "💾 Backing up package files..."\ncp package.json package.json.backup\ncp package-lock.json package-lock.json.backup\n\n# 4. Generate remediation report\necho "🔧 Generating remediation steps..."\ntyposentinel report --format html --include-remediation --output remediation.html\n\n# 5. Notify security team\necho "📧 Notifying security team..."\ncurl -X POST "$SLACK_WEBHOOK" -H 'Content-type: application/json' \\\n  --data '{"text":"🚨 Security incident detected. Check emergency-report.json"}'\n\necho "✅ Emergency response complete. Check reports for next steps."`, 'emergency')}
                            className="flex items-center space-x-1 text-silver hover:text-ghost-white transition-colors"
                          >
                            <ClipboardDocumentIcon className="h-4 w-4" />
                            <span className="text-sm">
                              {copiedCode === 'emergency' ? 'Copied!' : 'Copy'}
                            </span>
                          </button>
                        </div>
                        <pre className="text-success-green font-mono text-sm overflow-x-auto max-h-48">
                          <code>{`#!/bin/bash
# TypoSentinel Emergency Response

echo "🚨 TypoSentinel Emergency Response"
echo "================================="

# 1. Generate immediate report
echo "📊 Generating security report..."
typosentinel scan . --format json --output emergency-report.json

# 2. Check for active threats
echo "🔍 Checking for active threats..."
typosentinel scan . --analyzers vulnerability --severity critical

# 3. Backup current state
echo "💾 Backing up package files..."
cp package.json package.json.backup
cp package-lock.json package-lock.json.backup

# 4. Generate remediation report
echo "🔧 Generating remediation steps..."
typosentinel report --format html --include-remediation --output remediation.html

# 5. Notify security team
echo "📧 Notifying security team..."
curl -X POST "$SLACK_WEBHOOK" -H 'Content-type: application/json' \\
  --data '{"text":"🚨 Security incident detected. Check emergency-report.json"}'

echo "✅ Emergency response complete. Check reports for next steps."`}</code>
                        </pre>
                      </div>
                    </div>
                    
                    <div>
                      <h5 className="font-semibold text-ghost-white mb-2">Response Workflow</h5>
                      <div className="space-y-2">
                        <div className="flex items-start space-x-3">
                          <span className="bg-warning-orange text-dark-gray rounded-full w-6 h-6 flex items-center justify-center text-sm font-bold">1</span>
                          <div>
                            <span className="text-ghost-white font-medium">Immediate Response</span>
                            <p className="text-silver text-sm">Isolate affected systems, document findings</p>
                          </div>
                        </div>
                        <div className="flex items-start space-x-3">
                          <span className="bg-warning-orange text-dark-gray rounded-full w-6 h-6 flex items-center justify-center text-sm font-bold">2</span>
                          <div>
                            <span className="text-ghost-white font-medium">Impact Analysis</span>
                            <p className="text-silver text-sm">Assess scope, check for data exfiltration</p>
                          </div>
                        </div>
                        <div className="flex items-start space-x-3">
                          <span className="bg-warning-orange text-dark-gray rounded-full w-6 h-6 flex items-center justify-center text-sm font-bold">3</span>
                          <div>
                            <span className="text-ghost-white font-medium">Threat Validation</span>
                            <p className="text-silver text-sm">Verify if package is malicious or false positive</p>
                          </div>
                        </div>
                        <div className="flex items-start space-x-3">
                          <span className="bg-success-green text-dark-gray rounded-full w-6 h-6 flex items-center justify-center text-sm font-bold">4</span>
                          <div>
                            <span className="text-ghost-white font-medium">Remediation</span>
                            <p className="text-silver text-sm">Remove malicious packages, update dependencies</p>
                          </div>
                        </div>
                        <div className="flex items-start space-x-3">
                          <span className="bg-success-green text-dark-gray rounded-full w-6 h-6 flex items-center justify-center text-sm font-bold">5</span>
                          <div>
                            <span className="text-ghost-white font-medium">Recovery</span>
                            <p className="text-silver text-sm">Restore from clean backups, implement additional controls</p>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
                
                <div className="glass rounded-lg p-6">
                  <h4 className="text-lg font-semibold text-ghost-white mb-3">Performance Optimization</h4>
                  
                  <div className="space-y-4">
                    <div>
                      <h5 className="font-semibold text-ghost-white mb-2">High-Performance Configuration</h5>
                      <div className="glass rounded-lg p-4 mb-2">
                        <pre className="text-success-green font-mono text-sm overflow-x-auto">
                          <code>{`# High-performance configuration
settings:
  max_concurrent_scans: 20
  worker_pool_size: 8
  batch_size: 100
  timeout: "5m"
  
# For CI/CD environments
ci_optimization:
  cache_enabled: true
  cache_ttl: "1h"
  fail_fast: true
  parallel_analyzers: true
  
# Resource limits
resources:
  memory_limit: "2GB"
  cpu_limit: "4"
  disk_cache_size: "1GB"`}</code>
                        </pre>
                      </div>
                    </div>
                    
                    <div>
                      <h5 className="font-semibold text-ghost-white mb-2">Optimization Strategies</h5>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="glass rounded p-4">
                          <h6 className="font-medium text-ghost-white mb-2">Caching</h6>
                          <ul className="text-silver text-sm space-y-1">
                            <li>• Local scan result cache (24h)</li>
                            <li>• Registry metadata cache</li>
                            <li>• Vulnerability database cache</li>
                          </ul>
                        </div>
                        <div className="glass rounded p-4">
                          <h6 className="font-medium text-ghost-white mb-2">Parallel Processing</h6>
                          <ul className="text-silver text-sm space-y-1">
                            <li>• Concurrent package analysis</li>
                            <li>• Multi-threaded scanning</li>
                            <li>• Batch processing for large projects</li>
                          </ul>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div id="troubleshooting">
              <h3 className="text-2xl font-semibold text-ghost-white mb-4">Troubleshooting</h3>
              
              <div className="space-y-6">
                <div className="glass rounded-lg p-6">
                  <h4 className="text-lg font-semibold text-ghost-white mb-3">Common Issues</h4>
                  
                  <div className="space-y-4">
                    <div className="border-l-4 border-electric-blue pl-4">
                      <h5 className="font-semibold text-ghost-white mb-2">Installation Fails</h5>
                      <p className="text-silver mb-2">If Go installation fails, ensure you have Go 1.19+ installed:</p>
                      <code className="text-success-green font-mono text-sm">go version</code>
                    </div>
                    
                    <div className="border-l-4 border-electric-blue pl-4">
                      <h5 className="font-semibold text-ghost-white mb-2">Scan Takes Too Long</h5>
                      <p className="text-silver mb-2">For large projects, use the optimized configuration:</p>
                      <code className="text-success-green font-mono text-sm">typosentinel scan . --config config-optimized.yaml</code>
                    </div>
                    
                    <div className="border-l-4 border-electric-blue pl-4">
                      <h5 className="font-semibold text-ghost-white mb-2">False Positives</h5>
                      <p className="text-silver mb-2">Adjust detection thresholds or add packages to whitelist:</p>
                      <code className="text-success-green font-mono text-sm">typosentinel scan . --threshold 0.9 --whitelist approved-packages.txt</code>
                    </div>
                    
                    <div className="border-l-4 border-electric-blue pl-4">
                      <h5 className="font-semibold text-ghost-white mb-2">Network Issues</h5>
                      <p className="text-silver mb-2">Use offline mode when registry access is limited:</p>
                      <code className="text-success-green font-mono text-sm">typosentinel scan . --offline</code>
                    </div>
                  </div>
                </div>

                <div className="glass rounded-lg p-6">
                  <h4 className="text-lg font-semibold text-ghost-white mb-3">Debug Mode</h4>
                  <p className="text-silver mb-4">Enable verbose logging for detailed troubleshooting:</p>
                  <div className="glass rounded-lg p-4">
                    <code className="text-success-green font-mono">typosentinel scan . --debug --log-level trace</code>
                  </div>
                </div>
              </div>
            </div>

            <div id="migration">
              <h3 className="text-2xl font-semibold text-ghost-white mb-4">Migration Guide</h3>
              
              <div className="space-y-6">
                <div className="glass rounded-lg p-6">
                  <h4 className="text-lg font-semibold text-ghost-white mb-3">From Other Security Tools</h4>
                  
                  <div className="space-y-4">
                    <div className="border-l-4 border-success-green pl-4">
                      <h5 className="font-semibold text-ghost-white mb-2">From Snyk</h5>
                      <p className="text-silver mb-2">TypoSentinel provides additional supply chain protection:</p>
                      <ul className="text-silver text-sm space-y-1">
                        <li>• Enhanced typosquatting detection</li>
                        <li>• Dependency confusion prevention</li>
                        <li>• Homoglyph attack detection</li>
                        <li>• Free CLI and on-premise deployment</li>
                      </ul>
                    </div>
                    
                    <div className="border-l-4 border-success-green pl-4">
                      <h5 className="font-semibold text-ghost-white mb-2">From npm audit</h5>
                      <p className="text-silver mb-2">TypoSentinel extends beyond vulnerability scanning:</p>
                      <ul className="text-silver text-sm space-y-1">
                        <li>• Proactive threat detection</li>
                        <li>• Multi-language support</li>
                        <li>• Advanced ML-powered analysis</li>
                        <li>• Comprehensive reporting</li>
                      </ul>
                    </div>
                    
                    <div className="border-l-4 border-success-green pl-4">
                      <h5 className="font-semibold text-ghost-white mb-2">From Safety (Python)</h5>
                      <p className="text-silver mb-2">Migrate your Python security scanning:</p>
                      <div className="glass rounded-lg p-3 mt-2">
                        <code className="text-success-green font-mono text-sm">
                          # Replace: safety check\n
                          # With: typosentinel scan requirements.txt
                        </code>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="glass rounded-lg p-6">
                  <h4 className="text-lg font-semibold text-ghost-white mb-3">Version Upgrades</h4>
                  <p className="text-silver mb-4">Keep TypoSentinel updated for the latest threat detection:</p>
                  <div className="glass rounded-lg p-4">
                    <code className="text-success-green font-mono">go install github.com/Alivanroy/Typosentinel/cmd/typosentinel@latest</code>
                  </div>
                  <p className="text-silver text-sm mt-2">Check for breaking changes in the CHANGELOG.md before upgrading.</p>
                </div>
              </div>
            </div>
          </div>
        )

      default:
        return (
          <div className="text-center py-12">
            <DocumentTextIcon className="h-16 w-16 text-silver mx-auto mb-4" />
            <h3 className="text-xl font-semibold text-ghost-white mb-2">
              Section Coming Soon
            </h3>
            <p className="text-silver">
              This documentation section is currently being developed.
            </p>
          </div>
        )
    }
  }

  return (
    <div className="min-h-screen pt-20 pb-12">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center mb-12"
        >
          <h1 className="text-4xl md:text-6xl font-bold text-gradient mb-6 font-display">
            Open Source Documentation
          </h1>
          <p className="text-xl text-silver max-w-3xl mx-auto mb-4">
            Everything you need to integrate TypoSentinel into your development workflow
          </p>
          <div className="flex items-center justify-center space-x-4">
            <span className="text-success-green font-semibold">✓ Free CLI & On-Premise</span>
            <span className="text-silver">•</span>
            <a 
              href="https://github.com/Alivanroy/Typosentinel" 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-electric-blue hover:text-white transition-colors font-semibold"
            >
              View on GitHub →
            </a>
          </div>
        </motion.div>

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          {/* Sidebar */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            className="lg:col-span-1"
          >
            <div className="glass-strong rounded-xl p-6 sticky top-24">
              <h3 className="text-lg font-semibold text-ghost-white mb-4">
                Documentation
              </h3>
              
              <nav className="space-y-2">
                {sections.map((section) => {
                  const Icon = section.icon
                  return (
                    <div key={section.id}>
                      <button
                        onClick={() => setActiveSection(section.id)}
                        className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg text-left transition-colors ${
                          activeSection === section.id
                            ? 'bg-electric-blue/20 text-electric-blue'
                            : 'text-silver hover:text-ghost-white hover:bg-white/5'
                        }`}
                      >
                        <Icon className="h-5 w-5" />
                        <span>{section.title}</span>
                        <ChevronRightIcon className={`h-4 w-4 ml-auto transition-transform ${
                          activeSection === section.id ? 'rotate-90' : ''
                        }`} />
                      </button>
                      
                      {activeSection === section.id && section.subsections && (
                        <div className="ml-8 mt-2 space-y-1">
                          {section.subsections.map((subsection) => (
                            <a
                              key={subsection.id}
                              href={`#${subsection.id}`}
                              className="block px-3 py-1 text-sm text-silver hover:text-ghost-white transition-colors"
                            >
                              {subsection.title}
                            </a>
                          ))}
                        </div>
                      )}
                    </div>
                  )
                })}
              </nav>
            </div>
          </motion.div>

          {/* Content */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            className="lg:col-span-3"
          >
            <div className="glass-strong rounded-xl p-8">
              {renderContent()}
            </div>
          </motion.div>
        </div>
      </div>
    </div>
  )
}

export default Documentation