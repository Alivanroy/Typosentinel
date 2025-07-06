import React, { useState } from 'react';
import './Documentation.css';

const Documentation = () => {
  const [activeSection, setActiveSection] = useState('overview');

  const sections = {
    overview: {
      title: 'Overview',
      content: (
        <div>
          <h2>Typosentinel Overview</h2>
          <p>
            Typosentinel is an advanced security tool designed to detect and prevent typosquatting attacks 
            in package managers. It uses machine learning, reputation analysis, and vulnerability scanning 
            to identify potentially malicious packages that mimic legitimate ones.
          </p>
          
          <h3>Key Features</h3>
          <ul>
            <li><strong>ML-Powered Detection:</strong> Advanced machine learning algorithms to identify suspicious packages</li>
            <li><strong>Reputation Analysis:</strong> Comprehensive reputation scoring based on multiple factors</li>
            <li><strong>Vulnerability Scanning:</strong> Integration with CVE databases for known vulnerabilities</li>
            <li><strong>Multi-Registry Support:</strong> Support for npm, PyPI, Go modules, and more</li>
            <li><strong>Real-time Monitoring:</strong> Continuous monitoring of package ecosystems</li>
            <li><strong>Dynamic Analysis:</strong> Sandbox execution for behavioral analysis</li>
          </ul>

          <h3>How It Works</h3>
          <p>
            Typosentinel analyzes packages across multiple dimensions:
          </p>
          <ol>
            <li><strong>Lexical Analysis:</strong> Detects character substitutions, insertions, and deletions</li>
            <li><strong>Behavioral Analysis:</strong> Examines package behavior in controlled environments</li>
            <li><strong>Reputation Scoring:</strong> Evaluates author credibility, download patterns, and community feedback</li>
            <li><strong>Vulnerability Assessment:</strong> Checks against known security vulnerabilities</li>
            <li><strong>ML Classification:</strong> Uses trained models to classify packages as legitimate or suspicious</li>
          </ol>
        </div>
      )
    },
    installation: {
      title: 'Installation',
      content: (
        <div>
          <h2>Installation Guide</h2>
          
          <h3>Prerequisites</h3>
          <ul>
            <li>Go 1.19 or later</li>
            <li>Docker (optional, for containerized deployment)</li>
            <li>Redis (for caching)</li>
            <li>PostgreSQL (for data storage)</li>
          </ul>

          <h3>From Source</h3>
          <pre><code>{`# Clone the repository
git clone https://github.com/Alivanroy/Typosentinel.git
cd Typosentinel

# Build the application
make build

# Run tests
make test

# Install
make install`}</code></pre>

          <h3>Using Docker</h3>
          <pre><code>{`# Pull the image
docker pull alivanroy/typosentinel:latest

# Run with docker-compose
docker-compose up -d`}</code></pre>

          <h3>Configuration</h3>
          <p>Copy the example configuration file and customize it:</p>
          <pre><code>{`cp config.yaml.example config.yaml
# Edit config.yaml with your settings`}</code></pre>
        </div>
      )
    },
    usage: {
      title: 'Usage',
      content: (
        <div>
          <h2>Usage Guide</h2>
          
          <h3>Command Line Interface</h3>
          <h4>Basic Scanning</h4>
          <pre><code>{`# Scan a single package
typosentinel scan --package react --registry npm

# Scan multiple packages
typosentinel scan --file packages.txt

# Scan with specific configuration
typosentinel scan --config custom-config.yaml --package lodash`}</code></pre>

          <h4>Batch Operations</h4>
          <pre><code>{`# Scan all packages in a project
typosentinel scan --project-dir ./my-project

# Generate report
typosentinel scan --package react --output report.json

# Continuous monitoring
typosentinel monitor --registry npm --interval 1h`}</code></pre>

          <h3>Web Interface</h3>
          <p>Access the web interface at <code>http://localhost:8080</code> after starting the server:</p>
          <pre><code>typosentinel serve --port 8080</code></pre>

          <h3>API Usage</h3>
          <h4>REST API Endpoints</h4>
          <pre><code>{`# Analyze a package
POST /api/v1/analyze
{
  "package": "react",
  "registry": "npm",
  "version": "18.2.0"
}

# Get scan results
GET /api/v1/results/{scan_id}

# List recent scans
GET /api/v1/scans?limit=10`}</code></pre>
        </div>
      )
    },
    api: {
      title: 'API Reference',
      content: (
        <div>
          <h2>API Reference</h2>
          
          <h3>Authentication</h3>
          <p>All API requests require authentication using API keys:</p>
          <pre><code>Authorization: Bearer YOUR_API_KEY</code></pre>

          <h3>Endpoints</h3>
          
          <h4>POST /api/v1/analyze</h4>
          <p>Analyze a package for potential threats.</p>
          <pre><code>{`Request:
{
  "package": "string",
  "registry": "npm|pypi|go",
  "version": "string" (optional)
}

Response:
{
  "scan_id": "uuid",
  "status": "pending|completed|failed",
  "results": {
    "risk_score": 0.85,
    "threats": [
      {
        "type": "typosquatting",
        "confidence": 0.92,
        "description": "Package name similar to 'react'"
      }
    ],
    "reputation": {
      "score": 0.15,
      "factors": ["new_author", "low_downloads"]
    },
    "vulnerabilities": [
      {
        "cve_id": "CVE-2023-1234",
        "severity": "high",
        "description": "Remote code execution"
      }
    ]
  }
}`}</code></pre>

          <h4>GET /api/v1/results/{'{scan_id}'}</h4>
          <p>Retrieve scan results by ID.</p>
          
          <h4>GET /api/v1/scans</h4>
          <p>List recent scans with pagination.</p>
          <pre><code>{`Query Parameters:
- limit: number (default: 20)
- offset: number (default: 0)
- status: string (pending|completed|failed)`}</code></pre>

          <h4>POST /api/v1/batch</h4>
          <p>Submit multiple packages for analysis.</p>
          
          <h4>GET /api/v1/stats</h4>
          <p>Get system statistics and metrics.</p>
        </div>
      )
    },
    configuration: {
      title: 'Configuration',
      content: (
        <div>
          <h2>Configuration Guide</h2>
          
          <h3>Configuration File Structure</h3>
          <pre><code>{`# config.yaml
server:
  host: "0.0.0.0"
  port: 8080
  tls:
    enabled: false
    cert_file: ""
    key_file: ""

database:
  type: "postgres"
  host: "localhost"
  port: 5432
  name: "typosentinel"
  user: "postgres"
  password: "password"
  ssl_mode: "disable"

redis:
  host: "localhost"
  port: 6379
  password: ""
  db: 0

ml_analysis:
  enabled: true
  model_path: "./models/"
  similarity_threshold: 0.8
  malicious_threshold: 0.7
  batch_size: 100

reputation:
  enabled: true
  min_downloads: 1000
  min_age_days: 30
  author_weight: 0.3
  community_weight: 0.4

vulnerability:
  enabled: true
  cve_api_url: "https://services.nvd.nist.gov/rest/json/cves/2.0"
  update_interval: "24h"

logging:
  level: "info"
  format: "json"
  output: "stdout"`}</code></pre>

          <h3>Environment Variables</h3>
          <p>You can override configuration using environment variables:</p>
          <pre><code>{`TYPOSENTINEL_SERVER_PORT=8080
TYPOSENTINEL_DATABASE_HOST=localhost
TYPOSENTINEL_REDIS_HOST=localhost
TYPOSENTINEL_ML_ENABLED=true`}</code></pre>

          <h3>Advanced Configuration</h3>
          <h4>Custom Detection Rules</h4>
          <pre><code>{`detection:
  rules:
    - name: "suspicious_keywords"
      type: "keyword"
      patterns: ["hack", "exploit", "malware"]
      weight: 0.8
    - name: "typo_patterns"
      type: "levenshtein"
      threshold: 2
      weight: 0.9`}</code></pre>
        </div>
      )
    },
    troubleshooting: {
      title: 'Troubleshooting',
      content: (
        <div>
          <h2>Troubleshooting Guide</h2>
          
          <h3>Common Issues</h3>
          
          <h4>Database Connection Issues</h4>
          <p><strong>Problem:</strong> Cannot connect to PostgreSQL database</p>
          <p><strong>Solution:</strong></p>
          <ul>
            <li>Verify database credentials in config.yaml</li>
            <li>Ensure PostgreSQL is running: <code>systemctl status postgresql</code></li>
            <li>Check network connectivity: <code>telnet localhost 5432</code></li>
            <li>Verify database exists: <code>psql -U postgres -l</code></li>
          </ul>

          <h4>Redis Connection Issues</h4>
          <p><strong>Problem:</strong> Cannot connect to Redis cache</p>
          <p><strong>Solution:</strong></p>
          <ul>
            <li>Check Redis status: <code>redis-cli ping</code></li>
            <li>Verify Redis configuration in config.yaml</li>
            <li>Check Redis logs: <code>tail -f /var/log/redis/redis-server.log</code></li>
          </ul>

          <h4>ML Model Loading Issues</h4>
          <p><strong>Problem:</strong> Machine learning models fail to load</p>
          <p><strong>Solution:</strong></p>
          <ul>
            <li>Verify model files exist in the specified path</li>
            <li>Check file permissions: <code>ls -la ./models/</code></li>
            <li>Download models: <code>typosentinel download-models</code></li>
            <li>Verify model format compatibility</li>
          </ul>

          <h3>Performance Issues</h3>
          
          <h4>Slow Scan Performance</h4>
          <ul>
            <li>Enable Redis caching</li>
            <li>Increase batch size in configuration</li>
            <li>Use parallel processing: <code>parallel_processing: true</code></li>
            <li>Optimize database queries with indexes</li>
          </ul>

          <h4>High Memory Usage</h4>
          <ul>
            <li>Reduce ML model batch size</li>
            <li>Enable garbage collection tuning</li>
            <li>Monitor with: <code>typosentinel metrics</code></li>
          </ul>

          <h3>Debug Mode</h3>
          <p>Enable debug logging for detailed troubleshooting:</p>
          <pre><code>{`# In config.yaml
logging:
  level: "debug"
  
# Or via environment variable
TYPOSENTINEL_LOG_LEVEL=debug typosentinel scan --package react`}</code></pre>

          <h3>Getting Help</h3>
          <ul>
            <li>Check the <a href="https://github.com/Alivanroy/Typosentinel/issues">GitHub Issues</a></li>
            <li>Join our <a href="#">Discord Community</a></li>
            <li>Read the <a href="#">FAQ</a></li>
            <li>Contact support: support@typosentinel.com</li>
          </ul>
        </div>
      )
    }
  };

  return (
    <div className="documentation">
      <div className="documentation-sidebar">
        <h3>Documentation</h3>
        <nav>
          {Object.entries(sections).map(([key, section]) => (
            <button
              key={key}
              className={`nav-item ${activeSection === key ? 'active' : ''}`}
              onClick={() => setActiveSection(key)}
            >
              {section.title}
            </button>
          ))}
        </nav>
      </div>
      
      <div className="documentation-content">
        <div className="content-wrapper">
          {sections[activeSection].content}
        </div>
      </div>
    </div>
  );
};

export default Documentation;