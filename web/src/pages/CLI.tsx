import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { 
  CommandLineIcon,
  DocumentDuplicateIcon,
  CheckIcon,
  PlayIcon,
  ArrowDownTrayIcon
} from '@heroicons/react/24/outline'

const CLI: React.FC = () => {
  const [copied, setCopied] = useState('')
  const [terminalOutput, setTerminalOutput] = useState('')
  const [isRunning, setIsRunning] = useState(false)
  const [currentCommand, setCurrentCommand] = useState('')

  const installCommands = {
    npm: 'npm install -g typosentinel',
    yarn: 'yarn global add typosentinel',
    pip: 'pip install typosentinel',
    go: 'go install github.com/Alivanroy/Typosentinel@latest',
    brew: 'brew install typosentinel'
  }

  const examples = [
    {
      title: 'Scan a single package',
      command: 'typosentinel scan react',
      description: 'Analyze a specific package for threats'
    },
    {
      title: 'Scan package.json',
      command: 'typosentinel scan --file package.json',
      description: 'Scan all dependencies in your project'
    },
    {
      title: 'Continuous monitoring',
      command: 'typosentinel monitor --watch',
      description: 'Monitor dependencies in real-time'
    },
    {
      title: 'Generate report',
      command: 'typosentinel scan --output report.json',
      description: 'Export scan results to a file'
    },
    {
      title: 'Custom threshold',
      command: 'typosentinel scan --threshold 0.8',
      description: 'Set custom risk threshold'
    }
  ]

  const copyToClipboard = (text: string, type: string) => {
    navigator.clipboard.writeText(text)
    setCopied(type)
    setTimeout(() => setCopied(''), 2000)
  }

  const runCommand = async (command: string) => {
    setCurrentCommand(command)
    setIsRunning(true)
    setTerminalOutput('')
    
    // Simulate realistic terminal output based on command
    let outputs: string[] = []
    
    if (command.includes('react')) {
      outputs = [
        '🔍 TypoSentinel v1.2.0 - Open Source Package Security Scanner',
        '📦 Analyzing package: react@18.2.0',
        '',
        '🔍 Running analyzers:',
        '  ✓ Typosquatting detection',
        '  ✓ Dependency confusion check', 
        '  ✓ Homoglyph analysis',
        '  ✓ Vulnerability scanning',
        '  ✓ Reputation analysis',
        '',
        '📊 Scan Results:',
        '  Package: react@18.2.0',
        '  Registry: npmjs.org',
        '  Maintainer: React Team',
        '  Downloads: 20M+ weekly',
        '  Risk Score: 0.1/10 (Very Low)',
        '  Threats Found: 0',
        '  Vulnerabilities: 0',
        '  Reputation: Excellent (9.8/10)',
        '',
        '✅ Package is SAFE to use',
        '⏱️  Scan completed in 0.234s'
      ]
    } else if (command.includes('package.json')) {
      outputs = [
        '🔍 TypoSentinel v1.2.0 - Scanning package.json',
        '📂 Found 42 dependencies to analyze',
        '',
        '🔍 Scanning dependencies...',
        '  ✓ react@18.2.0 - Safe',
        '  ✓ express@4.18.2 - Safe', 
        '  ✓ lodash@4.17.21 - Safe',
        '  ⚠️  some-suspicious-pkg@1.0.0 - Medium Risk',
        '  ✓ typescript@5.0.4 - Safe',
        '  ... (37 more packages)',
        '',
        '📊 Summary:',
        '  Total packages: 42',
        '  Safe: 41',
        '  Medium risk: 1',
        '  High risk: 0',
        '  Critical: 0',
        '',
        '⚠️  Review flagged packages:',
        '  • some-suspicious-pkg@1.0.0',
        '    Reason: Typosquatting similarity to "some-popular-pkg"',
        '    Confidence: 85%',
        '',
        '⏱️  Scan completed in 1.847s'
      ]
    } else if (command.includes('monitor')) {
      outputs = [
        '🔍 TypoSentinel Monitor - Starting continuous monitoring',
        '📂 Watching: ./package.json, ./requirements.txt, ./go.mod',
        '',
        '👀 Monitoring mode active...',
        '  • File system watcher: ✓',
        '  • Registry polling: ✓', 
        '  • Threat feed updates: ✓',
        '',
        '📡 Connected to threat intelligence feeds',
        '🔄 Checking for updates every 5 minutes',
        '',
        '[12:34:56] No changes detected',
        '[12:39:56] No changes detected', 
        '[12:44:56] package.json modified - rescanning...',
        '[12:44:57] New dependency added: axios@1.4.0 - Safe',
        '',
        '✅ Monitoring active. Press Ctrl+C to stop.'
      ]
    } else if (command.includes('report.json')) {
      outputs = [
        '🔍 TypoSentinel v1.2.0 - Generating detailed report',
        '📦 Analyzing package: react@18.2.0',
        '',
        '🔍 Running comprehensive analysis...',
        '  ✓ Package metadata analysis',
        '  ✓ Maintainer verification',
        '  ✓ Download pattern analysis',
        '  ✓ Code quality assessment',
        '  ✓ Security vulnerability scan',
        '',
        '📄 Generating JSON report...',
        '  • Package details: ✓',
        '  • Risk assessment: ✓',
        '  • Threat analysis: ✓',
        '  • Recommendations: ✓',
        '',
        '💾 Report saved to: report.json',
        '📊 Report size: 2.4 KB',
        '',
        '✅ Detailed analysis complete',
        '⏱️  Total time: 0.891s'
      ]
    } else {
      outputs = [
        '🔍 TypoSentinel v1.2.0 - Custom threshold scan',
        '📦 Analyzing with risk threshold: 0.8',
        '',
        '🔍 Enhanced sensitivity mode active',
        '  • Stricter typosquatting detection',
        '  • Lower confidence thresholds',
        '  • Additional heuristics enabled',
        '',
        '📊 Scan Results:',
        '  Packages analyzed: 1',
        '  Threats detected: 0',
        '  Warnings: 0',
        '  Risk threshold: 0.8/10',
        '',
        '✅ No threats above threshold',
        '⏱️  Scan completed in 0.156s'
      ]
    }
    
    for (let i = 0; i < outputs.length; i++) {
      await new Promise(resolve => setTimeout(resolve, 300))
      setTerminalOutput(prev => prev + outputs[i] + '\n')
    }
    
    setIsRunning(false)
  }

  return (
    <div className="min-h-screen pt-20 pb-12">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center mb-12"
        >
          <h1 className="text-4xl md:text-6xl font-bold text-gradient mb-6 font-display">
            CLI Tool
          </h1>
          <p className="text-xl text-silver max-w-3xl mx-auto">
            Integrate TypoSentinel directly into your development workflow. 
            <span className="text-electric-blue font-semibold">100% Free</span> CLI tool with all analyzers included.
            Scan packages, monitor dependencies, and automate security checks.
          </p>
        </motion.div>

        {/* Installation */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="glass-strong rounded-xl p-8 mb-8"
        >
          <div className="flex items-center space-x-3 mb-6">
            <ArrowDownTrayIcon className="h-8 w-8 text-electric-blue" />
            <h2 className="text-2xl font-bold text-ghost-white">
              Installation
            </h2>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {Object.entries(installCommands).map(([manager, command]) => (
              <div key={manager} className="bg-deep-black rounded-lg p-4 border border-white/20">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-semibold text-electric-blue uppercase">
                    {manager}
                  </span>
                  <button
                    onClick={() => copyToClipboard(command, manager)}
                    className="text-silver hover:text-ghost-white transition-colors"
                  >
                    {copied === manager ? (
                      <CheckIcon className="h-4 w-4 text-success-green" />
                    ) : (
                      <DocumentDuplicateIcon className="h-4 w-4" />
                    )}
                  </button>
                </div>
                <code className="text-ghost-white font-mono text-sm">
                  {command}
                </code>
              </div>
            ))}
          </div>
        </motion.div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Examples */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.2 }}
            className="glass-strong rounded-xl p-8"
          >
            <div className="flex items-center space-x-3 mb-6">
              <CommandLineIcon className="h-8 w-8 text-electric-blue" />
              <h2 className="text-2xl font-bold text-ghost-white">
                Usage Examples
              </h2>
            </div>
            
            <div className="space-y-4">
              {examples.map((example, index) => (
                <div key={index} className="bg-deep-black rounded-lg p-4 border border-white/20">
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex-1">
                      <h3 className="text-sm font-semibold text-ghost-white mb-1">
                        {example.title}
                      </h3>
                      <p className="text-xs text-silver mb-3">
                        {example.description}
                      </p>
                    </div>
                    <div className="flex space-x-2">
                      <button
                        onClick={() => runCommand(example.command)}
                        className="text-electric-blue hover:text-electric-blue/80 transition-colors"
                        disabled={isRunning}
                      >
                        <PlayIcon className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => copyToClipboard(example.command, `example-${index}`)}
                        className="text-silver hover:text-ghost-white transition-colors"
                      >
                        {copied === `example-${index}` ? (
                          <CheckIcon className="h-4 w-4 text-success-green" />
                        ) : (
                          <DocumentDuplicateIcon className="h-4 w-4" />
                        )}
                      </button>
                    </div>
                  </div>
                  <code className="text-electric-blue font-mono text-sm">
                    $ {example.command}
                  </code>
                </div>
              ))}
            </div>
          </motion.div>

          {/* Terminal */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.3 }}
            className="glass-strong rounded-xl p-8"
          >
            <div className="flex items-center space-x-3 mb-6">
              <div className="flex space-x-2">
                <div className="w-3 h-3 bg-critical-red rounded-full" />
                <div className="w-3 h-3 bg-warning-amber rounded-full" />
                <div className="w-3 h-3 bg-success-green rounded-full" />
              </div>
              <span className="text-silver text-sm font-mono">
                terminal
              </span>
            </div>
            
            <div className="bg-deep-black rounded-lg p-4 border border-white/20 h-80 overflow-auto">
              {currentCommand && (
                <div className="mb-2">
                  <span className="text-electric-blue font-mono text-sm">
                    $ {currentCommand}
                  </span>
                </div>
              )}
              
              <pre className="text-ghost-white font-mono text-sm whitespace-pre-wrap">
                {terminalOutput}
              </pre>
              
              {isRunning && (
                <div className="flex items-center space-x-2 mt-2">
                  <div className="w-2 h-2 bg-electric-blue rounded-full animate-pulse" />
                  <span className="text-silver text-sm">Running...</span>
                </div>
              )}
              
              {!terminalOutput && !isRunning && (
                <div className="text-silver text-sm">
                  Click the play button next to any command to see it in action
                </div>
              )}
            </div>
          </motion.div>
        </div>

        {/* Features */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="mt-16 grid grid-cols-1 md:grid-cols-3 gap-8"
        >
          <div className="card text-center">
            <CommandLineIcon className="h-12 w-12 text-electric-blue mx-auto mb-4" />
            <h3 className="text-xl font-bold text-ghost-white mb-2">
              100% Free & Open Source
            </h3>
            <p className="text-silver">
              Complete CLI tool with all analyzers included. No limitations, no subscriptions.
            </p>
          </div>
          
          <div className="card text-center">
            <PlayIcon className="h-12 w-12 text-success-green mx-auto mb-4" />
            <h3 className="text-xl font-bold text-ghost-white mb-2">
              Cross-Platform Support
            </h3>
            <p className="text-silver">
              Works seamlessly on Windows, macOS, and Linux with consistent behavior and performance.
            </p>
          </div>
          
          <div className="card text-center">
            <CheckIcon className="h-12 w-12 text-warning-amber mx-auto mb-4" />
            <h3 className="text-xl font-bold text-ghost-white mb-2">
              CI/CD Ready
            </h3>
            <p className="text-silver">
              Seamlessly integrate into your build pipelines, GitHub Actions, and automated workflows.
            </p>
          </div>
        </motion.div>
      </div>
    </div>
  )
}

export default CLI