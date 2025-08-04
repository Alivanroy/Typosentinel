import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { 
  PlayIcon, 
  ShieldCheckIcon, 
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  ClockIcon
} from '@heroicons/react/24/outline'

const Demo: React.FC = () => {
  const [isScanning, setIsScanning] = useState(false)
  const [scanResults, setScanResults] = useState<any[]>([])
  const [selectedPackage, setSelectedPackage] = useState('')

  const mockPackages = [
    'react',
    'lodash',
    'express',
    'axios',
    'moment',
    'chalk',
    'commander',
    'debug'
  ]

  const mockThreats = [
    {
      package: 'reactt',
      type: 'Typosquatting',
      severity: 'High',
      confidence: 95,
      description: 'Suspicious package mimicking popular "react" library'
    },
    {
      package: 'lodaash',
      type: 'Typosquatting', 
      severity: 'Critical',
      confidence: 98,
      description: 'Malicious package attempting to impersonate "lodash"'
    },
    {
      package: 'expres',
      type: 'Dependency Confusion',
      severity: 'Medium',
      confidence: 87,
      description: 'Potential dependency confusion attack targeting "express"'
    }
  ]

  const handleScan = async () => {
    if (!selectedPackage) return
    
    setIsScanning(true)
    setScanResults([])
    
    // Simulate scanning process
    await new Promise(resolve => setTimeout(resolve, 2000))
    
    // Mock results based on selected package
    const threats = mockThreats.filter(threat => 
      threat.package.includes(selectedPackage.toLowerCase()) ||
      selectedPackage.toLowerCase().includes(threat.package)
    )
    
    setScanResults(threats.length > 0 ? threats : [
      {
        package: selectedPackage,
        type: 'Clean',
        severity: 'Safe',
        confidence: 99,
        description: 'No threats detected for this package'
      }
    ])
    
    setIsScanning(false)
  }

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'text-critical-red'
      case 'high': return 'text-warning-amber'
      case 'medium': return 'text-info-blue'
      case 'safe': return 'text-success-green'
      default: return 'text-silver'
    }
  }

  const getSeverityIcon = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
      case 'high':
        return <XCircleIcon className="h-5 w-5" />
      case 'medium':
        return <ExclamationTriangleIcon className="h-5 w-5" />
      case 'safe':
        return <CheckCircleIcon className="h-5 w-5" />
      default:
        return <ClockIcon className="h-5 w-5" />
    }
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
            Live Demo
          </h1>
          <p className="text-xl text-silver max-w-3xl mx-auto">
            Experience TypoSentinel's AI-powered threat detection in real-time. 
            Test our advanced algorithms against known typosquatting attacks.
          </p>
        </motion.div>

        {/* Demo Interface */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="max-w-4xl mx-auto"
        >
          {/* Scan Input */}
          <div className="glass-strong rounded-xl p-8 mb-8">
            <div className="flex items-center space-x-4 mb-6">
              <ShieldCheckIcon className="h-8 w-8 text-electric-blue" />
              <h2 className="text-2xl font-bold text-ghost-white">
                Package Security Scanner
              </h2>
            </div>
            
            <div className="flex flex-col md:flex-row gap-4">
              <div className="flex-1">
                <label className="block text-sm font-medium text-silver mb-2">
                  Package Name
                </label>
                <input
                  type="text"
                  value={selectedPackage}
                  onChange={(e) => setSelectedPackage(e.target.value)}
                  placeholder="Enter package name (e.g., react, lodash)"
                  className="w-full px-4 py-3 bg-deep-black border border-white/20 rounded-lg text-ghost-white placeholder-silver focus:border-electric-blue focus:outline-none transition-colors"
                />
                
                {/* Quick Select */}
                <div className="mt-3">
                  <p className="text-sm text-silver mb-2">Quick select:</p>
                  <div className="flex flex-wrap gap-2">
                    {mockPackages.map((pkg) => (
                      <button
                        key={pkg}
                        onClick={() => setSelectedPackage(pkg)}
                        className="px-3 py-1 text-sm bg-white/10 hover:bg-white/20 rounded-md text-silver hover:text-ghost-white transition-colors"
                      >
                        {pkg}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
              
              <div className="flex items-end">
                <button
                  onClick={handleScan}
                  disabled={!selectedPackage || isScanning}
                  className="btn-primary flex items-center space-x-2 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isScanning ? (
                    <>
                      <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white" />
                      <span>Scanning...</span>
                    </>
                  ) : (
                    <>
                      <PlayIcon className="h-5 w-5" />
                      <span>Scan Package</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>

          {/* Scan Results */}
          {(scanResults.length > 0 || isScanning) && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="glass-strong rounded-xl p-8"
            >
              <h3 className="text-xl font-bold text-ghost-white mb-6">
                Scan Results
              </h3>
              
              {isScanning ? (
                <div className="text-center py-12">
                  <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-electric-blue mx-auto mb-4" />
                  <p className="text-silver">Analyzing package for threats...</p>
                  <div className="mt-4 space-y-2">
                    <div className="text-sm text-silver">• Checking typosquatting patterns</div>
                    <div className="text-sm text-silver">• Analyzing dependency confusion risks</div>
                    <div className="text-sm text-silver">• Validating package integrity</div>
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  {scanResults.map((result, index) => (
                    <motion.div
                      key={index}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: index * 0.1 }}
                      className="bg-white/5 rounded-lg p-6 border border-white/10"
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center space-x-3 mb-2">
                            <span className={getSeverityColor(result.severity)}>
                              {getSeverityIcon(result.severity)}
                            </span>
                            <h4 className="text-lg font-semibold text-ghost-white">
                              {result.package}
                            </h4>
                            <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                              result.severity === 'Safe' 
                                ? 'bg-success-green/20 text-success-green'
                                : result.severity === 'Critical'
                                ? 'bg-critical-red/20 text-critical-red'
                                : result.severity === 'High'
                                ? 'bg-warning-amber/20 text-warning-amber'
                                : 'bg-info-blue/20 text-info-blue'
                            }`}>
                              {result.severity}
                            </span>
                          </div>
                          
                          <p className="text-silver mb-3">
                            {result.description}
                          </p>
                          
                          <div className="flex items-center space-x-4 text-sm">
                            <span className="text-silver">
                              Type: <span className="text-ghost-white">{result.type}</span>
                            </span>
                            <span className="text-silver">
                              Confidence: <span className="text-ghost-white">{result.confidence}%</span>
                            </span>
                          </div>
                        </div>
                      </div>
                    </motion.div>
                  ))}
                </div>
              )}
            </motion.div>
          )}
        </motion.div>

        {/* Demo Features */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="mt-16 grid grid-cols-1 md:grid-cols-3 gap-8"
        >
          <div className="card text-center">
            <ShieldCheckIcon className="h-12 w-12 text-electric-blue mx-auto mb-4" />
            <h3 className="text-xl font-bold text-ghost-white mb-2">
              Real-time Detection
            </h3>
            <p className="text-silver">
              Instant threat analysis using advanced ML algorithms
            </p>
          </div>
          
          <div className="card text-center">
            <ExclamationTriangleIcon className="h-12 w-12 text-warning-amber mx-auto mb-4" />
            <h3 className="text-xl font-bold text-ghost-white mb-2">
              Multiple Attack Vectors
            </h3>
            <p className="text-silver">
              Detects typosquatting, dependency confusion, and more
            </p>
          </div>
          
          <div className="card text-center">
            <CheckCircleIcon className="h-12 w-12 text-success-green mx-auto mb-4" />
            <h3 className="text-xl font-bold text-ghost-white mb-2">
              High Accuracy
            </h3>
            <p className="text-silver">
              99.7% detection accuracy with minimal false positives
            </p>
          </div>
        </motion.div>
      </div>
    </div>
  )
}

export default Demo