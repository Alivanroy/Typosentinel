import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { 
  CodeBracketIcon,
  PlayIcon,
  DocumentDuplicateIcon,
  CheckIcon
} from '@heroicons/react/24/outline'

const APIPlayground: React.FC = () => {
  const [selectedEndpoint, setSelectedEndpoint] = useState('/scan')
  const [requestBody, setRequestBody] = useState(JSON.stringify({
    "package_name": "react",
    "version": "18.2.0",
    "registry": "npm"
  }, null, 2))
  const [response, setResponse] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [copied, setCopied] = useState(false)

  const endpoints = [
    {
      method: 'POST',
      path: '/scan',
      description: 'Scan a package for threats',
      example: {
        "package_name": "react",
        "version": "18.2.0",
        "registry": "npm"
      }
    },
    {
      method: 'POST',
      path: '/batch-scan',
      description: 'Scan multiple packages',
      example: {
        "packages": [
          { "name": "react", "version": "18.2.0" },
          { "name": "lodash", "version": "4.17.21" }
        ]
      }
    }
  ]

  const handleSendRequest = async () => {
    setIsLoading(true)
    
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 1500))
    
    const mockResponse = {
      status: 'success',
      data: {
        package_name: 'react',
        version: '18.2.0',
        threats_detected: 0,
        risk_score: 0.1,
        analysis: {
          typosquatting_risk: 'low',
          dependency_confusion: 'none',
          malware_detected: false,
          reputation_score: 9.8
        },
        scan_time: '0.234s'
      }
    }
    
    setResponse(JSON.stringify(mockResponse, null, 2))
    setIsLoading(false)
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
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
            API Playground
          </h1>
          <p className="text-xl text-silver max-w-3xl mx-auto">
            Test our REST API endpoints in real-time. Integrate TypoSentinel's 
            threat detection capabilities into your applications.
          </p>
        </motion.div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* API Explorer */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            className="space-y-6"
          >
            {/* Endpoint Selection */}
            <div className="glass-strong rounded-xl p-6">
              <h2 className="text-xl font-bold text-ghost-white mb-4 flex items-center">
                <CodeBracketIcon className="h-6 w-6 text-electric-blue mr-2" />
                API Endpoints
              </h2>
              
              <div className="space-y-3">
                {endpoints.map((endpoint, index) => (
                  <button
                    key={index}
                    onClick={() => {
                      setSelectedEndpoint(endpoint.path)
                      setRequestBody(JSON.stringify(endpoint.example, null, 2))
                    }}
                    className={`w-full text-left p-4 rounded-lg border transition-all ${
                      selectedEndpoint === endpoint.path
                        ? 'border-electric-blue bg-electric-blue/10'
                        : 'border-white/20 hover:border-white/40'
                    }`}
                  >
                    <div className="flex items-center space-x-3 mb-2">
                      <span className={`px-2 py-1 rounded text-xs font-mono ${
                        endpoint.method === 'GET' 
                          ? 'bg-success-green/20 text-success-green'
                          : 'bg-info-blue/20 text-info-blue'
                      }`}>
                        {endpoint.method}
                      </span>
                      <span className="font-mono text-ghost-white">
                        {endpoint.path}
                      </span>
                    </div>
                    <p className="text-sm text-silver">
                      {endpoint.description}
                    </p>
                  </button>
                ))}
              </div>
            </div>

            {/* Request Body */}
            <div className="glass-strong rounded-xl p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-ghost-white">
                  Request Body
                </h3>
                <button
                  onClick={() => copyToClipboard(requestBody)}
                  className="flex items-center space-x-2 text-sm text-silver hover:text-ghost-white transition-colors"
                >
                  {copied ? (
                    <CheckIcon className="h-4 w-4 text-success-green" />
                  ) : (
                    <DocumentDuplicateIcon className="h-4 w-4" />
                  )}
                  <span>{copied ? 'Copied!' : 'Copy'}</span>
                </button>
              </div>
              
              <textarea
                value={requestBody}
                onChange={(e) => setRequestBody(e.target.value)}
                className="w-full h-40 bg-deep-black border border-white/20 rounded-lg p-4 text-ghost-white font-mono text-sm focus:border-electric-blue focus:outline-none resize-none"
                placeholder="Enter JSON request body..."
              />
              
              <button
                onClick={handleSendRequest}
                disabled={isLoading}
                className="btn-primary mt-4 w-full flex items-center justify-center space-x-2"
              >
                {isLoading ? (
                  <>
                    <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white" />
                    <span>Sending...</span>
                  </>
                ) : (
                  <>
                    <PlayIcon className="h-5 w-5" />
                    <span>Send Request</span>
                  </>
                )}
              </button>
            </div>
          </motion.div>

          {/* Response */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            className="glass-strong rounded-xl p-6"
          >
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-ghost-white">
                Response
              </h3>
              {response && (
                <button
                  onClick={() => copyToClipboard(response)}
                  className="flex items-center space-x-2 text-sm text-silver hover:text-ghost-white transition-colors"
                >
                  <DocumentDuplicateIcon className="h-4 w-4" />
                  <span>Copy</span>
                </button>
              )}
            </div>
            
            <div className="bg-deep-black border border-white/20 rounded-lg p-4 h-96 overflow-auto">
              {isLoading ? (
                <div className="flex items-center justify-center h-full">
                  <div className="text-center">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-electric-blue mx-auto mb-4" />
                    <p className="text-silver">Processing request...</p>
                  </div>
                </div>
              ) : response ? (
                <pre className="text-ghost-white font-mono text-sm whitespace-pre-wrap">
                  {response}
                </pre>
              ) : (
                <div className="flex items-center justify-center h-full">
                  <p className="text-silver text-center">
                    Send a request to see the response here
                  </p>
                </div>
              )}
            </div>
          </motion.div>
        </div>

        {/* API Documentation */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="mt-16 glass-strong rounded-xl p-8"
        >
          <h2 className="text-2xl font-bold text-ghost-white mb-6">
            API Documentation
          </h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div>
              <h3 className="text-lg font-semibold text-ghost-white mb-4">
                Authentication
              </h3>
              <div className="bg-deep-black rounded-lg p-4 border border-white/20">
                <code className="text-electric-blue text-sm">
                  Authorization: Bearer YOUR_API_KEY
                </code>
              </div>
              <p className="text-silver text-sm mt-2">
                Include your API key in the Authorization header
              </p>
            </div>
            
            <div>
              <h3 className="text-lg font-semibold text-ghost-white mb-4">
                Rate Limits
              </h3>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-silver">Free Tier:</span>
                  <span className="text-ghost-white">100 requests/hour</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-silver">Pro Tier:</span>
                  <span className="text-ghost-white">1,000 requests/hour</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-silver">Enterprise:</span>
                  <span className="text-ghost-white">Unlimited</span>
                </div>
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  )
}

export default APIPlayground