import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { 
  CpuChipIcon, 
  CogIcon, 
  EyeIcon, 
  ShieldCheckIcon,
  BoltIcon,
  ChartBarIcon
} from '@heroicons/react/24/outline'

const AICapabilities: React.FC = () => {
  const [activeCapability, setActiveCapability] = useState(0)
  const [processingStage, setProcessingStage] = useState(0)

  const capabilities = [
    {
      icon: CpuChipIcon,
      title: 'Neural Network Analysis',
      description: 'Deep learning models trained on millions of packages to identify subtle patterns in malicious code.',
      features: [
        'Multi-layer perceptron architecture',
        'Real-time pattern recognition',
        'Continuous model updates',
        '99.9% accuracy rate'
      ],
      color: 'text-electric-blue',
      bgColor: 'bg-electric-blue/10'
    },
    {
      icon: CogIcon,
      title: 'Behavioral Analysis',
      description: 'AI monitors package behavior patterns to detect anomalies and suspicious activities.',
      features: [
        'Runtime behavior monitoring',
        'Anomaly detection algorithms',
        'Predictive threat modeling',
        'Zero-day threat detection'
      ],
      color: 'text-cyber-purple',
      bgColor: 'bg-cyber-purple/10'
    },
    {
      icon: EyeIcon,
      title: 'Computer Vision',
      description: 'Advanced image recognition to detect visual similarities in package names and logos.',
      features: [
        'OCR-based name analysis',
        'Logo similarity detection',
        'Visual phishing identification',
        'Brand impersonation alerts'
      ],
      color: 'text-neon-cyan',
      bgColor: 'bg-neon-cyan/10'
    },
    {
      icon: ShieldCheckIcon,
      title: 'Threat Intelligence',
      description: 'Machine learning aggregates global threat data to predict and prevent new attack vectors.',
      features: [
        'Global threat correlation',
        'Predictive analytics',
        'Threat actor profiling',
        'Attack vector prediction'
      ],
      color: 'text-success-green',
      bgColor: 'bg-success-green/10'
    }
  ]

  const processingStages = [
    'Ingesting package data...',
    'Analyzing code patterns...',
    'Checking threat databases...',
    'Running ML models...',
    'Generating risk score...',
    'Analysis complete!'
  ]

  useEffect(() => {
    const interval = setInterval(() => {
      setActiveCapability((prev) => (prev + 1) % capabilities.length)
    }, 4000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    const interval = setInterval(() => {
      setProcessingStage((prev) => (prev + 1) % processingStages.length)
    }, 1000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
      {/* AI Processing Visualization */}
      <motion.div
        initial={{ opacity: 0, x: -50 }}
        whileInView={{ opacity: 1, x: 0 }}
        transition={{ duration: 0.8 }}
        viewport={{ once: true }}
        className="relative"
      >
        <div className="glass-strong rounded-2xl p-8">
          <div className="text-center mb-8">
            <h3 className="text-2xl font-bold text-ghost-white mb-2">
              AI Processing Pipeline
            </h3>
            <p className="text-silver">
              Watch our AI analyze packages in real-time
            </p>
          </div>

          {/* Processing Visualization */}
          <div className="relative">
            {/* Central Processing Unit */}
            <div className="flex justify-center mb-8">
              <motion.div
                animate={{ 
                  scale: [1, 1.1, 1],
                  rotate: [0, 180, 360]
                }}
                transition={{ 
                  duration: 3, 
                  repeat: Infinity,
                  ease: "easeInOut"
                }}
                className="w-24 h-24 bg-gradient-to-br from-electric-blue to-cyber-purple rounded-full flex items-center justify-center"
              >
                <CpuChipIcon className="h-12 w-12 text-white" />
              </motion.div>
            </div>

            {/* Processing Stages */}
            <div className="space-y-3">
              {processingStages.map((stage, index) => (
                <motion.div
                  key={stage}
                  initial={{ opacity: 0.3 }}
                  animate={{ 
                    opacity: index === processingStage ? 1 : 0.3,
                    scale: index === processingStage ? 1.05 : 1
                  }}
                  transition={{ duration: 0.3 }}
                  className={`flex items-center space-x-3 p-3 rounded-lg ${
                    index === processingStage ? 'glass-strong' : 'glass-subtle'
                  }`}
                >
                  <div className={`w-3 h-3 rounded-full ${
                    index === processingStage ? 'bg-electric-blue animate-pulse' : 'bg-silver/30'
                  }`} />
                  <span className={`text-sm ${
                    index === processingStage ? 'text-ghost-white font-medium' : 'text-silver'
                  }`}>
                    {stage}
                  </span>
                  {index === processingStage && (
                    <motion.div
                      animate={{ rotate: 360 }}
                      transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                      className="ml-auto"
                    >
                      <BoltIcon className="h-4 w-4 text-electric-blue" />
                    </motion.div>
                  )}
                </motion.div>
              ))}
            </div>
          </div>
        </div>
      </motion.div>

      {/* Capabilities List */}
      <motion.div
        initial={{ opacity: 0, x: 50 }}
        whileInView={{ opacity: 1, x: 0 }}
        transition={{ duration: 0.8 }}
        viewport={{ once: true }}
        className="space-y-6"
      >
        {capabilities.map((capability, index) => (
          <motion.div
            key={capability.title}
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: index * 0.1 }}
            viewport={{ once: true }}
            className={`glass-strong rounded-xl p-6 cursor-pointer transition-all duration-300 ${
              index === activeCapability ? 'ring-2 ring-electric-blue/50' : ''
            }`}
            onClick={() => setActiveCapability(index)}
          >
            <div className="flex items-start space-x-4">
              <div className={`flex-shrink-0 w-12 h-12 rounded-lg ${capability.bgColor} flex items-center justify-center`}>
                <capability.icon className={`h-6 w-6 ${capability.color}`} />
              </div>
              
              <div className="flex-1">
                <h4 className="text-xl font-bold text-ghost-white mb-2">
                  {capability.title}
                </h4>
                <p className="text-silver mb-4">
                  {capability.description}
                </p>
                
                {/* Features List */}
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ 
                    height: index === activeCapability ? 'auto' : 0,
                    opacity: index === activeCapability ? 1 : 0
                  }}
                  transition={{ duration: 0.3 }}
                  className="overflow-hidden"
                >
                  <ul className="space-y-2">
                    {capability.features.map((feature, featureIndex) => (
                      <motion.li
                        key={feature}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.3, delay: featureIndex * 0.1 }}
                        className="flex items-center space-x-2 text-sm text-silver"
                      >
                        <ChartBarIcon className={`h-4 w-4 ${capability.color}`} />
                        <span>{feature}</span>
                      </motion.li>
                    ))}
                  </ul>
                </motion.div>
              </div>
            </div>
          </motion.div>
        ))}
      </motion.div>
    </div>
  )
}

export default AICapabilities