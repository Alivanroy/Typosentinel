import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Link } from 'react-router-dom'
import { PlayIcon, ShieldCheckIcon, BoltIcon } from '@heroicons/react/24/outline'
import ThreatCounter from './ThreatCounter'

const HeroSection: React.FC = () => {
  const [currentText, setCurrentText] = useState(0)
  const heroTexts = [
    'Typosquatting Attacks',
    'Malicious Packages',
    'Supply Chain Threats',
    'Dependency Confusion'
  ]

  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentText((prev) => (prev + 1) % heroTexts.length)
    }, 3000)
    return () => clearInterval(interval)
  }, [])

  return (
    <section className="relative min-h-screen flex items-center justify-center overflow-hidden">
      {/* Animated Background Elements */}
      <div className="absolute inset-0">
        <div className="absolute top-20 left-10 w-64 h-64 bg-electric-blue/10 rounded-full blur-3xl animate-float" />
        <div className="absolute bottom-20 right-10 w-96 h-96 bg-cyber-purple/10 rounded-full blur-3xl animate-float" style={{ animationDelay: '2s' }} />
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-neon-cyan/5 rounded-full blur-3xl animate-pulse" />
      </div>

      {/* Scan Line Effect */}
      <div className="absolute inset-0 scan-line opacity-30" />

      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
        <motion.div
          initial={{ opacity: 0, y: 50 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          className="mb-8"
        >
          <div className="inline-flex items-center px-4 py-2 rounded-full glass-subtle border border-electric-blue/30 mb-6">
            <ShieldCheckIcon className="h-5 w-5 text-electric-blue mr-2" />
            <span className="text-sm font-medium text-electric-blue">Open Source AI-Powered Security Platform</span>
          </div>
        </motion.div>

        <motion.h1
          initial={{ opacity: 0, y: 50 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.2 }}
          className="text-5xl md:text-7xl lg:text-8xl font-bold mb-8"
        >
          <span className="text-ghost-white">Defend Against</span>
          <br />
          <motion.span
            key={currentText}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.5 }}
            className="text-gradient inline-block"
          >
            {heroTexts[currentText]}
          </motion.span>
        </motion.h1>

        <motion.p
          initial={{ opacity: 0, y: 50 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.4 }}
          className="text-xl md:text-2xl text-silver max-w-4xl mx-auto mb-12 leading-relaxed"
        >
          TypoSentinel's open source AI guardian continuously monitors your software supply chain, 
          detecting malicious packages and typosquatting attacks before they compromise your systems.
          <br />
          <span className="text-electric-blue font-semibold">Free • Cross-Platform • Self-Hostable</span>
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 50 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.6 }}
          className="flex flex-col sm:flex-row gap-6 justify-center items-center mb-16"
        >
          <Link to="/demo" className="btn-primary text-lg px-8 py-4 group">
            <BoltIcon className="h-5 w-5 mr-2 group-hover:animate-pulse" />
            Start Free Scan
          </Link>
          <a href="https://github.com/Alivanroy/Typosentinel" target="_blank" rel="noopener noreferrer" className="btn-ghost text-lg px-8 py-4 group">
            <svg className="h-5 w-5 mr-2 group-hover:scale-110 transition-transform" fill="currentColor" viewBox="0 0 24 24">
              <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
            </svg>
            View on GitHub
          </a>
        </motion.div>

        {/* Threat Counter */}
        <motion.div
          initial={{ opacity: 0, y: 50 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.8 }}
          className="mb-16"
        >
          <ThreatCounter />
        </motion.div>

        {/* Trust Indicators */}
        <motion.div
          initial={{ opacity: 0, y: 50 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 1.0 }}
          className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-4xl mx-auto"
        >
          {[
            {
              number: '99.9%',
              label: 'Detection Accuracy',
              description: 'AI-powered precision'
            },
            {
              number: '<100ms',
              label: 'Scan Speed',
              description: 'Lightning-fast analysis'
            },
            {
              number: '24/7',
              label: 'Monitoring',
              description: 'Continuous protection'
            }
          ].map((stat, index) => (
            <div key={stat.label} className="text-center group">
              <div className="text-3xl md:text-4xl font-bold text-gradient mb-2 group-hover:scale-110 transition-transform">
                {stat.number}
              </div>
              <div className="text-lg font-semibold text-ghost-white mb-1">
                {stat.label}
              </div>
              <div className="text-sm text-silver">
                {stat.description}
              </div>
            </div>
          ))}
        </motion.div>
      </div>

      {/* Floating Elements */}
      <motion.div
        animate={{
          y: [0, -20, 0],
          rotate: [0, 5, 0]
        }}
        transition={{
          duration: 6,
          repeat: Infinity,
          ease: "easeInOut"
        }}
        className="absolute top-20 right-20 hidden lg:block"
      >
        <div className="w-16 h-16 border-2 border-electric-blue/30 rounded-lg rotate-45 bg-electric-blue/5" />
      </motion.div>

      <motion.div
        animate={{
          y: [0, 20, 0],
          rotate: [0, -5, 0]
        }}
        transition={{
          duration: 8,
          repeat: Infinity,
          ease: "easeInOut",
          delay: 2
        }}
        className="absolute bottom-32 left-20 hidden lg:block"
      >
        <div className="w-12 h-12 border-2 border-cyber-purple/30 rounded-full bg-cyber-purple/5" />
      </motion.div>
    </section>
  )
}

export default HeroSection