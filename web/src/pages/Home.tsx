import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Link } from 'react-router-dom'
import { 
  ShieldCheckIcon, 
  CpuChipIcon, 
  GlobeAltIcon, 
  BoltIcon,
  EyeIcon,
  ChartBarIcon,
  CodeBracketIcon,
  DocumentTextIcon,
  ExclamationTriangleIcon,
  MagnifyingGlassIcon,
  CogIcon,
  ServerIcon
} from '@heroicons/react/24/outline'

// Components
import HeroSection from '../components/HeroSection'
import ThreatCounter from '../components/ThreatCounter'
import AICapabilities from '../components/AICapabilities'
import PerformanceMetrics from '../components/PerformanceMetrics'
import ClientLogos from '../components/ClientLogos'
import SecurityCertifications from '../components/SecurityCertifications'
import ThreatDashboardPreview from '../components/ThreatDashboardPreview'

const Home: React.FC = () => {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.5 }}
      className="min-h-screen"
    >
      {/* Hero Section */}
      <HeroSection />

      {/* Threat Intelligence Dashboard Preview */}
      <section className="py-20 relative">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 50 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
            viewport={{ once: true }}
            className="text-center mb-16"
          >
            <h2 className="text-4xl md:text-5xl font-bold text-gradient mb-6">
              Real-Time Threat Intelligence
            </h2>
            <p className="text-xl text-silver max-w-3xl mx-auto">
              Watch our AI guardian analyze millions of packages in real-time, 
              detecting threats before they reach your supply chain.
            </p>
          </motion.div>
          
          <ThreatDashboardPreview />
        </div>
      </section>

      {/* AI Capabilities Showcase */}
      <section className="py-20 relative">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 50 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
            viewport={{ once: true }}
            className="text-center mb-16"
          >
            <h2 className="text-4xl md:text-5xl font-bold text-gradient mb-6">
              AI-Powered Detection Engine
            </h2>
            <p className="text-xl text-silver max-w-3xl mx-auto">
              Our machine learning models continuously evolve to stay ahead of emerging threats.
            </p>
          </motion.div>
          
          <AICapabilities />
        </div>
      </section>

      {/* Performance Metrics */}
      <section className="py-20 relative">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 50 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
            viewport={{ once: true }}
            className="text-center mb-16"
          >
            <h2 className="text-4xl md:text-5xl font-bold text-gradient mb-6">
              Unmatched Performance
            </h2>
            <p className="text-xl text-silver max-w-3xl mx-auto">
              Lightning-fast analysis with industry-leading accuracy rates.
            </p>
          </motion.div>
          
          <PerformanceMetrics />
        </div>
      </section>

      {/* Features Grid */}
      <section className="py-20 relative">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 50 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
            viewport={{ once: true }}
            className="text-center mb-16"
          >
            <h2 className="text-4xl md:text-5xl font-bold text-gradient mb-6">
              Complete Security Arsenal
            </h2>
            <p className="text-xl text-silver max-w-3xl mx-auto">
              Every tool you need to secure your software supply chain.
            </p>
          </motion.div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {[
              {
                icon: ShieldCheckIcon,
                title: 'Typosquatting Detection',
                description: 'Advanced algorithms detect malicious packages that mimic legitimate ones using edit distance and similarity analysis.',
                color: 'text-electric-blue'
              },
              {
                icon: ExclamationTriangleIcon,
                title: 'Dependency Confusion',
                description: 'Detect packages that exploit dependency confusion attacks across public and private repositories.',
                color: 'text-critical-red'
              },
              {
                icon: MagnifyingGlassIcon,
                title: 'Homoglyph Detection',
                description: 'Identify packages using visually similar characters to deceive developers.',
                color: 'text-warning-amber'
              },
              {
                icon: CodeBracketIcon,
                title: 'Multi-Language Support',
                description: 'Supports Node.js (npm), Python (PyPI), Go modules, and generic package analysis.',
                color: 'text-success-green'
              },
              {
                icon: CpuChipIcon,
                title: 'AI-Powered Analysis',
                description: 'Machine learning models trained on millions of packages for accurate threat detection.',
                color: 'text-cyber-purple'
              },
              {
                icon: DocumentTextIcon,
                title: 'Vulnerability Scanning',
                description: 'Comprehensive vulnerability database integration for known security issues.',
                color: 'text-info-blue'
              },
              {
                icon: ServerIcon,
                title: 'Cross-Platform',
                description: 'Works seamlessly on Windows, macOS, and Linux with consistent behavior.',
                color: 'text-neon-cyan'
              },
              {
                icon: CogIcon,
                title: 'Open Source & Free',
                description: 'Completely free CLI tool and on-premise deployment. SaaS API available for cloud usage.',
                color: 'text-electric-blue'
              },
              {
                icon: BoltIcon,
                title: 'Lightning Fast',
                description: 'Scan thousands of dependencies in seconds with our optimized Go-based engine.',
                color: 'text-warning-amber'
              }
            ].map((feature, index) => (
              <motion.div
                key={feature.title}
                initial={{ opacity: 0, y: 50 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: index * 0.1 }}
                viewport={{ once: true }}
                className="card-glow group cursor-pointer"
              >
                <feature.icon className={`h-12 w-12 ${feature.color} mb-4 group-hover:scale-110 transition-transform`} />
                <h3 className="text-xl font-bold text-ghost-white mb-3">{feature.title}</h3>
                <p className="text-silver">{feature.description}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Client Logos */}
      <section className="py-20 relative">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 50 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
            viewport={{ once: true }}
            className="text-center mb-16"
          >
            <h2 className="text-2xl font-bold text-silver mb-8">
              Trusted by Leading Organizations
            </h2>
          </motion.div>
          
          <ClientLogos />
        </div>
      </section>

      {/* Security Certifications */}
      <section className="py-20 relative">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <SecurityCertifications />
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 relative">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <motion.div
            initial={{ opacity: 0, y: 50 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
            viewport={{ once: true }}
            className="glass-strong rounded-2xl p-12"
          >
            <h2 className="text-4xl md:text-5xl font-bold text-gradient mb-6">
              Ready to Secure Your Supply Chain?
            </h2>
            <p className="text-xl text-silver mb-8 max-w-2xl mx-auto">
              Join thousands of developers who trust TypoSentinel to protect their dependencies.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Link to="/demo" className="btn-primary text-lg px-8 py-4">
                Try Interactive Demo
              </Link>
              <Link to="/api" className="btn-ghost text-lg px-8 py-4">
                Explore API
              </Link>
            </div>
          </motion.div>
        </div>
      </section>
    </motion.div>
  )
}

export default Home