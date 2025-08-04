import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { 
  BoltIcon, 
  ShieldCheckIcon, 
  ClockIcon, 
  CpuChipIcon,
  ChartBarIcon,
  GlobeAltIcon
} from '@heroicons/react/24/outline'

interface MetricProps {
  value: number
  suffix: string
  label: string
  description: string
  icon: React.ComponentType<any>
  color: string
  bgColor: string
  duration?: number
}

const AnimatedMetric: React.FC<MetricProps> = ({ 
  value, 
  suffix, 
  label, 
  description, 
  icon: Icon, 
  color, 
  bgColor,
  duration = 2 
}) => {
  const [count, setCount] = useState(0)
  const [isVisible, setIsVisible] = useState(false)

  useEffect(() => {
    if (!isVisible) return

    let startTime: number
    let animationFrame: number

    const animate = (timestamp: number) => {
      if (!startTime) startTime = timestamp
      const progress = Math.min((timestamp - startTime) / (duration * 1000), 1)
      
      setCount(progress * value)
      
      if (progress < 1) {
        animationFrame = requestAnimationFrame(animate)
      }
    }

    animationFrame = requestAnimationFrame(animate)
    return () => cancelAnimationFrame(animationFrame)
  }, [value, duration, isVisible])

  return (
    <motion.div
      initial={{ opacity: 0, y: 50 }}
      whileInView={{ opacity: 1, y: 0 }}
      onViewportEnter={() => setIsVisible(true)}
      transition={{ duration: 0.6 }}
      viewport={{ once: true }}
      className="glass-strong rounded-xl p-6 text-center group hover:scale-105 transition-transform duration-300"
    >
      <div className={`inline-flex items-center justify-center w-16 h-16 rounded-full ${bgColor} mb-4 group-hover:scale-110 transition-transform`}>
        <Icon className={`h-8 w-8 ${color}`} />
      </div>
      
      <div className={`text-4xl md:text-5xl font-bold ${color} mb-2`}>
        {suffix === '%' ? count.toFixed(1) : Math.floor(count).toLocaleString()}{suffix}
      </div>
      
      <h3 className="text-xl font-bold text-ghost-white mb-2">
        {label}
      </h3>
      
      <p className="text-silver text-sm">
        {description}
      </p>
    </motion.div>
  )
}

const PerformanceMetrics: React.FC = () => {
  const [activeMetric, setActiveMetric] = useState(0)

  const metrics = [
    {
      value: 99.9,
      suffix: '%',
      label: 'Detection Accuracy',
      description: 'AI-powered precision in identifying malicious packages',
      icon: ShieldCheckIcon,
      color: 'text-success-green',
      bgColor: 'bg-success-green/10',
      duration: 2.5
    },
    {
      value: 50,
      suffix: 'ms',
      label: 'Average Scan Time',
      description: 'Lightning-fast analysis of package dependencies',
      icon: BoltIcon,
      color: 'text-warning-amber',
      bgColor: 'bg-warning-amber/10',
      duration: 2
    },
    {
      value: 99.99,
      suffix: '%',
      label: 'Uptime Reliability',
      description: 'Always-on protection for your development workflow',
      icon: ClockIcon,
      color: 'text-electric-blue',
      bgColor: 'bg-electric-blue/10',
      duration: 3
    },
    {
      value: 10000000,
      suffix: '+',
      label: 'Packages Analyzed',
      description: 'Comprehensive coverage across all major registries',
      icon: CpuChipIcon,
      color: 'text-cyber-purple',
      bgColor: 'bg-cyber-purple/10',
      duration: 3.5
    },
    {
      value: 0.001,
      suffix: '%',
      label: 'False Positive Rate',
      description: 'Minimal disruption to your development process',
      icon: ChartBarIcon,
      color: 'text-neon-cyan',
      bgColor: 'bg-neon-cyan/10',
      duration: 2.5
    },
    {
      value: 150,
      suffix: '+',
      label: 'Countries Protected',
      description: 'Global reach with localized threat intelligence',
      icon: GlobeAltIcon,
      color: 'text-info-blue',
      bgColor: 'bg-info-blue/10',
      duration: 2
    }
  ]

  useEffect(() => {
    const interval = setInterval(() => {
      setActiveMetric((prev) => (prev + 1) % metrics.length)
    }, 3000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="space-y-12">
      {/* Main Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {metrics.map((metric, index) => (
          <AnimatedMetric key={metric.label} {...metric} />
        ))}
      </div>

      {/* Performance Comparison */}
      <motion.div
        initial={{ opacity: 0, y: 50 }}
        whileInView={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.8 }}
        viewport={{ once: true }}
        className="glass-strong rounded-2xl p-8"
      >
        <div className="text-center mb-8">
          <h3 className="text-2xl font-bold text-ghost-white mb-2">
            Performance Comparison
          </h3>
          <p className="text-silver">
            See how TypoSentinel outperforms traditional security tools
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {[
            {
              category: 'Speed',
              typosentinel: '50ms',
              traditional: '5-10s',
              improvement: '200x faster'
            },
            {
              category: 'Accuracy',
              typosentinel: '99.9%',
              traditional: '85-90%',
              improvement: '15% better'
            },
            {
              category: 'Coverage',
              typosentinel: '10M+ packages',
              traditional: '1M packages',
              improvement: '10x more'
            }
          ].map((comparison, index) => (
            <motion.div
              key={comparison.category}
              initial={{ opacity: 0, scale: 0.8 }}
              whileInView={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.5, delay: index * 0.2 }}
              viewport={{ once: true }}
              className="text-center"
            >
              <h4 className="text-lg font-bold text-ghost-white mb-4">
                {comparison.category}
              </h4>
              
              <div className="space-y-3">
                <div className="glass-subtle rounded-lg p-3">
                  <div className="text-sm text-silver mb-1">TypoSentinel</div>
                  <div className="text-xl font-bold text-success-green">
                    {comparison.typosentinel}
                  </div>
                </div>
                
                <div className="glass-subtle rounded-lg p-3">
                  <div className="text-sm text-silver mb-1">Traditional Tools</div>
                  <div className="text-xl font-bold text-warning-amber">
                    {comparison.traditional}
                  </div>
                </div>
                
                <div className="text-sm font-medium text-electric-blue">
                  {comparison.improvement}
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </motion.div>

      {/* Real-time Performance Monitor */}
      <motion.div
        initial={{ opacity: 0, y: 50 }}
        whileInView={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.8 }}
        viewport={{ once: true }}
        className="glass-strong rounded-2xl p-8"
      >
        <div className="flex items-center justify-between mb-6">
          <div>
            <h3 className="text-xl font-bold text-ghost-white mb-1">
              Live Performance Monitor
            </h3>
            <p className="text-silver text-sm">
              Real-time system performance metrics
            </p>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-success-green rounded-full animate-pulse" />
            <span className="text-sm text-success-green font-medium">Live</span>
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'CPU Usage', value: '12%', color: 'text-success-green' },
            { label: 'Memory', value: '2.1GB', color: 'text-electric-blue' },
            { label: 'Active Scans', value: '847', color: 'text-warning-amber' },
            { label: 'Queue', value: '23', color: 'text-cyber-purple' }
          ].map((stat, index) => (
            <motion.div
              key={stat.label}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: index * 0.1 }}
              className="text-center p-3 glass-subtle rounded-lg"
            >
              <div className={`text-lg font-bold ${stat.color} mb-1`}>
                {stat.value}
              </div>
              <div className="text-xs text-silver">
                {stat.label}
              </div>
            </motion.div>
          ))}
        </div>
      </motion.div>
    </div>
  )
}

export default PerformanceMetrics