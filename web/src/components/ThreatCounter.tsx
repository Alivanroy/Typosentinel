import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { ExclamationTriangleIcon, ShieldCheckIcon, EyeIcon } from '@heroicons/react/24/outline'

interface CounterProps {
  end: number
  duration?: number
  suffix?: string
  prefix?: string
}

const AnimatedCounter: React.FC<CounterProps> = ({ end, duration = 2, suffix = '', prefix = '' }) => {
  const [count, setCount] = useState(0)

  useEffect(() => {
    let startTime: number
    let animationFrame: number

    const animate = (timestamp: number) => {
      if (!startTime) startTime = timestamp
      const progress = Math.min((timestamp - startTime) / (duration * 1000), 1)
      
      setCount(Math.floor(progress * end))
      
      if (progress < 1) {
        animationFrame = requestAnimationFrame(animate)
      }
    }

    animationFrame = requestAnimationFrame(animate)
    return () => cancelAnimationFrame(animationFrame)
  }, [end, duration])

  return (
    <span>
      {prefix}{count.toLocaleString()}{suffix}
    </span>
  )
}

const ThreatCounter: React.FC = () => {
  const [isVisible, setIsVisible] = useState(false)

  useEffect(() => {
    setIsVisible(true)
  }, [])

  const stats = [
    {
      icon: ExclamationTriangleIcon,
      value: 2847392,
      suffix: '+',
      label: 'Threats Detected',
      sublabel: 'This Month',
      color: 'text-warning-amber',
      bgColor: 'bg-warning-amber/10'
    },
    {
      icon: ShieldCheckIcon,
      value: 15672,
      suffix: '+',
      label: 'Packages Secured',
      sublabel: 'Today',
      color: 'text-success-green',
      bgColor: 'bg-success-green/10'
    },
    {
      icon: EyeIcon,
      value: 847,
      suffix: '',
      label: 'Active Scans',
      sublabel: 'Right Now',
      color: 'text-electric-blue',
      bgColor: 'bg-electric-blue/10'
    }
  ]

  return (
    <motion.div
      initial={{ opacity: 0, y: 50 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.8 }}
      className="glass-strong rounded-2xl p-8 max-w-4xl mx-auto"
    >
      <div className="text-center mb-8">
        <h3 className="text-2xl font-bold text-ghost-white mb-2">
          Real-Time Threat Intelligence
        </h3>
        <p className="text-silver">
          Our AI guardian never sleeps, continuously protecting the software ecosystem
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {stats.map((stat, index) => (
          <motion.div
            key={stat.label}
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5, delay: index * 0.2 }}
            className="text-center group"
          >
            <div className={`inline-flex items-center justify-center w-16 h-16 rounded-full ${stat.bgColor} mb-4 group-hover:scale-110 transition-transform`}>
              <stat.icon className={`h-8 w-8 ${stat.color}`} />
            </div>
            
            <div className={`text-3xl md:text-4xl font-bold ${stat.color} mb-2`}>
              {isVisible && (
                <AnimatedCounter 
                  end={stat.value} 
                  suffix={stat.suffix}
                  duration={2 + index * 0.5}
                />
              )}
            </div>
            
            <div className="text-lg font-semibold text-ghost-white mb-1">
              {stat.label}
            </div>
            
            <div className="text-sm text-silver">
              {stat.sublabel}
            </div>
          </motion.div>
        ))}
      </div>

      {/* Live Activity Indicator */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.8, delay: 1 }}
        className="flex items-center justify-center mt-8 pt-6 border-t border-silver/20"
      >
        <div className="flex items-center space-x-2">
          <div className="w-3 h-3 bg-success-green rounded-full animate-pulse" />
          <span className="text-sm text-silver">
            Live monitoring active across all package registries
          </span>
        </div>
      </motion.div>
    </motion.div>
  )
}

export default ThreatCounter