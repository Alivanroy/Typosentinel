import React from 'react'
import { motion } from 'framer-motion'

const ClientLogos: React.FC = () => {
  // Mock client logos - in a real app, these would be actual logo images
  const clients = [
    { name: 'TechCorp', industry: 'Technology' },
    { name: 'SecureBank', industry: 'Financial' },
    { name: 'CloudSoft', industry: 'Software' },
    { name: 'DataFlow', industry: 'Analytics' },
    { name: 'CyberShield', industry: 'Security' },
    { name: 'DevOps Pro', industry: 'DevOps' },
    { name: 'AI Systems', industry: 'AI/ML' },
    { name: 'BlockChain Inc', industry: 'Blockchain' }
  ]

  const LogoPlaceholder: React.FC<{ name: string; index: number }> = ({ name, index }) => (
    <motion.div
      initial={{ opacity: 0, scale: 0.8 }}
      whileInView={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.5, delay: index * 0.1 }}
      viewport={{ once: true }}
      whileHover={{ scale: 1.05 }}
      className="flex items-center justify-center h-20 px-8 glass-subtle rounded-lg group cursor-pointer"
    >
      <div className="text-center">
        <div className="text-lg font-bold text-ghost-white group-hover:text-electric-blue transition-colors">
          {name}
        </div>
        <div className="w-full h-0.5 bg-gradient-to-r from-electric-blue to-cyber-purple mt-2 opacity-0 group-hover:opacity-100 transition-opacity" />
      </div>
    </motion.div>
  )

  return (
    <div className="space-y-8">
      {/* Main Logo Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
        {clients.map((client, index) => (
          <LogoPlaceholder key={client.name} name={client.name} index={index} />
        ))}
      </div>

      {/* Animated Logo Carousel */}
      <motion.div
        initial={{ opacity: 0 }}
        whileInView={{ opacity: 1 }}
        transition={{ duration: 0.8 }}
        viewport={{ once: true }}
        className="relative overflow-hidden"
      >
        <div className="flex space-x-8 animate-scroll">
          {[...clients, ...clients].map((client, index) => (
            <div
              key={`${client.name}-${index}`}
              className="flex-shrink-0 flex items-center justify-center h-16 px-6 glass-subtle rounded-lg"
            >
              <span className="text-silver font-medium whitespace-nowrap">
                {client.name}
              </span>
            </div>
          ))}
        </div>
      </motion.div>

      {/* Trust Indicators */}
      <motion.div
        initial={{ opacity: 0, y: 30 }}
        whileInView={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.8 }}
        viewport={{ once: true }}
        className="text-center"
      >
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-4xl mx-auto">
          {[
            {
              stat: '500+',
              label: 'Enterprise Clients',
              description: 'Fortune 500 companies trust our platform'
            },
            {
              stat: '50M+',
              label: 'Packages Protected',
              description: 'Dependencies secured across all clients'
            },
            {
              stat: '99.9%',
              label: 'Client Satisfaction',
              description: 'Consistently rated as industry leader'
            }
          ].map((item, index) => (
            <motion.div
              key={item.label}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: index * 0.2 }}
              viewport={{ once: true }}
              className="text-center"
            >
              <div className="text-3xl font-bold text-gradient mb-2">
                {item.stat}
              </div>
              <div className="text-lg font-semibold text-ghost-white mb-1">
                {item.label}
              </div>
              <div className="text-sm text-silver">
                {item.description}
              </div>
            </motion.div>
          ))}
        </div>
      </motion.div>
    </div>
  )
}

export default ClientLogos