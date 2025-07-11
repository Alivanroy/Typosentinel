import React from 'react'
import { motion } from 'framer-motion'
import { 
  ShieldCheckIcon, 
  LockClosedIcon, 
  DocumentCheckIcon, 
  GlobeAltIcon,
  KeyIcon,
  EyeSlashIcon
} from '@heroicons/react/24/outline'

const SecurityCertifications: React.FC = () => {
  const certifications = [
    {
      name: 'SOC 2 Type II',
      description: 'Security, availability, and confidentiality controls',
      icon: ShieldCheckIcon,
      color: 'text-success-green',
      bgColor: 'bg-success-green/10',
      status: 'Certified'
    },
    {
      name: 'ISO 27001',
      description: 'Information security management systems',
      icon: LockClosedIcon,
      color: 'text-electric-blue',
      bgColor: 'bg-electric-blue/10',
      status: 'Certified'
    },
    {
      name: 'GDPR Compliant',
      description: 'European data protection regulation compliance',
      icon: DocumentCheckIcon,
      color: 'text-cyber-purple',
      bgColor: 'bg-cyber-purple/10',
      status: 'Compliant'
    },
    {
      name: 'CCPA Compliant',
      description: 'California consumer privacy act compliance',
      icon: EyeSlashIcon,
      color: 'text-neon-cyan',
      bgColor: 'bg-neon-cyan/10',
      status: 'Compliant'
    },
    {
      name: 'PCI DSS',
      description: 'Payment card industry data security standard',
      icon: KeyIcon,
      color: 'text-warning-amber',
      bgColor: 'bg-warning-amber/10',
      status: 'Level 1'
    },
    {
      name: 'NIST Framework',
      description: 'Cybersecurity framework implementation',
      icon: GlobeAltIcon,
      color: 'text-info-blue',
      bgColor: 'bg-info-blue/10',
      status: 'Aligned'
    }
  ]

  const securityFeatures = [
    {
      title: 'End-to-End Encryption',
      description: 'All data encrypted in transit and at rest using AES-256',
      icon: LockClosedIcon
    },
    {
      title: 'Zero Trust Architecture',
      description: 'Never trust, always verify - comprehensive access controls',
      icon: ShieldCheckIcon
    },
    {
      title: 'Regular Security Audits',
      description: 'Third-party penetration testing and vulnerability assessments',
      icon: DocumentCheckIcon
    },
    {
      title: 'Data Residency Control',
      description: 'Choose where your data is stored and processed globally',
      icon: GlobeAltIcon
    }
  ]

  return (
    <div className="space-y-12">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 30 }}
        whileInView={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.8 }}
        viewport={{ once: true }}
        className="text-center"
      >
        <h2 className="text-3xl md:text-4xl font-bold text-gradient mb-4">
          Enterprise-Grade Security
        </h2>
        <p className="text-xl text-silver max-w-3xl mx-auto">
          Built with security-first principles and certified to the highest industry standards
        </p>
      </motion.div>

      {/* Certifications Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {certifications.map((cert, index) => (
          <motion.div
            key={cert.name}
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: index * 0.1 }}
            viewport={{ once: true }}
            className="glass-strong rounded-xl p-6 group hover:scale-105 transition-transform duration-300"
          >
            <div className="flex items-start space-x-4">
              <div className={`flex-shrink-0 w-12 h-12 rounded-lg ${cert.bgColor} flex items-center justify-center group-hover:scale-110 transition-transform`}>
                <cert.icon className={`h-6 w-6 ${cert.color}`} />
              </div>
              
              <div className="flex-1">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-lg font-bold text-ghost-white">
                    {cert.name}
                  </h3>
                  <span className={`text-xs px-2 py-1 rounded-full ${cert.bgColor} ${cert.color} font-medium`}>
                    {cert.status}
                  </span>
                </div>
                <p className="text-silver text-sm">
                  {cert.description}
                </p>
              </div>
            </div>
          </motion.div>
        ))}
      </div>

      {/* Security Features */}
      <motion.div
        initial={{ opacity: 0, y: 30 }}
        whileInView={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.8 }}
        viewport={{ once: true }}
        className="glass-strong rounded-2xl p-8"
      >
        <div className="text-center mb-8">
          <h3 className="text-2xl font-bold text-ghost-white mb-2">
            Security by Design
          </h3>
          <p className="text-silver">
            Every component built with security as the foundation
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {securityFeatures.map((feature, index) => (
            <motion.div
              key={feature.title}
              initial={{ opacity: 0, x: index % 2 === 0 ? -30 : 30 }}
              whileInView={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.5, delay: index * 0.2 }}
              viewport={{ once: true }}
              className="flex items-start space-x-4 p-4 glass-subtle rounded-lg"
            >
              <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-electric-blue/10 flex items-center justify-center">
                <feature.icon className="h-5 w-5 text-electric-blue" />
              </div>
              
              <div>
                <h4 className="text-lg font-semibold text-ghost-white mb-2">
                  {feature.title}
                </h4>
                <p className="text-silver text-sm">
                  {feature.description}
                </p>
              </div>
            </motion.div>
          ))}
        </div>
      </motion.div>

      {/* Security Stats */}
      <motion.div
        initial={{ opacity: 0, y: 30 }}
        whileInView={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.8 }}
        viewport={{ once: true }}
        className="grid grid-cols-1 md:grid-cols-4 gap-6"
      >
        {[
          {
            stat: '0',
            label: 'Security Breaches',
            description: 'Perfect security record since inception'
          },
          {
            stat: '24/7',
            label: 'Security Monitoring',
            description: 'Continuous threat detection and response'
          },
          {
            stat: '< 1min',
            label: 'Incident Response',
            description: 'Automated threat mitigation and alerts'
          },
          {
            stat: '256-bit',
            label: 'Encryption Standard',
            description: 'Military-grade encryption for all data'
          }
        ].map((item, index) => (
          <motion.div
            key={item.label}
            initial={{ opacity: 0, scale: 0.8 }}
            whileInView={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5, delay: index * 0.1 }}
            viewport={{ once: true }}
            className="text-center p-6 glass-strong rounded-xl"
          >
            <div className="text-3xl font-bold text-gradient mb-2">
              {item.stat}
            </div>
            <div className="text-lg font-semibold text-ghost-white mb-2">
              {item.label}
            </div>
            <div className="text-sm text-silver">
              {item.description}
            </div>
          </motion.div>
        ))}
      </motion.div>

      {/* Trust Badge */}
      <motion.div
        initial={{ opacity: 0, y: 30 }}
        whileInView={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.8 }}
        viewport={{ once: true }}
        className="text-center"
      >
        <div className="inline-flex items-center space-x-3 px-6 py-3 glass-strong rounded-full">
          <ShieldCheckIcon className="h-6 w-6 text-success-green" />
          <span className="text-ghost-white font-medium">
            Trusted by security teams worldwide
          </span>
          <div className="w-2 h-2 bg-success-green rounded-full animate-pulse" />
        </div>
      </motion.div>
    </div>
  )
}

export default SecurityCertifications