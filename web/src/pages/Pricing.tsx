import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { 
  CheckIcon,
  XMarkIcon,
  StarIcon,
  ShieldCheckIcon,
  BoltIcon,
  GlobeAltIcon
} from '@heroicons/react/24/outline'

const Pricing: React.FC = () => {
  const [isAnnual, setIsAnnual] = useState(false)
  const [selectedPlan, setSelectedPlan] = useState('pro')

  const plans = [
    {
      id: 'opensource',
      name: 'Open Source',
      description: 'Complete free solution for self-hosting and CLI usage',
      price: { monthly: 0, annual: 0 },
      features: [
        'Unlimited CLI scans',
        'All threat detection analyzers',
        'Self-hosted on-premise deployment',
        'On-premise API (unlimited)',
        'All programming languages supported',
        'Cross-platform support',
        'Community support',
        'Full source code access',
        'No usage limitations',
        'CI/CD integration'
      ],
      limitations: [],
      cta: 'Download & Install',
      popular: true
    },
    {
      id: 'saas',
      name: 'SaaS API',
      description: 'Managed cloud API with enterprise features',
      price: { monthly: 49, annual: 39 },
      features: [
        'Cloud-hosted API',
        'No infrastructure management',
        'Global CDN and caching',
        'Advanced analytics dashboard',
        'Real-time threat intelligence feeds',
        'Priority support',
        'SLA guarantees',
        'Advanced reporting',
        'Slack/Teams notifications',
        'Custom integrations'
      ],
      limitations: [],
      cta: 'Start SaaS Trial',
      popular: false
    },
    {
      id: 'enterprise',
      name: 'Enterprise SaaS',
      description: 'Enterprise cloud solution with advanced features',
      price: { monthly: 199, annual: 159 },
      features: [
        'Everything in SaaS API',
        'SSO integration (SAML, OIDC)',
        'Advanced user management',
        'Custom threat intelligence feeds',
        'White-label solutions',
        'Dedicated support team',
        'Custom SLA (99.9% uptime)',
        'Compliance reporting (SOC2, ISO27001)',
        'Advanced analytics & insights',
        'Multi-tenant architecture',
        'Custom integrations',
        'Priority feature requests'
      ],
      limitations: [],
      cta: 'Contact Sales',
      popular: false
    }
  ]

  const features = [
    {
      category: 'Core Features',
      items: [
        { name: 'CLI Tool', opensource: 'Unlimited', saas: 'N/A', enterprise: 'N/A' },
        { name: 'On-Premise API', opensource: 'Unlimited', saas: 'N/A', enterprise: 'N/A' },
        { name: 'Cloud API', opensource: 'N/A', saas: 'Included', enterprise: 'Included' },
        { name: 'All Analyzers', opensource: true, saas: true, enterprise: true },
        { name: 'Cross-Platform', opensource: true, saas: true, enterprise: true },
        { name: 'Source Code Access', opensource: true, saas: false, enterprise: false }
      ]
    },
    {
      category: 'Deployment Options',
      items: [
        { name: 'Self-Hosted', opensource: true, saas: false, enterprise: false },
        { name: 'Cloud-Hosted', opensource: false, saas: true, enterprise: true },
        { name: 'Global CDN', opensource: false, saas: true, enterprise: true },
        { name: 'Infrastructure Management', opensource: 'Self-managed', saas: 'Managed', enterprise: 'Managed' }
      ]
    },
    {
      category: 'Enterprise Features',
      items: [
        { name: 'SSO Integration', opensource: false, saas: false, enterprise: true },
        { name: 'Advanced Analytics', opensource: false, saas: true, enterprise: true },
        { name: 'White-label Solutions', opensource: false, saas: false, enterprise: true },
        { name: 'Compliance Reporting', opensource: false, saas: false, enterprise: true },
        { name: 'Custom SLA', opensource: false, saas: false, enterprise: true }
      ]
    },
    {
      category: 'Support',
      items: [
        { name: 'Community Support', opensource: true, saas: true, enterprise: true },
        { name: 'Priority Support', opensource: false, saas: true, enterprise: true },
        { name: 'Dedicated Support', opensource: false, saas: false, enterprise: true },
        { name: 'Phone Support', opensource: false, saas: false, enterprise: true }
      ]
    }
  ]

  const renderFeatureValue = (value: any) => {
    if (typeof value === 'boolean') {
      return value ? (
        <CheckIcon className="h-5 w-5 text-success-green mx-auto" />
      ) : (
        <XMarkIcon className="h-5 w-5 text-silver mx-auto" />
      )
    }
    return <span className="text-ghost-white text-sm">{value}</span>
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
            Open Source & Transparent Pricing
          </h1>
          <p className="text-xl text-silver max-w-3xl mx-auto mb-8">
            <span className="text-electric-blue font-semibold">CLI and on-premise deployment are completely free.</span>
            <br />Only pay for managed cloud API services with enterprise features like SSO.
          </p>
          
          {/* Billing Toggle */}
          <div className="flex items-center justify-center space-x-4">
            <span className={`text-sm ${!isAnnual ? 'text-ghost-white' : 'text-silver'}`}>
              Monthly
            </span>
            <button
              onClick={() => setIsAnnual(!isAnnual)}
              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                isAnnual ? 'bg-electric-blue' : 'bg-white/20'
              }`}
            >
              <span
                className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                  isAnnual ? 'translate-x-6' : 'translate-x-1'
                }`}
              />
            </button>
            <span className={`text-sm ${isAnnual ? 'text-ghost-white' : 'text-silver'}`}>
              Annual
              <span className="ml-1 px-2 py-0.5 bg-success-green/20 text-success-green rounded-full text-xs">
                Save 20%
              </span>
            </span>
          </div>
        </motion.div>

        {/* Pricing Cards */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-16"
        >
          {plans.map((plan, index) => (
            <motion.div
              key={plan.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              className={`relative rounded-xl p-8 border transition-all hover:scale-105 ${
                plan.popular
                  ? 'border-electric-blue bg-electric-blue/5 glass-strong'
                  : 'border-white/20 glass'
              }`}
            >
              {plan.popular && (
                <div className="absolute -top-4 left-1/2 transform -translate-x-1/2">
                  <div className="flex items-center space-x-1 bg-electric-blue px-3 py-1 rounded-full">
                    <StarIcon className="h-4 w-4 text-white" />
                    <span className="text-white text-sm font-medium">Most Popular</span>
                  </div>
                </div>
              )}
              
              <div className="text-center mb-8">
                <h3 className="text-2xl font-bold text-ghost-white mb-2">
                  {plan.name}
                </h3>
                <p className="text-silver text-sm mb-6">
                  {plan.description}
                </p>
                
                <div className="mb-6">
                  <span className="text-4xl font-bold text-gradient">
                    ${isAnnual ? plan.price.annual : plan.price.monthly}
                  </span>
                  <span className="text-silver text-sm ml-1">
                    {plan.price.monthly === 0 ? '' : '/month'}
                  </span>
                  {isAnnual && plan.price.monthly > 0 && (
                    <div className="text-sm text-silver mt-1">
                      Billed annually (${plan.price.annual * 12}/year)
                    </div>
                  )}
                </div>
                
                <button
                  className={`w-full py-3 px-6 rounded-lg font-semibold transition-all ${
                    plan.popular
                      ? 'bg-electric-blue hover:bg-electric-blue/80 text-white'
                      : 'bg-white/10 hover:bg-white/20 text-ghost-white border border-white/20'
                  }`}
                >
                  {plan.cta}
                </button>
              </div>
              
              <div className="space-y-4">
                <div>
                  <h4 className="text-sm font-semibold text-ghost-white mb-3">
                    What's included:
                  </h4>
                  <ul className="space-y-2">
                    {plan.features.map((feature, idx) => (
                      <li key={idx} className="flex items-start space-x-3">
                        <CheckIcon className="h-4 w-4 text-success-green mt-0.5 flex-shrink-0" />
                        <span className="text-silver text-sm">{feature}</span>
                      </li>
                    ))}
                  </ul>
                </div>
                
                {plan.limitations.length > 0 && (
                  <div>
                    <h4 className="text-sm font-semibold text-ghost-white mb-3">
                      Limitations:
                    </h4>
                    <ul className="space-y-2">
                      {plan.limitations.map((limitation, idx) => (
                        <li key={idx} className="flex items-start space-x-3">
                          <XMarkIcon className="h-4 w-4 text-silver mt-0.5 flex-shrink-0" />
                          <span className="text-silver text-sm">{limitation}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </motion.div>
          ))}
        </motion.div>

        {/* Feature Comparison */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="glass-strong rounded-xl p-8 mb-16"
        >
          <h2 className="text-2xl font-bold text-ghost-white text-center mb-8">
            Feature Comparison
          </h2>
          
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-white/20">
                  <th className="text-left py-4 px-4 text-ghost-white font-semibold">
                    Features
                  </th>
                  <th className="text-center py-4 px-4 text-ghost-white font-semibold">
                    Open Source
                  </th>
                  <th className="text-center py-4 px-4 text-ghost-white font-semibold">
                    SaaS API
                  </th>
                  <th className="text-center py-4 px-4 text-ghost-white font-semibold">
                    Enterprise SaaS
                  </th>
                </tr>
              </thead>
              <tbody>
                {features.map((category, categoryIdx) => (
                  <React.Fragment key={categoryIdx}>
                    <tr>
                      <td colSpan={4} className="py-4 px-4">
                        <h3 className="text-electric-blue font-semibold">
                          {category.category}
                        </h3>
                      </td>
                    </tr>
                    {category.items.map((item, itemIdx) => (
                      <tr key={itemIdx} className="border-b border-white/10">
                        <td className="py-3 px-4 text-silver">
                          {item.name}
                        </td>
                        <td className="py-3 px-4 text-center">
                          {renderFeatureValue(item.opensource)}
                        </td>
                        <td className="py-3 px-4 text-center">
                          {renderFeatureValue(item.saas)}
                        </td>
                        <td className="py-3 px-4 text-center">
                          {renderFeatureValue(item.enterprise)}
                        </td>
                      </tr>
                    ))}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </motion.div>

        {/* Trust Indicators */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="grid grid-cols-1 md:grid-cols-3 gap-8"
        >
          <div className="card text-center">
            <ShieldCheckIcon className="h-12 w-12 text-success-green mx-auto mb-4" />
            <h3 className="text-xl font-bold text-ghost-white mb-2">
              Enterprise Security
            </h3>
            <p className="text-silver">
              SOC 2 Type II certified with enterprise-grade security controls
            </p>
          </div>
          
          <div className="card text-center">
            <BoltIcon className="h-12 w-12 text-electric-blue mx-auto mb-4" />
            <h3 className="text-xl font-bold text-ghost-white mb-2">
              99.9% Uptime SLA
            </h3>
            <p className="text-silver">
              Reliable service with guaranteed uptime and performance
            </p>
          </div>
          
          <div className="card text-center">
            <GlobeAltIcon className="h-12 w-12 text-cyber-purple mx-auto mb-4" />
            <h3 className="text-xl font-bold text-ghost-white mb-2">
              Global Coverage
            </h3>
            <p className="text-silver">
              Worldwide threat intelligence with regional data compliance
            </p>
          </div>
        </motion.div>
      </div>
    </div>
  )
}

export default Pricing