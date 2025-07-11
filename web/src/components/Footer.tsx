import React from 'react'
import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { ShieldCheckIcon } from '@heroicons/react/24/outline'
import { 
  GitHubLogoIcon, 
  TwitterLogoIcon, 
  LinkedInLogoIcon,
  DiscordLogoIcon 
} from '@radix-ui/react-icons'

const Footer: React.FC = () => {
  const currentYear = new Date().getFullYear()

  const footerLinks = {
    product: [
      { name: 'Features', href: '/demo' },
      { name: 'API', href: '/api' },
      { name: 'CLI Tool', href: '/cli' },
      { name: 'Pricing', href: '/pricing' },
    ],
    resources: [
      { name: 'Documentation', href: '/docs' },
      { name: 'Blog', href: '/blog' },
      { name: 'Status', href: '/status' },
    ],
    company: [
      { name: 'About', href: '/about' },
      { name: 'Careers', href: '/careers' },
      { name: 'Contact', href: '/contact' },
      { name: 'Security', href: '/security' },
    ],
    legal: [
      { name: 'Privacy Policy', href: '/privacy' },
      { name: 'Terms of Service', href: '/terms' },
      { name: 'Cookie Policy', href: '/cookies' },
      { name: 'GDPR', href: '/gdpr' },
    ],
  }

  const socialLinks = [
    { name: 'GitHub', icon: GitHubLogoIcon, href: 'https://github.com/alikorsi/typosentinel' },
    { name: 'Twitter', icon: TwitterLogoIcon, href: 'https://twitter.com/typosentinel' },
    { name: 'LinkedIn', icon: LinkedInLogoIcon, href: 'https://linkedin.com/company/typosentinel' },
    { name: 'Discord', icon: DiscordLogoIcon, href: 'https://discord.gg/typosentinel' },
  ]

  return (
    <footer className="relative mt-20">
      {/* Gradient Border */}
      <div className="h-px bg-gradient-to-r from-transparent via-electric-blue to-transparent" />
      
      <div className="glass-strong">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-8">
            {/* Brand Section */}
            <div className="lg:col-span-2">
              <Link to="/" className="flex items-center space-x-2 group mb-4">
                <motion.div
                  whileHover={{ rotate: 360 }}
                  transition={{ duration: 0.5 }}
                  className="relative"
                >
                  <ShieldCheckIcon className="h-8 w-8 text-electric-blue" />
                  <div className="absolute inset-0 bg-electric-blue rounded-full blur-md opacity-30 group-hover:opacity-60 transition-opacity" />
                </motion.div>
                <span className="text-xl font-bold text-gradient font-display">
                  TypoSentinel
                </span>
              </Link>
              <p className="text-silver text-sm mb-6 max-w-md">
                AI-powered supply chain defense. Protecting your dependencies from typosquatting attacks with advanced machine learning and real-time threat intelligence.
              </p>
              
              {/* Social Links */}
              <div className="flex space-x-4">
                {socialLinks.map((social) => {
                  const Icon = social.icon
                  return (
                    <motion.a
                      key={social.name}
                      href={social.href}
                      target="_blank"
                      rel="noopener noreferrer"
                      whileHover={{ scale: 1.1, y: -2 }}
                      className="text-silver hover:text-electric-blue transition-colors p-2 rounded-lg hover:bg-white/5"
                    >
                      <Icon className="h-5 w-5" />
                      <span className="sr-only">{social.name}</span>
                    </motion.a>
                  )
                })}
              </div>
            </div>

            {/* Links Sections */}
            <div>
              <h3 className="text-ghost-white font-semibold mb-4">Product</h3>
              <ul className="space-y-2">
                {footerLinks.product.map((link) => (
                  <li key={link.name}>
                    <Link
                      to={link.href}
                      className="text-silver hover:text-electric-blue transition-colors text-sm"
                    >
                      {link.name}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>

            <div>
              <h3 className="text-ghost-white font-semibold mb-4">Resources</h3>
              <ul className="space-y-2">
                {footerLinks.resources.map((link) => (
                  <li key={link.name}>
                    <Link
                      to={link.href}
                      className="text-silver hover:text-electric-blue transition-colors text-sm"
                    >
                      {link.name}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>

            <div>
              <h3 className="text-ghost-white font-semibold mb-4">Company</h3>
              <ul className="space-y-2">
                {footerLinks.company.map((link) => (
                  <li key={link.name}>
                    <Link
                      to={link.href}
                      className="text-silver hover:text-electric-blue transition-colors text-sm"
                    >
                      {link.name}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>

            <div>
              <h3 className="text-ghost-white font-semibold mb-4">Legal</h3>
              <ul className="space-y-2">
                {footerLinks.legal.map((link) => (
                  <li key={link.name}>
                    <Link
                      to={link.href}
                      className="text-silver hover:text-electric-blue transition-colors text-sm"
                    >
                      {link.name}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Bottom Section */}
          <div className="mt-12 pt-8 border-t border-white/10">
            <div className="flex flex-col md:flex-row justify-between items-center">
              <p className="text-silver text-sm">
                © {currentYear} TypoSentinel. All rights reserved.
              </p>
              <div className="flex items-center space-x-4 mt-4 md:mt-0">
                <span className="text-silver text-sm">Secured by</span>
                <div className="flex items-center space-x-2">
                  <div className="w-2 h-2 bg-success-green rounded-full animate-pulse" />
                  <span className="text-success-green text-sm font-mono">AI Guardian</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </footer>
  )
}

export default Footer