import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { 
  LineChart, 
  Line, 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell
} from 'recharts'
import { 
  ExclamationTriangleIcon, 
  ShieldCheckIcon, 
  ClockIcon,
  GlobeAltIcon
} from '@heroicons/react/24/outline'

const ThreatDashboardPreview: React.FC = () => {
  const [activeTab, setActiveTab] = useState('threats')
  const [liveData, setLiveData] = useState(false)

  useEffect(() => {
    const interval = setInterval(() => {
      setLiveData(prev => !prev)
    }, 3000)
    return () => clearInterval(interval)
  }, [])

  // Sample data for charts
  const threatData = [
    { time: '00:00', threats: 45, blocked: 43 },
    { time: '04:00', threats: 67, blocked: 65 },
    { time: '08:00', threats: 123, blocked: 119 },
    { time: '12:00', threats: 89, blocked: 87 },
    { time: '16:00', threats: 156, blocked: 152 },
    { time: '20:00', threats: 98, blocked: 96 },
    { time: '24:00', threats: 134, blocked: 131 }
  ]

  const threatTypes = [
    { name: 'Typosquatting', value: 45, color: '#FF6B6B' },
    { name: 'Malicious Code', value: 30, color: '#4ECDC4' },
    { name: 'Dependency Confusion', value: 15, color: '#45B7D1' },
    { name: 'Supply Chain', value: 10, color: '#96CEB4' }
  ]

  const recentThreats = [
    {
      package: 'reqeusts',
      type: 'Typosquatting',
      severity: 'High',
      time: '2 min ago',
      status: 'Blocked'
    },
    {
      package: 'lodahs',
      type: 'Malicious Code',
      severity: 'Critical',
      time: '5 min ago',
      status: 'Blocked'
    },
    {
      package: 'expres',
      type: 'Typosquatting',
      severity: 'Medium',
      time: '8 min ago',
      status: 'Flagged'
    },
    {
      package: 'reactt',
      type: 'Dependency Confusion',
      severity: 'High',
      time: '12 min ago',
      status: 'Blocked'
    }
  ]

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical': return 'text-red-400'
      case 'High': return 'text-orange-400'
      case 'Medium': return 'text-yellow-400'
      default: return 'text-green-400'
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'Blocked': return 'text-red-400 bg-red-400/10'
      case 'Flagged': return 'text-yellow-400 bg-yellow-400/10'
      default: return 'text-green-400 bg-green-400/10'
    }
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 50 }}
      whileInView={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.8 }}
      viewport={{ once: true }}
      className="glass-strong rounded-2xl p-8 max-w-6xl mx-auto"
    >
      {/* Dashboard Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h3 className="text-2xl font-bold text-ghost-white mb-2">
            Threat Intelligence Dashboard
          </h3>
          <p className="text-silver">
            Real-time monitoring and analysis of package threats
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <div className={`w-3 h-3 rounded-full ${liveData ? 'bg-success-green' : 'bg-success-green/50'} animate-pulse`} />
          <span className="text-sm text-success-green font-medium">Live</span>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex space-x-1 mb-8 bg-dark-charcoal/50 rounded-lg p-1">
        {[
          { id: 'threats', label: 'Threat Timeline', icon: ExclamationTriangleIcon },
          { id: 'types', label: 'Threat Types', icon: ShieldCheckIcon },
          { id: 'recent', label: 'Recent Activity', icon: ClockIcon }
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center space-x-2 px-4 py-2 rounded-md transition-all ${
              activeTab === tab.id
                ? 'bg-electric-blue text-white'
                : 'text-silver hover:text-white hover:bg-silver/10'
            }`}
          >
            <tab.icon className="h-4 w-4" />
            <span className="text-sm font-medium">{tab.label}</span>
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="min-h-[400px]">
        {activeTab === 'threats' && (
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.5 }}
          >
            <div className="mb-6">
              <h4 className="text-lg font-semibold text-ghost-white mb-2">
                24-Hour Threat Detection Timeline
              </h4>
              <p className="text-sm text-silver">
                Threats detected vs. successfully blocked over time
              </p>
            </div>
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={threatData}>
                <defs>
                  <linearGradient id="threatsGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#FF6B6B" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#FF6B6B" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="blockedGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#4ECDC4" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#4ECDC4" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="time" stroke="#9CA3AF" />
                <YAxis stroke="#9CA3AF" />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#1F2937', 
                    border: '1px solid #374151',
                    borderRadius: '8px'
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="threats"
                  stroke="#FF6B6B"
                  fillOpacity={1}
                  fill="url(#threatsGradient)"
                  name="Threats Detected"
                />
                <Area
                  type="monotone"
                  dataKey="blocked"
                  stroke="#4ECDC4"
                  fillOpacity={1}
                  fill="url(#blockedGradient)"
                  name="Threats Blocked"
                />
              </AreaChart>
            </ResponsiveContainer>
          </motion.div>
        )}

        {activeTab === 'types' && (
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.5 }}
            className="grid grid-cols-1 lg:grid-cols-2 gap-8"
          >
            <div>
              <h4 className="text-lg font-semibold text-ghost-white mb-4">
                Threat Distribution
              </h4>
              <ResponsiveContainer width="100%" height={250}>
                <PieChart>
                  <Pie
                    data={threatTypes}
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  >
                    {threatTypes.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div>
              <h4 className="text-lg font-semibold text-ghost-white mb-4">
                Threat Categories
              </h4>
              <div className="space-y-4">
                {threatTypes.map((type, index) => (
                  <motion.div
                    key={type.name}
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.5, delay: index * 0.1 }}
                    className="flex items-center justify-between p-3 glass-subtle rounded-lg"
                  >
                    <div className="flex items-center space-x-3">
                      <div 
                        className="w-4 h-4 rounded-full"
                        style={{ backgroundColor: type.color }}
                      />
                      <span className="text-ghost-white font-medium">{type.name}</span>
                    </div>
                    <span className="text-silver">{type.value}%</span>
                  </motion.div>
                ))}
              </div>
            </div>
          </motion.div>
        )}

        {activeTab === 'recent' && (
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.5 }}
          >
            <div className="mb-6">
              <h4 className="text-lg font-semibold text-ghost-white mb-2">
                Recent Threat Activity
              </h4>
              <p className="text-sm text-silver">
                Latest threats detected and actions taken
              </p>
            </div>
            <div className="space-y-3">
              {recentThreats.map((threat, index) => (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.5, delay: index * 0.1 }}
                  className="flex items-center justify-between p-4 glass-subtle rounded-lg hover:bg-silver/5 transition-colors"
                >
                  <div className="flex items-center space-x-4">
                    <div className="flex-shrink-0">
                      <ExclamationTriangleIcon className="h-5 w-5 text-warning-amber" />
                    </div>
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="font-mono text-ghost-white font-medium">
                          {threat.package}
                        </span>
                        <span className="text-xs px-2 py-1 rounded-full bg-dark-charcoal text-silver">
                          {threat.type}
                        </span>
                      </div>
                      <div className="flex items-center space-x-2 mt-1">
                        <span className={`text-sm ${getSeverityColor(threat.severity)}`}>
                          {threat.severity}
                        </span>
                        <span className="text-xs text-silver">•</span>
                        <span className="text-xs text-silver">{threat.time}</span>
                      </div>
                    </div>
                  </div>
                  <div className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(threat.status)}`}>
                    {threat.status}
                  </div>
                </motion.div>
              ))}
            </div>
          </motion.div>
        )}
      </div>
    </motion.div>
  )
}

export default ThreatDashboardPreview