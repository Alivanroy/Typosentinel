import React from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card'
import { Badge } from '../ui/badge'
import { AlertTriangle, Shield, Eye, Clock } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'

interface ThreatEvent {
  id: string
  type: 'malicious' | 'suspicious' | 'typosquatting' | 'resolved'
  packageName: string
  registry: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  description: string
  detectedAt: Date
  status: 'active' | 'investigating' | 'resolved' | 'false_positive'
}

interface ThreatTimelineProps {
  data?: ThreatEvent[]
  className?: string
}

const mockData: ThreatEvent[] = [
  {
    id: '1',
    type: 'malicious',
    packageName: 'react-dom-utils',
    registry: 'npm',
    severity: 'critical',
    description: 'Package contains obfuscated code that attempts to steal environment variables',
    detectedAt: new Date(Date.now() - 1000 * 60 * 15), // 15 minutes ago
    status: 'active'
  },
  {
    id: '2',
    type: 'typosquatting',
    packageName: 'lodash-helper',
    registry: 'npm',
    severity: 'high',
    description: 'Potential typosquatting attempt of popular "lodash" package',
    detectedAt: new Date(Date.now() - 1000 * 60 * 45), // 45 minutes ago
    status: 'investigating'
  },
  {
    id: '3',
    type: 'suspicious',
    packageName: 'crypto-utils-plus',
    registry: 'npm',
    severity: 'medium',
    description: 'Package has unusual network activity patterns',
    detectedAt: new Date(Date.now() - 1000 * 60 * 120), // 2 hours ago
    status: 'investigating'
  },
  {
    id: '4',
    type: 'resolved',
    packageName: 'requests-plus',
    registry: 'pypi',
    severity: 'high',
    description: 'Previously flagged package has been verified as safe after investigation',
    detectedAt: new Date(Date.now() - 1000 * 60 * 180), // 3 hours ago
    status: 'resolved'
  },
  {
    id: '5',
    type: 'malicious',
    packageName: 'express-middleware',
    registry: 'npm',
    severity: 'critical',
    description: 'Package attempts to execute arbitrary code during installation',
    detectedAt: new Date(Date.now() - 1000 * 60 * 240), // 4 hours ago
    status: 'resolved'
  }
]

function getThreatTypeIcon(type: string) {
  switch (type) {
    case 'malicious': return <AlertTriangle className="h-4 w-4 text-red-500" />
    case 'suspicious': return <Eye className="h-4 w-4 text-orange-500" />
    case 'typosquatting': return <AlertTriangle className="h-4 w-4 text-yellow-500" />
    case 'resolved': return <Shield className="h-4 w-4 text-green-500" />
    default: return <Clock className="h-4 w-4 text-gray-500" />
  }
}

function getThreatTypeColor(type: string) {
  switch (type) {
    case 'malicious': return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300'
    case 'suspicious': return 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300'
    case 'typosquatting': return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300'
    case 'resolved': return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300'
    default: return 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300'
  }
}

function getSeverityColor(severity: string) {
  switch (severity) {
    case 'low': return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300'
    case 'medium': return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300'
    case 'high': return 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300'
    case 'critical': return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300'
    default: return 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300'
  }
}

function getStatusColor(status: string) {
  switch (status) {
    case 'active': return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300'
    case 'investigating': return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300'
    case 'resolved': return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300'
    case 'false_positive': return 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300'
    default: return 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300'
  }
}

export function ThreatTimeline({ data = mockData, className }: ThreatTimelineProps) {
  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle>Threat Timeline</CardTitle>
        <CardDescription>
          Recent security threats and their resolution status
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {data.map((threat, index) => (
            <div key={threat.id} className="relative">
              {/* Timeline line */}
              {index < data.length - 1 && (
                <div className="absolute left-6 top-8 w-0.5 h-16 bg-border" />
              )}
              
              <div className="flex items-start space-x-4">
                <div className="flex-shrink-0 w-12 h-12 rounded-full border-2 border-background bg-card flex items-center justify-center">
                  {getThreatTypeIcon(threat.type)}
                </div>
                
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <p className="font-medium text-sm">{threat.packageName}</p>
                      <Badge variant="outline" className="text-xs">
                        {threat.registry}
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      {formatDistanceToNow(threat.detectedAt, { addSuffix: true })}
                    </p>
                  </div>
                  
                  <p className="text-sm text-muted-foreground mt-1">
                    {threat.description}
                  </p>
                  
                  <div className="flex items-center space-x-2 mt-2">
                    <Badge className={getThreatTypeColor(threat.type)}>
                      {threat.type}
                    </Badge>
                    <Badge className={getSeverityColor(threat.severity)}>
                      {threat.severity}
                    </Badge>
                    <Badge className={getStatusColor(threat.status)}>
                      {threat.status.replace('_', ' ')}
                    </Badge>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
        
        <div className="mt-6 pt-4 border-t">
          <button className="text-sm text-primary hover:underline">
            View full threat log →
          </button>
        </div>
      </CardContent>
    </Card>
  )
}