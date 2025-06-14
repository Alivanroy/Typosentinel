import React from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card'
import { Badge } from '../ui/badge'
import { AlertTriangle, CheckCircle, Clock, Package } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'

interface ScanResult {
  id: string
  packageName: string
  registry: string
  status: 'completed' | 'running' | 'failed'
  riskLevel: 'low' | 'medium' | 'high' | 'critical'
  threatsFound: number
  scannedAt: Date
  duration: number // in seconds
}

interface RecentScansProps {
  data?: ScanResult[]
  className?: string
}

const mockData: ScanResult[] = [
  {
    id: '1',
    packageName: 'react-dom-utils',
    registry: 'npm',
    status: 'completed',
    riskLevel: 'high',
    threatsFound: 3,
    scannedAt: new Date(Date.now() - 1000 * 60 * 15), // 15 minutes ago
    duration: 45
  },
  {
    id: '2',
    packageName: 'lodash-helper',
    registry: 'npm',
    status: 'completed',
    riskLevel: 'medium',
    threatsFound: 1,
    scannedAt: new Date(Date.now() - 1000 * 60 * 32), // 32 minutes ago
    duration: 23
  },
  {
    id: '3',
    packageName: 'express-middleware',
    registry: 'npm',
    status: 'running',
    riskLevel: 'low',
    threatsFound: 0,
    scannedAt: new Date(Date.now() - 1000 * 60 * 5), // 5 minutes ago
    duration: 0
  },
  {
    id: '4',
    packageName: 'requests-plus',
    registry: 'pypi',
    status: 'completed',
    riskLevel: 'critical',
    threatsFound: 7,
    scannedAt: new Date(Date.now() - 1000 * 60 * 60), // 1 hour ago
    duration: 67
  },
  {
    id: '5',
    packageName: 'numpy-extended',
    registry: 'pypi',
    status: 'completed',
    riskLevel: 'low',
    threatsFound: 0,
    scannedAt: new Date(Date.now() - 1000 * 60 * 90), // 1.5 hours ago
    duration: 34
  }
]

function getRiskLevelColor(level: string) {
  switch (level) {
    case 'low': return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300'
    case 'medium': return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300'
    case 'high': return 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300'
    case 'critical': return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300'
    default: return 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300'
  }
}

function getStatusIcon(status: string) {
  switch (status) {
    case 'completed': return <CheckCircle className="h-4 w-4 text-green-500" />
    case 'running': return <Clock className="h-4 w-4 text-blue-500 animate-spin" />
    case 'failed': return <AlertTriangle className="h-4 w-4 text-red-500" />
    default: return <Clock className="h-4 w-4 text-gray-500" />
  }
}

function getRegistryBadgeColor(registry: string) {
  switch (registry) {
    case 'npm': return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300'
    case 'pypi': return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300'
    case 'rubygems': return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300'
    default: return 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300'
  }
}

export function RecentScans({ data = mockData, className }: RecentScansProps) {
  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle>Recent Scans</CardTitle>
        <CardDescription>
          Latest package security scans and their results
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {data.map((scan) => (
            <div key={scan.id} className="flex items-center justify-between p-4 border rounded-lg hover:bg-muted/50 transition-colors">
              <div className="flex items-center space-x-4">
                <div className="flex items-center space-x-2">
                  {getStatusIcon(scan.status)}
                  <Package className="h-4 w-4 text-muted-foreground" />
                </div>
                
                <div className="flex-1">
                  <div className="flex items-center space-x-2">
                    <p className="font-medium text-sm">{scan.packageName}</p>
                    <Badge 
                      variant="outline" 
                      className={`text-xs ${getRegistryBadgeColor(scan.registry)}`}
                    >
                      {scan.registry}
                    </Badge>
                  </div>
                  
                  <div className="flex items-center space-x-4 mt-1">
                    <p className="text-xs text-muted-foreground">
                      {formatDistanceToNow(scan.scannedAt, { addSuffix: true })}
                    </p>
                    {scan.status === 'completed' && (
                      <p className="text-xs text-muted-foreground">
                        Completed in {scan.duration}s
                      </p>
                    )}
                  </div>
                </div>
              </div>
              
              <div className="flex items-center space-x-3">
                <Badge className={getRiskLevelColor(scan.riskLevel)}>
                  {scan.riskLevel}
                </Badge>
                
                {scan.threatsFound > 0 && (
                  <div className="flex items-center space-x-1">
                    <AlertTriangle className="h-4 w-4 text-orange-500" />
                    <span className="text-sm font-medium">{scan.threatsFound}</span>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
        
        <div className="mt-4 pt-4 border-t">
          <button className="text-sm text-primary hover:underline">
            View all scan results →
          </button>
        </div>
      </CardContent>
    </Card>
  )
}