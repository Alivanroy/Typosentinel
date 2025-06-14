import React from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card'
import { Badge } from '../ui/badge'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { Package, AlertTriangle, CheckCircle, Clock } from 'lucide-react'

interface RegistryData {
  name: string
  displayName: string
  totalPackages: number
  scannedPackages: number
  threatsFound: number
  lastScanTime: Date
  status: 'healthy' | 'warning' | 'error'
  scanProgress: number // percentage
}

interface RegistryOverviewProps {
  data?: RegistryData[]
  className?: string
}

const mockData: RegistryData[] = [
  {
    name: 'npm',
    displayName: 'NPM Registry',
    totalPackages: 8542,
    scannedPackages: 8234,
    threatsFound: 45,
    lastScanTime: new Date(Date.now() - 1000 * 60 * 15), // 15 minutes ago
    status: 'healthy',
    scanProgress: 96.4
  },
  {
    name: 'pypi',
    displayName: 'PyPI Registry',
    totalPackages: 3421,
    scannedPackages: 3201,
    threatsFound: 23,
    lastScanTime: new Date(Date.now() - 1000 * 60 * 32), // 32 minutes ago
    status: 'warning',
    scanProgress: 93.6
  },
  {
    name: 'rubygems',
    displayName: 'RubyGems Registry',
    totalPackages: 1234,
    scannedPackages: 1198,
    threatsFound: 8,
    lastScanTime: new Date(Date.now() - 1000 * 60 * 45), // 45 minutes ago
    status: 'healthy',
    scanProgress: 97.1
  },
  {
    name: 'nuget',
    displayName: 'NuGet Registry',
    totalPackages: 892,
    scannedPackages: 756,
    threatsFound: 12,
    lastScanTime: new Date(Date.now() - 1000 * 60 * 120), // 2 hours ago
    status: 'error',
    scanProgress: 84.8
  },
  {
    name: 'maven',
    displayName: 'Maven Central',
    totalPackages: 2156,
    scannedPackages: 2089,
    threatsFound: 15,
    lastScanTime: new Date(Date.now() - 1000 * 60 * 28), // 28 minutes ago
    status: 'healthy',
    scanProgress: 96.9
  }
]

const chartData = mockData.map(registry => ({
  name: registry.displayName,
  packages: registry.totalPackages,
  scanned: registry.scannedPackages,
  threats: registry.threatsFound
}))

function getStatusIcon(status: string) {
  switch (status) {
    case 'healthy': return <CheckCircle className="h-4 w-4 text-green-500" />
    case 'warning': return <AlertTriangle className="h-4 w-4 text-yellow-500" />
    case 'error': return <AlertTriangle className="h-4 w-4 text-red-500" />
    default: return <Clock className="h-4 w-4 text-gray-500" />
  }
}

function getStatusColor(status: string) {
  switch (status) {
    case 'healthy': return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300'
    case 'warning': return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300'
    case 'error': return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300'
    default: return 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300'
  }
}

function getRegistryIcon(name: string) {
  // You could return specific icons for each registry here
  return <Package className="h-5 w-5" />
}

function formatTimeAgo(date: Date) {
  const now = new Date()
  const diffInMinutes = Math.floor((now.getTime() - date.getTime()) / (1000 * 60))
  
  if (diffInMinutes < 60) {
    return `${diffInMinutes}m ago`
  } else if (diffInMinutes < 1440) {
    return `${Math.floor(diffInMinutes / 60)}h ago`
  } else {
    return `${Math.floor(diffInMinutes / 1440)}d ago`
  }
}

export function RegistryOverview({ data = mockData, className }: RegistryOverviewProps) {
  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle>Registry Overview</CardTitle>
        <CardDescription>
          Package scanning status across all monitored registries
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-6">
          {/* Registry Status List */}
          <div className="space-y-3">
            {data.map((registry) => (
              <div key={registry.name} className="flex items-center justify-between p-4 border rounded-lg">
                <div className="flex items-center space-x-4">
                  <div className="flex items-center space-x-2">
                    {getStatusIcon(registry.status)}
                    {getRegistryIcon(registry.name)}
                  </div>
                  
                  <div>
                    <div className="flex items-center space-x-2">
                      <p className="font-medium text-sm">{registry.displayName}</p>
                      <Badge className={getStatusColor(registry.status)}>
                        {registry.status}
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Last scan: {formatTimeAgo(registry.lastScanTime)}
                    </p>
                  </div>
                </div>
                
                <div className="text-right space-y-1">
                  <div className="flex items-center space-x-4">
                    <div className="text-sm">
                      <span className="font-medium">{registry.scannedPackages.toLocaleString()}</span>
                      <span className="text-muted-foreground">/{registry.totalPackages.toLocaleString()}</span>
                    </div>
                    {registry.threatsFound > 0 && (
                      <div className="flex items-center space-x-1">
                        <AlertTriangle className="h-4 w-4 text-orange-500" />
                        <span className="text-sm font-medium text-orange-600">{registry.threatsFound}</span>
                      </div>
                    )}
                  </div>
                  <div className="w-24 bg-gray-200 rounded-full h-2 dark:bg-gray-700">
                    <div 
                      className="bg-primary h-2 rounded-full transition-all duration-300" 
                      style={{ width: `${registry.scanProgress}%` }}
                    />
                  </div>
                  <p className="text-xs text-muted-foreground">{registry.scanProgress}% scanned</p>
                </div>
              </div>
            ))}
          </div>
          
          {/* Chart */}
          <div className="mt-6">
            <h4 className="text-sm font-medium mb-4">Package Distribution</h4>
            <div className="h-[200px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                  <XAxis 
                    dataKey="name" 
                    className="text-xs"
                    tick={{ fontSize: 12 }}
                  />
                  <YAxis className="text-xs" tick={{ fontSize: 12 }} />
                  <Tooltip 
                    contentStyle={{
                      backgroundColor: 'hsl(var(--card))',
                      border: '1px solid hsl(var(--border))',
                      borderRadius: '6px'
                    }}
                  />
                  <Bar dataKey="packages" fill="hsl(var(--primary))" name="Total Packages" />
                  <Bar dataKey="scanned" fill="hsl(var(--primary))" fillOpacity={0.6} name="Scanned" />
                  <Bar dataKey="threats" fill="hsl(var(--destructive))" name="Threats" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}