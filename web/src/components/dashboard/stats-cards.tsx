import React from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card'
import { AlertTriangle, Shield, Package, Scan, TrendingUp, TrendingDown } from 'lucide-react'

interface StatsData {
  totalPackages: number
  threatsDetected: number
  recentScans: number
  securityScore: number
  packagesTrend: number
  threatsTrend: number
  scansTrend: number
  scoreTrend: number
}

interface StatsCardsProps {
  data?: StatsData
  className?: string
}

const mockData: StatsData = {
  totalPackages: 12543,
  threatsDetected: 89,
  recentScans: 1247,
  securityScore: 98.5,
  packagesTrend: 12.5,
  threatsTrend: -8.2,
  scansTrend: 23.1,
  scoreTrend: 2.1
}

function TrendIndicator({ value, className }: { value: number; className?: string }) {
  const isPositive = value > 0
  const Icon = isPositive ? TrendingUp : TrendingDown
  
  return (
    <div className={`flex items-center space-x-1 ${className}`}>
      <Icon className={`h-3 w-3 ${isPositive ? 'text-green-500' : 'text-red-500'}`} />
      <span className={`text-xs ${isPositive ? 'text-green-500' : 'text-red-500'}`}>
        {Math.abs(value)}%
      </span>
    </div>
  )
}

export function StatsCards({ data = mockData, className }: StatsCardsProps) {
  return (
    <div className={`grid gap-4 md:grid-cols-2 lg:grid-cols-4 ${className}`}>
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Total Packages</CardTitle>
          <Package className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{data.totalPackages.toLocaleString()}</div>
          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">Across 5 registries</p>
            <TrendIndicator value={data.packagesTrend} />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Threats Detected</CardTitle>
          <AlertTriangle className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{data.threatsDetected.toLocaleString()}</div>
          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">12 in last 24h</p>
            <TrendIndicator value={data.threatsTrend} />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Recent Scans</CardTitle>
          <Scan className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{data.recentScans.toLocaleString()}</div>
          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">In the last 7 days</p>
            <TrendIndicator value={data.scansTrend} />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Security Score</CardTitle>
          <Shield className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{data.securityScore}%</div>
          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">From last month</p>
            <TrendIndicator value={data.scoreTrend} />
          </div>
        </CardContent>
      </Card>
    </div>
  )
}