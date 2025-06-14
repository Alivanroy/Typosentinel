import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { packageService } from '../services/package'
import { StatsCards } from '../components/dashboard/stats-cards'
import { ThreatChart } from '../components/dashboard/threat-chart'
import { RiskDistribution } from '../components/dashboard/risk-distribution'
import { RecentScans } from '../components/dashboard/recent-scans'
import { ThreatTimeline } from '../components/dashboard/threat-timeline'
import { RegistryOverview } from '../components/dashboard/registry-overview'
import { AlertTriangle, Shield, Package, Scan } from 'lucide-react'

const DashboardPage: React.FC = () => {
  const { data: packageStats, isLoading: packageStatsLoading } = useQuery({
    queryKey: ['package-stats'],
    queryFn: packageService.getPackageStats,
  })

  const { data: threatStats, isLoading: threatStatsLoading } = useQuery({
    queryKey: ['threat-stats'],
    queryFn: packageService.getThreatStats,
  })

  const { data: recentScans, isLoading: recentScansLoading } = useQuery({
    queryKey: ['recent-scans'],
    queryFn: () => packageService.getScans({ limit: 10, sortBy: 'createdAt', sortOrder: 'desc' }),
  })

  const isLoading = packageStatsLoading || threatStatsLoading || recentScansLoading

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-muted-foreground">
          Overview of your package security monitoring and threat detection.
        </p>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Packages</CardTitle>
            <Package className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{packageStats?.total.toLocaleString() || 0}</div>
            <p className="text-xs text-muted-foreground">
              Across {Object.keys(packageStats?.byRegistry || {}).length} registries
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Threats Detected</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{threatStats?.total.toLocaleString() || 0}</div>
            <p className="text-xs text-muted-foreground">
              {threatStats?.trends?.slice(-1)[0]?.count || 0} in last 24h
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Recent Scans</CardTitle>
            <Scan className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{packageStats?.recentScans || 0}</div>
            <p className="text-xs text-muted-foreground">
              In the last 7 days
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Security Score</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">98.5%</div>
            <p className="text-xs text-muted-foreground">
              +2.1% from last month
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Main Content */}
      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="threats">Threats</TabsTrigger>
          <TabsTrigger value="registries">Registries</TabsTrigger>
          <TabsTrigger value="activity">Activity</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
            <Card className="col-span-4">
              <CardHeader>
                <CardTitle>Threat Detection Trends</CardTitle>
                <CardDescription>
                  Number of threats detected over time
                </CardDescription>
              </CardHeader>
              <CardContent className="pl-2">
                <ThreatChart data={threatStats?.trends || []} />
              </CardContent>
            </Card>

            <Card className="col-span-3">
              <CardHeader>
                <CardTitle>Risk Distribution</CardTitle>
                <CardDescription>
                  Breakdown of packages by risk level
                </CardDescription>
              </CardHeader>
              <CardContent>
                <RiskDistribution data={packageStats?.byRiskLevel || {}} />
              </CardContent>
            </Card>
          </div>

          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
            <Card className="col-span-4">
              <CardHeader>
                <CardTitle>Recent Scans</CardTitle>
                <CardDescription>
                  Latest package security scans
                </CardDescription>
              </CardHeader>
              <CardContent>
                <RecentScans scans={recentScans?.scans || []} />
              </CardContent>
            </Card>

            <Card className="col-span-3">
              <CardHeader>
                <CardTitle>Registry Coverage</CardTitle>
                <CardDescription>
                  Packages monitored by registry
                </CardDescription>
              </CardHeader>
              <CardContent>
                <RegistryOverview data={packageStats?.byRegistry || {}} />
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="threats" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Threat Types</CardTitle>
                <CardDescription>
                  Distribution of detected threat types
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {Object.entries(threatStats?.byType || {}).map(([type, count]) => (
                    <div key={type} className="flex items-center justify-between">
                      <span className="text-sm font-medium capitalize">
                        {type.replace('_', ' ')}
                      </span>
                      <span className="text-sm text-muted-foreground">{count}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Threat Severity</CardTitle>
                <CardDescription>
                  Breakdown by severity level
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {Object.entries(threatStats?.bySeverity || {}).map(([severity, count]) => (
                    <div key={severity} className="flex items-center justify-between">
                      <span className="text-sm font-medium capitalize">{severity}</span>
                      <span className="text-sm text-muted-foreground">{count}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Threat Timeline</CardTitle>
              <CardDescription>
                Recent threat detection activity
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ThreatTimeline />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="registries" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-3">
            {Object.entries(packageStats?.byRegistry || {}).map(([registry, count]) => (
              <Card key={registry}>
                <CardHeader>
                  <CardTitle className="capitalize">{registry}</CardTitle>
                  <CardDescription>
                    {count.toLocaleString()} packages monitored
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{count.toLocaleString()}</div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="activity" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Recent Activity</CardTitle>
              <CardDescription>
                Latest scanning and detection activity
              </CardDescription>
            </CardHeader>
            <CardContent>
              <RecentScans scans={recentScans?.scans || []} showDetails />
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}

export default DashboardPage