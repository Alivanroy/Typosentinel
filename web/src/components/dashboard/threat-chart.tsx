import React from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area } from 'recharts'

interface ThreatData {
  date: string
  threats: number
  malicious: number
  suspicious: number
  typosquatting: number
}

interface ThreatChartProps {
  data?: ThreatData[]
  className?: string
}

const mockData: ThreatData[] = [
  { date: '2024-01-01', threats: 45, malicious: 12, suspicious: 18, typosquatting: 15 },
  { date: '2024-01-02', threats: 52, malicious: 15, suspicious: 20, typosquatting: 17 },
  { date: '2024-01-03', threats: 38, malicious: 8, suspicious: 16, typosquatting: 14 },
  { date: '2024-01-04', threats: 61, malicious: 18, suspicious: 25, typosquatting: 18 },
  { date: '2024-01-05', threats: 47, malicious: 13, suspicious: 19, typosquatting: 15 },
  { date: '2024-01-06', threats: 55, malicious: 16, suspicious: 22, typosquatting: 17 },
  { date: '2024-01-07', threats: 42, malicious: 11, suspicious: 17, typosquatting: 14 },
]

export function ThreatChart({ data = mockData, className }: ThreatChartProps) {
  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle>Threat Detection Timeline</CardTitle>
        <CardDescription>
          Daily threat detection trends across all monitored packages
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="h-[300px]">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data}>
              <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
              <XAxis 
                dataKey="date" 
                className="text-xs"
                tickFormatter={(value) => new Date(value).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
              />
              <YAxis className="text-xs" />
              <Tooltip 
                labelFormatter={(value) => new Date(value).toLocaleDateString('en-US', { 
                  weekday: 'long', 
                  year: 'numeric', 
                  month: 'long', 
                  day: 'numeric' 
                })}
                formatter={(value: number, name: string) => [
                  value,
                  name.charAt(0).toUpperCase() + name.slice(1)
                ]}
                contentStyle={{
                  backgroundColor: 'hsl(var(--card))',
                  border: '1px solid hsl(var(--border))',
                  borderRadius: '6px'
                }}
              />
              <Area
                type="monotone"
                dataKey="malicious"
                stackId="1"
                stroke="hsl(var(--destructive))"
                fill="hsl(var(--destructive))"
                fillOpacity={0.8}
              />
              <Area
                type="monotone"
                dataKey="suspicious"
                stackId="1"
                stroke="hsl(var(--warning))"
                fill="hsl(var(--warning))"
                fillOpacity={0.8}
              />
              <Area
                type="monotone"
                dataKey="typosquatting"
                stackId="1"
                stroke="hsl(var(--primary))"
                fill="hsl(var(--primary))"
                fillOpacity={0.8}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
        <div className="flex items-center justify-center space-x-6 mt-4">
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 rounded-full bg-destructive"></div>
            <span className="text-sm text-muted-foreground">Malicious</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 rounded-full bg-warning"></div>
            <span className="text-sm text-muted-foreground">Suspicious</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 rounded-full bg-primary"></div>
            <span className="text-sm text-muted-foreground">Typosquatting</span>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}