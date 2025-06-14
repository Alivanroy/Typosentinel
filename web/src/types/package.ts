export interface Package {
  id: string
  name: string
  version: string
  registry: 'npm' | 'pypi' | 'maven' | 'nuget' | 'cargo' | 'rubygems' | 'custom'
  description?: string
  author?: string
  homepage?: string
  repository?: string
  license?: string
  downloads?: number
  lastUpdated: string
  createdAt: string
  riskScore: number
  riskLevel: 'none' | 'low' | 'medium' | 'high'
  threats: Threat[]
  dependencies?: Dependency[]
  metadata: PackageMetadata
}

export interface Threat {
  id: string
  type: 'typosquatting' | 'dependency_confusion' | 'malicious_code' | 'reputation' | 'homoglyph'
  severity: 'low' | 'medium' | 'high' | 'critical'
  description: string
  confidence: number
  targetPackage?: string
  evidence: ThreatEvidence[]
  detectedAt: string
}

export interface ThreatEvidence {
  type: 'similarity' | 'metadata' | 'code_analysis' | 'reputation' | 'ml_prediction'
  value: string | number
  description: string
}

export interface Dependency {
  name: string
  version: string
  type: 'direct' | 'transitive'
  depth: number
  riskScore: number
  threats: Threat[]
  children?: Dependency[]
}

export interface PackageMetadata {
  size?: number
  files?: number
  maintainers?: string[]
  keywords?: string[]
  engines?: Record<string, string>
  scripts?: Record<string, string>
  peerDependencies?: Record<string, string>
  devDependencies?: Record<string, string>
}

export interface ScanRequest {
  type: 'package' | 'project' | 'repository'
  target: string
  options: ScanOptions
}

export interface ScanOptions {
  includeDevDependencies: boolean
  maxDepth: number
  registries: string[]
  riskThreshold: number
  enableMLAnalysis: boolean
}

export interface ScanResult {
  id: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  type: 'package' | 'project' | 'repository'
  target: string
  startedAt: string
  completedAt?: string
  duration?: number
  summary: ScanSummary
  packages: Package[]
  dependencyTree?: DependencyTree
  errors?: string[]
}

export interface ScanSummary {
  totalPackages: number
  threatsFound: number
  riskDistribution: {
    none: number
    low: number
    medium: number
    high: number
  }
  threatTypes: Record<string, number>
  registries: Record<string, number>
}

export interface DependencyTree {
  name: string
  version: string
  riskScore: number
  threats: Threat[]
  dependencies: DependencyTree[]
  metadata: {
    depth: number
    size: number
    isDevDependency: boolean
  }
}

export interface ProjectScan {
  id: string
  name: string
  path: string
  type: 'nodejs' | 'python' | 'java' | 'dotnet' | 'rust' | 'ruby' | 'php' | 'go'
  lastScanAt?: string
  autoScan: boolean
  riskScore: number
  threatCount: number
  packageCount: number
  status: 'healthy' | 'warning' | 'critical'
}