export interface User {
  id: string
  email: string
  name: string
  role: 'admin' | 'user' | 'viewer'
  organizationId: string
  organizationName: string
  createdAt: string
  lastLoginAt?: string
}

export interface LoginRequest {
  email: string
  password: string
}

export interface LoginResponse {
  user: User
  token: string
  expiresAt: string
}

export interface Organization {
  id: string
  name: string
  domain: string
  settings: OrganizationSettings
  createdAt: string
  updatedAt: string
}

export interface OrganizationSettings {
  riskThresholds: {
    high: number
    medium: number
    low: number
  }
  notifications: {
    email: boolean
    slack: boolean
    webhook?: string
  }
  scanning: {
    autoScan: boolean
    scanFrequency: 'hourly' | 'daily' | 'weekly'
    includeDevDependencies: boolean
  }
  registries: {
    npm: boolean
    pypi: boolean
    maven: boolean
    nuget: boolean
    custom: CustomRegistry[]
  }
}

export interface CustomRegistry {
  id: string
  name: string
  type: 'jfrog' | 'nexus' | 'generic'
  url: string
  authType: 'none' | 'basic' | 'token'
  credentials?: {
    username?: string
    password?: string
    token?: string
  }
}