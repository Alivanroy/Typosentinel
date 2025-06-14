import { api } from './api';

export interface Package {
  id: string;
  name: string;
  version: string;
  registry: string;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  riskScore: number;
  threats: string[];
  lastScanned: string;
  projectId?: string;
}

export interface PackageStats {
  total: number;
  scanned: number;
  threats: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface ThreatStats {
  total: number;
  typosquatting: number;
  malicious: number;
  suspicious: number;
  resolved: number;
}

export interface ScanStats {
  total: number;
  today: number;
  thisWeek: number;
  thisMonth: number;
  failed: number;
}

export interface RecentScan {
  id: string;
  projectName: string;
  packagesScanned: number;
  threatsFound: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  timestamp: string;
  status: 'completed' | 'failed' | 'running';
}

export interface ChartData {
  date: string;
  packages: number;
  threats: number;
  scans: number;
}

class PackageService {
  async getPackageStats(): Promise<PackageStats> {
    try {
      const response = await api.get<PackageStats>('/packages/stats');
      return response.data;
    } catch (error) {
      console.error('Failed to fetch package stats:', error);
      // Return mock data for development
      return {
        total: 1247,
        scanned: 1180,
        threats: 23,
        critical: 3,
        high: 8,
        medium: 12,
        low: 1157
      };
    }
  }

  async getThreatStats(): Promise<ThreatStats> {
    try {
      const response = await api.get<ThreatStats>('/threats/stats');
      return response.data;
    } catch (error) {
      console.error('Failed to fetch threat stats:', error);
      // Return mock data for development
      return {
        total: 23,
        typosquatting: 15,
        malicious: 5,
        suspicious: 3,
        resolved: 18
      };
    }
  }

  async getScanStats(): Promise<ScanStats> {
    try {
      const response = await api.get<ScanStats>('/scans/stats');
      return response.data;
    } catch (error) {
      console.error('Failed to fetch scan stats:', error);
      // Return mock data for development
      return {
        total: 156,
        today: 12,
        thisWeek: 45,
        thisMonth: 134,
        failed: 3
      };
    }
  }

  async getRecentScans(limit: number = 10): Promise<RecentScan[]> {
    try {
      const response = await api.get<RecentScan[]>(`/scans/recent?limit=${limit}`);
      return response.data;
    } catch (error) {
      console.error('Failed to fetch recent scans:', error);
      // Return mock data for development
      return [
        {
          id: '1',
          projectName: 'Frontend App',
          packagesScanned: 245,
          threatsFound: 3,
          riskLevel: 'medium',
          timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
          status: 'completed'
        },
        {
          id: '2',
          projectName: 'API Server',
          packagesScanned: 189,
          threatsFound: 1,
          riskLevel: 'low',
          timestamp: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(),
          status: 'completed'
        },
        {
          id: '3',
          projectName: 'Mobile App',
          packagesScanned: 156,
          threatsFound: 0,
          riskLevel: 'low',
          timestamp: new Date(Date.now() - 1000 * 60 * 60 * 4).toISOString(),
          status: 'completed'
        },
        {
          id: '4',
          projectName: 'Analytics Service',
          packagesScanned: 98,
          threatsFound: 2,
          riskLevel: 'medium',
          timestamp: new Date(Date.now() - 1000 * 60 * 60 * 6).toISOString(),
          status: 'completed'
        },
        {
          id: '5',
          projectName: 'Data Pipeline',
          packagesScanned: 67,
          threatsFound: 0,
          riskLevel: 'low',
          timestamp: new Date(Date.now() - 1000 * 60 * 60 * 8).toISOString(),
          status: 'failed'
        }
      ];
    }
  }

  async getChartData(days: number = 30): Promise<ChartData[]> {
    try {
      const response = await api.get<ChartData[]>(`/analytics/chart?days=${days}`);
      return response.data;
    } catch (error) {
      console.error('Failed to fetch chart data:', error);
      // Return mock data for development
      const data: ChartData[] = [];
      for (let i = days - 1; i >= 0; i--) {
        const date = new Date();
        date.setDate(date.getDate() - i);
        data.push({
          date: date.toISOString().split('T')[0],
          packages: Math.floor(Math.random() * 50) + 20,
          threats: Math.floor(Math.random() * 5),
          scans: Math.floor(Math.random() * 10) + 5
        });
      }
      return data;
    }
  }

  async getPackages(page: number = 1, limit: number = 20, filter?: string): Promise<{ packages: Package[]; total: number }> {
    try {
      const params = new URLSearchParams({
        page: page.toString(),
        limit: limit.toString(),
        ...(filter && { filter })
      });
      const response = await api.get<{ packages: Package[]; total: number }>(`/packages?${params}`);
      return response.data;
    } catch (error) {
      console.error('Failed to fetch packages:', error);
      // Return mock data for development
      return {
        packages: [],
        total: 0
      };
    }
  }

  async getPackage(id: string): Promise<Package> {
    try {
      const response = await api.get<Package>(`/packages/${id}`);
      return response.data;
    } catch (error) {
      console.error('Failed to fetch package:', error);
      throw error;
    }
  }

  async scanPackage(packageName: string, version?: string): Promise<Package> {
    try {
      const response = await api.post<Package>('/packages/scan', {
        name: packageName,
        version
      });
      return response.data;
    } catch (error) {
      console.error('Failed to scan package:', error);
      throw error;
    }
  }
}

export const packageService = new PackageService();