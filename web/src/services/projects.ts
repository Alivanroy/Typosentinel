import { api } from './api';

export interface Project {
  id: string;
  name: string;
  description?: string;
  repositoryUrl?: string;
  language: string;
  packageManager: string;
  lastScanAt?: string;
  createdAt: string;
  updatedAt: string;
  status: 'active' | 'inactive' | 'scanning';
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  packageCount: number;
  threatCount: number;
}

export interface ProjectScan {
  id: string;
  projectId: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  startedAt: string;
  completedAt?: string;
  packagesScanned: number;
  threatsFound: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  summary?: string;
  errorMessage?: string;
}

export interface ProjectStats {
  totalProjects: number;
  activeProjects: number;
  totalScans: number;
  averageRiskScore: number;
  projectsByLanguage: { [key: string]: number };
  projectsByRisk: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
}

export interface CreateProjectRequest {
  name: string;
  description?: string;
  repositoryUrl?: string;
  language: string;
  packageManager: string;
}

export interface UpdateProjectRequest {
  name?: string;
  description?: string;
  repositoryUrl?: string;
  language?: string;
  packageManager?: string;
  status?: 'active' | 'inactive';
}

class ProjectService {
  async getProjects(page: number = 1, limit: number = 20): Promise<{ projects: Project[]; total: number }> {
    try {
      const params = new URLSearchParams({
        page: page.toString(),
        limit: limit.toString()
      });
      const response = await api.get<{ projects: Project[]; total: number }>(`/projects?${params}`);
      return response.data;
    } catch (error) {
      console.error('Failed to fetch projects:', error);
      // Return mock data for development
      return {
        projects: [
          {
            id: '1',
            name: 'Frontend Application',
            description: 'React-based web application',
            repositoryUrl: 'https://github.com/company/frontend-app',
            language: 'JavaScript',
            packageManager: 'npm',
            lastScanAt: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
            createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 30).toISOString(),
            updatedAt: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
            status: 'active',
            riskLevel: 'medium',
            packageCount: 245,
            threatCount: 3
          },
          {
            id: '2',
            name: 'API Server',
            description: 'Node.js REST API server',
            repositoryUrl: 'https://github.com/company/api-server',
            language: 'JavaScript',
            packageManager: 'npm',
            lastScanAt: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(),
            createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 25).toISOString(),
            updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(),
            status: 'active',
            riskLevel: 'low',
            packageCount: 189,
            threatCount: 1
          },
          {
            id: '3',
            name: 'Data Analytics',
            description: 'Python data processing pipeline',
            repositoryUrl: 'https://github.com/company/data-analytics',
            language: 'Python',
            packageManager: 'pip',
            lastScanAt: new Date(Date.now() - 1000 * 60 * 60 * 4).toISOString(),
            createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 20).toISOString(),
            updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 4).toISOString(),
            status: 'active',
            riskLevel: 'high',
            packageCount: 156,
            threatCount: 5
          },
          {
            id: '4',
            name: 'Mobile Backend',
            description: 'Go microservices for mobile app',
            repositoryUrl: 'https://github.com/company/mobile-backend',
            language: 'Go',
            packageManager: 'go mod',
            lastScanAt: new Date(Date.now() - 1000 * 60 * 60 * 6).toISOString(),
            createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 15).toISOString(),
            updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 6).toISOString(),
            status: 'active',
            riskLevel: 'low',
            packageCount: 98,
            threatCount: 0
          }
        ],
        total: 4
      };
    }
  }

  async getProject(id: string): Promise<Project> {
    try {
      const response = await api.get<Project>(`/projects/${id}`);
      return response.data;
    } catch (error) {
      console.error('Failed to fetch project:', error);
      throw error;
    }
  }

  async createProject(project: CreateProjectRequest): Promise<Project> {
    try {
      const response = await api.post<Project>('/projects', project);
      return response.data;
    } catch (error) {
      console.error('Failed to create project:', error);
      throw error;
    }
  }

  async updateProject(id: string, updates: UpdateProjectRequest): Promise<Project> {
    try {
      const response = await api.put<Project>(`/projects/${id}`, updates);
      return response.data;
    } catch (error) {
      console.error('Failed to update project:', error);
      throw error;
    }
  }

  async deleteProject(id: string): Promise<void> {
    try {
      await api.delete(`/projects/${id}`);
    } catch (error) {
      console.error('Failed to delete project:', error);
      throw error;
    }
  }

  async triggerScan(id: string): Promise<ProjectScan> {
    try {
      const response = await api.post<ProjectScan>(`/projects/${id}/scan`);
      return response.data;
    } catch (error) {
      console.error('Failed to trigger scan:', error);
      throw error;
    }
  }

  async getProjectScans(id: string, page: number = 1, limit: number = 10): Promise<{ scans: ProjectScan[]; total: number }> {
    try {
      const params = new URLSearchParams({
        page: page.toString(),
        limit: limit.toString()
      });
      const response = await api.get<{ scans: ProjectScan[]; total: number }>(`/projects/${id}/scans?${params}`);
      return response.data;
    } catch (error) {
      console.error('Failed to fetch project scans:', error);
      // Return mock data for development
      return {
        scans: [
          {
            id: '1',
            projectId: id,
            status: 'completed',
            startedAt: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
            completedAt: new Date(Date.now() - 1000 * 60 * 25).toISOString(),
            packagesScanned: 245,
            threatsFound: 3,
            riskLevel: 'medium',
            summary: 'Found 3 potential threats in dependencies'
          },
          {
            id: '2',
            projectId: id,
            status: 'completed',
            startedAt: new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString(),
            completedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 + 1000 * 60 * 5).toISOString(),
            packagesScanned: 243,
            threatsFound: 2,
            riskLevel: 'low',
            summary: 'Found 2 low-risk issues'
          },
          {
            id: '3',
            projectId: id,
            status: 'failed',
            startedAt: new Date(Date.now() - 1000 * 60 * 60 * 48).toISOString(),
            completedAt: new Date(Date.now() - 1000 * 60 * 60 * 48 + 1000 * 60 * 2).toISOString(),
            packagesScanned: 0,
            threatsFound: 0,
            riskLevel: 'low',
            errorMessage: 'Failed to access repository'
          }
        ],
        total: 3
      };
    }
  }

  async getProjectStats(): Promise<ProjectStats> {
    try {
      const response = await api.get<ProjectStats>('/projects/stats');
      return response.data;
    } catch (error) {
      console.error('Failed to fetch project stats:', error);
      // Return mock data for development
      return {
        totalProjects: 12,
        activeProjects: 10,
        totalScans: 156,
        averageRiskScore: 2.3,
        projectsByLanguage: {
          'JavaScript': 5,
          'Python': 3,
          'Go': 2,
          'Java': 1,
          'Rust': 1
        },
        projectsByRisk: {
          low: 6,
          medium: 4,
          high: 2,
          critical: 0
        }
      };
    }
  }
}

export const projectService = new ProjectService();