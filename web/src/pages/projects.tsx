import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import { packageService } from '../services/package';
import { formatDate, formatNumber, getRiskLevelColor } from '../lib/utils';
import { Project, ProjectScan, ScanResult } from '../types/package';

interface ProjectWithStats extends Project {
  lastScan?: ProjectScan;
  threatCount: number;
  packageCount: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
}

const Projects: React.FC = () => {
  const [projects, setProjects] = useState<ProjectWithStats[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedProject, setSelectedProject] = useState<ProjectWithStats | null>(null);
  const [scanHistory, setScanHistory] = useState<ProjectScan[]>([]);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newProject, setNewProject] = useState({ name: '', description: '', repository_url: '' });

  useEffect(() => {
    fetchProjects();
  }, []);

  const fetchProjects = async () => {
    try {
      setLoading(true);
      // Mock data - in real implementation, this would come from API
      const mockProjects: ProjectWithStats[] = [
        {
          id: '1',
          name: 'Frontend App',
          description: 'Main React application',
          repository_url: 'https://github.com/org/frontend-app',
          created_at: '2024-01-15T10:00:00Z',
          updated_at: '2024-01-20T14:30:00Z',
          threatCount: 5,
          packageCount: 234,
          riskLevel: 'medium',
          lastScan: {
            id: 'scan-1',
            project_id: '1',
            status: 'completed',
            started_at: '2024-01-20T14:00:00Z',
            completed_at: '2024-01-20T14:30:00Z',
            total_packages: 234,
            threats_found: 5,
            risk_score: 65
          }
        },
        {
          id: '2',
          name: 'Backend API',
          description: 'Node.js REST API server',
          repository_url: 'https://github.com/org/backend-api',
          created_at: '2024-01-10T09:00:00Z',
          updated_at: '2024-01-19T16:45:00Z',
          threatCount: 12,
          packageCount: 156,
          riskLevel: 'high',
          lastScan: {
            id: 'scan-2',
            project_id: '2',
            status: 'completed',
            started_at: '2024-01-19T16:00:00Z',
            completed_at: '2024-01-19T16:45:00Z',
            total_packages: 156,
            threats_found: 12,
            risk_score: 85
          }
        },
        {
          id: '3',
          name: 'Mobile App',
          description: 'React Native mobile application',
          repository_url: 'https://github.com/org/mobile-app',
          created_at: '2024-01-05T11:00:00Z',
          updated_at: '2024-01-18T13:20:00Z',
          threatCount: 2,
          packageCount: 89,
          riskLevel: 'low',
          lastScan: {
            id: 'scan-3',
            project_id: '3',
            status: 'completed',
            started_at: '2024-01-18T13:00:00Z',
            completed_at: '2024-01-18T13:20:00Z',
            total_packages: 89,
            threats_found: 2,
            risk_score: 25
          }
        }
      ];
      setProjects(mockProjects);
    } catch (error) {
      console.error('Failed to fetch projects:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchScanHistory = async (projectId: string) => {
    try {
      // Mock scan history data
      const mockHistory: ProjectScan[] = [
        {
          id: 'scan-1',
          project_id: projectId,
          status: 'completed',
          started_at: '2024-01-20T14:00:00Z',
          completed_at: '2024-01-20T14:30:00Z',
          total_packages: 234,
          threats_found: 5,
          risk_score: 65
        },
        {
          id: 'scan-2',
          project_id: projectId,
          status: 'completed',
          started_at: '2024-01-19T10:00:00Z',
          completed_at: '2024-01-19T10:25:00Z',
          total_packages: 230,
          threats_found: 7,
          risk_score: 72
        },
        {
          id: 'scan-3',
          project_id: projectId,
          status: 'completed',
          started_at: '2024-01-18T16:00:00Z',
          completed_at: '2024-01-18T16:20:00Z',
          total_packages: 228,
          threats_found: 8,
          risk_score: 78
        }
      ];
      setScanHistory(mockHistory);
    } catch (error) {
      console.error('Failed to fetch scan history:', error);
    }
  };

  const handleCreateProject = async () => {
    try {
      // In real implementation, this would call the API
      console.log('Creating project:', newProject);
      setShowCreateModal(false);
      setNewProject({ name: '', description: '', repository_url: '' });
      await fetchProjects();
    } catch (error) {
      console.error('Failed to create project:', error);
    }
  };

  const handleTriggerScan = async (projectId: string) => {
    try {
      // In real implementation, this would call the API
      console.log('Triggering scan for project:', projectId);
      // Update project status to show scanning
      setProjects(prev => prev.map(p => 
        p.id === projectId 
          ? { ...p, lastScan: { ...p.lastScan!, status: 'running' } }
          : p
      ));
    } catch (error) {
      console.error('Failed to trigger scan:', error);
    }
  };

  const handleProjectSelect = (project: ProjectWithStats) => {
    setSelectedProject(project);
    fetchScanHistory(project.id);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Projects</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">
            Manage and monitor your organization's projects
          </p>
        </div>
        <Button onClick={() => setShowCreateModal(true)}>
          <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          New Project
        </Button>
      </div>

      {/* Projects Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {projects.map((project) => (
          <Card 
            key={project.id} 
            className={`cursor-pointer transition-all hover:shadow-lg ${
              selectedProject?.id === project.id ? 'ring-2 ring-blue-500' : ''
            }`}
            onClick={() => handleProjectSelect(project)}
          >
            <CardHeader>
              <div className="flex justify-between items-start">
                <div>
                  <CardTitle className="text-lg">{project.name}</CardTitle>
                  <CardDescription className="mt-1">{project.description}</CardDescription>
                </div>
                <div className={`px-2 py-1 rounded-full text-xs font-medium ${
                  getRiskLevelColor(project.riskLevel, false)
                } bg-opacity-20`}>
                  {project.riskLevel.toUpperCase()}
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600 dark:text-gray-400">Packages</span>
                  <span className="font-medium">{formatNumber(project.packageCount)}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600 dark:text-gray-400">Threats</span>
                  <span className={`font-medium ${
                    project.threatCount > 0 ? 'text-red-600' : 'text-green-600'
                  }`}>
                    {project.threatCount}
                  </span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600 dark:text-gray-400">Last Scan</span>
                  <span className="font-medium">
                    {project.lastScan ? formatDate(project.lastScan.completed_at || project.lastScan.started_at) : 'Never'}
                  </span>
                </div>
                <div className="flex justify-between items-center pt-2">
                  <span className={`text-xs px-2 py-1 rounded-full ${
                    project.lastScan?.status === 'completed' ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' :
                    project.lastScan?.status === 'running' ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200' :
                    project.lastScan?.status === 'failed' ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200' :
                    'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200'
                  }`}>
                    {project.lastScan?.status || 'No scans'}
                  </span>
                  <Button 
                    size="sm" 
                    variant="outline"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleTriggerScan(project.id);
                    }}
                    disabled={project.lastScan?.status === 'running'}
                  >
                    {project.lastScan?.status === 'running' ? 'Scanning...' : 'Scan'}
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Project Details */}
      {selectedProject && (
        <Card>
          <CardHeader>
            <CardTitle>Project Details: {selectedProject.name}</CardTitle>
            <CardDescription>Detailed information and scan history</CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="overview" className="space-y-4">
              <TabsList>
                <TabsTrigger value="overview">Overview</TabsTrigger>
                <TabsTrigger value="scans">Scan History</TabsTrigger>
                <TabsTrigger value="dependencies">Dependencies</TabsTrigger>
                <TabsTrigger value="settings">Settings</TabsTrigger>
              </TabsList>

              <TabsContent value="overview" className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="space-y-2">
                    <h4 className="font-medium text-gray-900 dark:text-white">Repository</h4>
                    <a 
                      href={selectedProject.repository_url} 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 text-sm break-all"
                    >
                      {selectedProject.repository_url}
                    </a>
                  </div>
                  <div className="space-y-2">
                    <h4 className="font-medium text-gray-900 dark:text-white">Created</h4>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                      {formatDate(selectedProject.created_at)}
                    </p>
                  </div>
                  <div className="space-y-2">
                    <h4 className="font-medium text-gray-900 dark:text-white">Last Updated</h4>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                      {formatDate(selectedProject.updated_at)}
                    </p>
                  </div>
                </div>

                {selectedProject.lastScan && (
                  <div className="mt-6">
                    <h4 className="font-medium text-gray-900 dark:text-white mb-3">Latest Scan Results</h4>
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                      <div className="bg-gray-50 dark:bg-gray-800 p-4 rounded-lg">
                        <div className="text-2xl font-bold text-blue-600">
                          {selectedProject.lastScan.total_packages}
                        </div>
                        <div className="text-sm text-gray-600 dark:text-gray-400">Total Packages</div>
                      </div>
                      <div className="bg-gray-50 dark:bg-gray-800 p-4 rounded-lg">
                        <div className="text-2xl font-bold text-red-600">
                          {selectedProject.lastScan.threats_found}
                        </div>
                        <div className="text-sm text-gray-600 dark:text-gray-400">Threats Found</div>
                      </div>
                      <div className="bg-gray-50 dark:bg-gray-800 p-4 rounded-lg">
                        <div className="text-2xl font-bold text-orange-600">
                          {selectedProject.lastScan.risk_score}
                        </div>
                        <div className="text-sm text-gray-600 dark:text-gray-400">Risk Score</div>
                      </div>
                      <div className="bg-gray-50 dark:bg-gray-800 p-4 rounded-lg">
                        <div className="text-2xl font-bold text-green-600">
                          {selectedProject.lastScan.completed_at ? 
                            Math.round((new Date(selectedProject.lastScan.completed_at).getTime() - 
                                      new Date(selectedProject.lastScan.started_at).getTime()) / 60000) : 0}m
                        </div>
                        <div className="text-sm text-gray-600 dark:text-gray-400">Scan Duration</div>
                      </div>
                    </div>
                  </div>
                )}
              </TabsContent>

              <TabsContent value="scans" className="space-y-4">
                <div className="space-y-3">
                  {scanHistory.map((scan) => (
                    <div key={scan.id} className="border dark:border-gray-700 rounded-lg p-4">
                      <div className="flex justify-between items-start">
                        <div className="space-y-1">
                          <div className="flex items-center space-x-2">
                            <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                              scan.status === 'completed' ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' :
                              scan.status === 'running' ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200' :
                              'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
                            }`}>
                              {scan.status}
                            </span>
                            <span className="text-sm text-gray-600 dark:text-gray-400">
                              {formatDate(scan.started_at)}
                            </span>
                          </div>
                          <div className="text-sm text-gray-600 dark:text-gray-400">
                            {scan.total_packages} packages scanned, {scan.threats_found} threats found
                          </div>
                        </div>
                        <div className="text-right">
                          <div className="text-lg font-bold text-orange-600">{scan.risk_score}</div>
                          <div className="text-xs text-gray-600 dark:text-gray-400">Risk Score</div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </TabsContent>

              <TabsContent value="dependencies" className="space-y-4">
                <div className="text-center py-8 text-gray-500">
                  <svg className="mx-auto h-12 w-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" />
                  </svg>
                  <p className="mt-2">Dependency tree visualization would be implemented here</p>
                  <p className="text-sm text-gray-400">Showing package dependencies and their relationships</p>
                </div>
              </TabsContent>

              <TabsContent value="settings" className="space-y-4">
                <div className="space-y-4">
                  <div>
                    <h4 className="font-medium text-gray-900 dark:text-white mb-2">Project Settings</h4>
                    <div className="space-y-3">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                          Project Name
                        </label>
                        <input 
                          type="text" 
                          value={selectedProject.name}
                          className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                          readOnly
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                          Description
                        </label>
                        <textarea 
                          value={selectedProject.description}
                          className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                          rows={3}
                          readOnly
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                          Repository URL
                        </label>
                        <input 
                          type="url" 
                          value={selectedProject.repository_url}
                          className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                          readOnly
                        />
                      </div>
                    </div>
                  </div>
                </div>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      )}

      {/* Create Project Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-full max-w-md">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Create New Project</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Project Name
                </label>
                <input 
                  type="text" 
                  value={newProject.name}
                  onChange={(e) => setNewProject(prev => ({ ...prev, name: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                  placeholder="Enter project name"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Description
                </label>
                <textarea 
                  value={newProject.description}
                  onChange={(e) => setNewProject(prev => ({ ...prev, description: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                  rows={3}
                  placeholder="Enter project description"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Repository URL
                </label>
                <input 
                  type="url" 
                  value={newProject.repository_url}
                  onChange={(e) => setNewProject(prev => ({ ...prev, repository_url: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                  placeholder="https://github.com/org/repo"
                />
              </div>
            </div>
            <div className="flex justify-end space-x-3 mt-6">
              <Button 
                variant="outline" 
                onClick={() => {
                  setShowCreateModal(false);
                  setNewProject({ name: '', description: '', repository_url: '' });
                }}
              >
                Cancel
              </Button>
              <Button 
                onClick={handleCreateProject}
                disabled={!newProject.name.trim()}
              >
                Create Project
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Projects;