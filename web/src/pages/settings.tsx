import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import { authService } from '../services/auth';
import { formatDate } from '../lib/utils';
import { User, Organization, OrganizationSettings, CustomRegistry } from '../types/auth';

const Settings: React.FC = () => {
  const [user, setUser] = useState<User | null>(null);
  const [organization, setOrganization] = useState<Organization | null>(null);
  const [orgSettings, setOrgSettings] = useState<OrganizationSettings | null>(null);
  const [customRegistries, setCustomRegistries] = useState<CustomRegistry[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [showAddRegistry, setShowAddRegistry] = useState(false);
  const [newRegistry, setNewRegistry] = useState({
    name: '',
    url: '',
    auth_type: 'none' as 'none' | 'basic' | 'token',
    username: '',
    password: '',
    token: ''
  });
  const [passwordForm, setPasswordForm] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });

  useEffect(() => {
    fetchUserData();
    fetchOrganizationData();
  }, []);

  const fetchUserData = async () => {
    try {
      const userData = await authService.getCurrentUser();
      setUser(userData);
    } catch (error) {
      console.error('Failed to fetch user data:', error);
    }
  };

  const fetchOrganizationData = async () => {
    try {
      setLoading(true);
      // Mock data - in real implementation, these would come from API
      const mockOrg: Organization = {
        id: 'org-1',
        name: 'Acme Corporation',
        domain: 'acme.com',
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-20T10:00:00Z'
      };

      const mockSettings: OrganizationSettings = {
        scan_settings: {
          auto_scan: true,
          scan_frequency: 'daily',
          include_dev_dependencies: true,
          severity_threshold: 'medium'
        },
        notification_settings: {
          email_notifications: true,
          slack_webhook: '',
          notify_on_new_threats: true,
          notify_on_scan_completion: false
        },
        security_settings: {
          require_2fa: false,
          session_timeout: 3600,
          allowed_domains: ['acme.com']
        }
      };

      const mockRegistries: CustomRegistry[] = [
        {
          id: 'reg-1',
          name: 'Internal NPM',
          url: 'https://npm.internal.acme.com',
          auth_type: 'token',
          is_active: true,
          created_at: '2024-01-10T00:00:00Z'
        },
        {
          id: 'reg-2',
          name: 'Private PyPI',
          url: 'https://pypi.internal.acme.com',
          auth_type: 'basic',
          is_active: true,
          created_at: '2024-01-15T00:00:00Z'
        }
      ];

      setOrganization(mockOrg);
      setOrgSettings(mockSettings);
      setCustomRegistries(mockRegistries);
    } catch (error) {
      console.error('Failed to fetch organization data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSaveSettings = async () => {
    try {
      setSaving(true);
      // In real implementation, this would call the API
      console.log('Saving organization settings:', orgSettings);
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));
    } catch (error) {
      console.error('Failed to save settings:', error);
    } finally {
      setSaving(false);
    }
  };

  const handleAddRegistry = async () => {
    try {
      // In real implementation, this would call the API
      const registry: CustomRegistry = {
        id: `reg-${Date.now()}`,
        name: newRegistry.name,
        url: newRegistry.url,
        auth_type: newRegistry.auth_type,
        is_active: true,
        created_at: new Date().toISOString()
      };
      setCustomRegistries(prev => [...prev, registry]);
      setShowAddRegistry(false);
      setNewRegistry({
        name: '',
        url: '',
        auth_type: 'none',
        username: '',
        password: '',
        token: ''
      });
    } catch (error) {
      console.error('Failed to add registry:', error);
    }
  };

  const handleDeleteRegistry = async (registryId: string) => {
    try {
      // In real implementation, this would call the API
      setCustomRegistries(prev => prev.filter(r => r.id !== registryId));
    } catch (error) {
      console.error('Failed to delete registry:', error);
    }
  };

  const handleChangePassword = async () => {
    try {
      if (passwordForm.newPassword !== passwordForm.confirmPassword) {
        alert('New passwords do not match');
        return;
      }
      // In real implementation, this would call the API
      await authService.changePassword(passwordForm.currentPassword, passwordForm.newPassword);
      setPasswordForm({ currentPassword: '', newPassword: '', confirmPassword: '' });
      alert('Password changed successfully');
    } catch (error) {
      console.error('Failed to change password:', error);
      alert('Failed to change password');
    }
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
      <div>
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Settings</h1>
        <p className="text-gray-600 dark:text-gray-400 mt-1">
          Manage your account and organization settings
        </p>
      </div>

      <Tabs defaultValue="profile" className="space-y-4">
        <TabsList>
          <TabsTrigger value="profile">Profile</TabsTrigger>
          <TabsTrigger value="organization">Organization</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
          <TabsTrigger value="registries">Custom Registries</TabsTrigger>
          <TabsTrigger value="notifications">Notifications</TabsTrigger>
        </TabsList>

        <TabsContent value="profile" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Profile Information</CardTitle>
              <CardDescription>Update your personal information</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {user && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Full Name
                    </label>
                    <input 
                      type="text" 
                      value={user.name}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                      readOnly
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Email Address
                    </label>
                    <input 
                      type="email" 
                      value={user.email}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                      readOnly
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Role
                    </label>
                    <input 
                      type="text" 
                      value={user.role}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                      readOnly
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Member Since
                    </label>
                    <input 
                      type="text" 
                      value={formatDate(user.created_at)}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                      readOnly
                    />
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Change Password</CardTitle>
              <CardDescription>Update your account password</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Current Password
                </label>
                <input 
                  type="password" 
                  value={passwordForm.currentPassword}
                  onChange={(e) => setPasswordForm(prev => ({ ...prev, currentPassword: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  New Password
                </label>
                <input 
                  type="password" 
                  value={passwordForm.newPassword}
                  onChange={(e) => setPasswordForm(prev => ({ ...prev, newPassword: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Confirm New Password
                </label>
                <input 
                  type="password" 
                  value={passwordForm.confirmPassword}
                  onChange={(e) => setPasswordForm(prev => ({ ...prev, confirmPassword: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                />
              </div>
              <Button 
                onClick={handleChangePassword}
                disabled={!passwordForm.currentPassword || !passwordForm.newPassword || !passwordForm.confirmPassword}
              >
                Change Password
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="organization" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Organization Information</CardTitle>
              <CardDescription>Basic organization details</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {organization && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Organization Name
                    </label>
                    <input 
                      type="text" 
                      value={organization.name}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                      readOnly
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Domain
                    </label>
                    <input 
                      type="text" 
                      value={organization.domain}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                      readOnly
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Created
                    </label>
                    <input 
                      type="text" 
                      value={formatDate(organization.created_at)}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                      readOnly
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Last Updated
                    </label>
                    <input 
                      type="text" 
                      value={formatDate(organization.updated_at)}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                      readOnly
                    />
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Scan Settings</CardTitle>
              <CardDescription>Configure automatic scanning behavior</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {orgSettings && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-medium text-gray-900 dark:text-white">Auto Scan</h4>
                      <p className="text-sm text-gray-600 dark:text-gray-400">Automatically scan projects on changes</p>
                    </div>
                    <input 
                      type="checkbox" 
                      checked={orgSettings.scan_settings.auto_scan}
                      onChange={(e) => setOrgSettings(prev => prev ? {
                        ...prev,
                        scan_settings: { ...prev.scan_settings, auto_scan: e.target.checked }
                      } : null)}
                      className="h-4 w-4 text-blue-600 rounded"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Scan Frequency
                    </label>
                    <select 
                      value={orgSettings.scan_settings.scan_frequency}
                      onChange={(e) => setOrgSettings(prev => prev ? {
                        ...prev,
                        scan_settings: { ...prev.scan_settings, scan_frequency: e.target.value as any }
                      } : null)}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                    >
                      <option value="hourly">Hourly</option>
                      <option value="daily">Daily</option>
                      <option value="weekly">Weekly</option>
                      <option value="monthly">Monthly</option>
                    </select>
                  </div>
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-medium text-gray-900 dark:text-white">Include Dev Dependencies</h4>
                      <p className="text-sm text-gray-600 dark:text-gray-400">Scan development dependencies</p>
                    </div>
                    <input 
                      type="checkbox" 
                      checked={orgSettings.scan_settings.include_dev_dependencies}
                      onChange={(e) => setOrgSettings(prev => prev ? {
                        ...prev,
                        scan_settings: { ...prev.scan_settings, include_dev_dependencies: e.target.checked }
                      } : null)}
                      className="h-4 w-4 text-blue-600 rounded"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Severity Threshold
                    </label>
                    <select 
                      value={orgSettings.scan_settings.severity_threshold}
                      onChange={(e) => setOrgSettings(prev => prev ? {
                        ...prev,
                        scan_settings: { ...prev.scan_settings, severity_threshold: e.target.value as any }
                      } : null)}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                    >
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                      <option value="critical">Critical</option>
                    </select>
                  </div>
                </div>
              )}
              <Button onClick={handleSaveSettings} disabled={saving}>
                {saving ? 'Saving...' : 'Save Settings'}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="security" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Security Settings</CardTitle>
              <CardDescription>Configure security policies for your organization</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {orgSettings && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-medium text-gray-900 dark:text-white">Require Two-Factor Authentication</h4>
                      <p className="text-sm text-gray-600 dark:text-gray-400">Require 2FA for all organization members</p>
                    </div>
                    <input 
                      type="checkbox" 
                      checked={orgSettings.security_settings.require_2fa}
                      onChange={(e) => setOrgSettings(prev => prev ? {
                        ...prev,
                        security_settings: { ...prev.security_settings, require_2fa: e.target.checked }
                      } : null)}
                      className="h-4 w-4 text-blue-600 rounded"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Session Timeout (seconds)
                    </label>
                    <input 
                      type="number" 
                      value={orgSettings.security_settings.session_timeout}
                      onChange={(e) => setOrgSettings(prev => prev ? {
                        ...prev,
                        security_settings: { ...prev.security_settings, session_timeout: parseInt(e.target.value) }
                      } : null)}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Allowed Domains
                    </label>
                    <input 
                      type="text" 
                      value={orgSettings.security_settings.allowed_domains.join(', ')}
                      onChange={(e) => setOrgSettings(prev => prev ? {
                        ...prev,
                        security_settings: { ...prev.security_settings, allowed_domains: e.target.value.split(',').map(d => d.trim()) }
                      } : null)}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                      placeholder="domain1.com, domain2.com"
                    />
                  </div>
                </div>
              )}
              <Button onClick={handleSaveSettings} disabled={saving}>
                {saving ? 'Saving...' : 'Save Settings'}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="registries" className="space-y-4">
          <div className="flex justify-between items-center">
            <div>
              <h3 className="text-lg font-medium text-gray-900 dark:text-white">Custom Package Registries</h3>
              <p className="text-sm text-gray-600 dark:text-gray-400">Configure custom package registries for scanning</p>
            </div>
            <Button onClick={() => setShowAddRegistry(true)}>
              <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
              Add Registry
            </Button>
          </div>

          <div className="space-y-4">
            {customRegistries.map((registry) => (
              <Card key={registry.id}>
                <CardContent className="pt-6">
                  <div className="flex justify-between items-start">
                    <div className="space-y-2">
                      <div className="flex items-center space-x-2">
                        <h4 className="font-medium text-gray-900 dark:text-white">{registry.name}</h4>
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                          registry.is_active 
                            ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
                            : 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200'
                        }`}>
                          {registry.is_active ? 'Active' : 'Inactive'}
                        </span>
                      </div>
                      <p className="text-sm text-gray-600 dark:text-gray-400">{registry.url}</p>
                      <p className="text-xs text-gray-500 dark:text-gray-500">
                        Auth: {registry.auth_type} • Created: {formatDate(registry.created_at)}
                      </p>
                    </div>
                    <div className="flex space-x-2">
                      <Button size="sm" variant="outline">
                        Test
                      </Button>
                      <Button 
                        size="sm" 
                        variant="outline"
                        onClick={() => handleDeleteRegistry(registry.id)}
                        className="text-red-600 hover:text-red-700"
                      >
                        Delete
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Add Registry Modal */}
          {showAddRegistry && (
            <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
              <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-full max-w-md">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Add Custom Registry</h3>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Registry Name
                    </label>
                    <input 
                      type="text" 
                      value={newRegistry.name}
                      onChange={(e) => setNewRegistry(prev => ({ ...prev, name: e.target.value }))}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                      placeholder="Internal NPM"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Registry URL
                    </label>
                    <input 
                      type="url" 
                      value={newRegistry.url}
                      onChange={(e) => setNewRegistry(prev => ({ ...prev, url: e.target.value }))}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                      placeholder="https://npm.internal.company.com"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Authentication Type
                    </label>
                    <select 
                      value={newRegistry.auth_type}
                      onChange={(e) => setNewRegistry(prev => ({ ...prev, auth_type: e.target.value as any }))}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                    >
                      <option value="none">None</option>
                      <option value="basic">Basic Auth</option>
                      <option value="token">Token</option>
                    </select>
                  </div>
                  {newRegistry.auth_type === 'basic' && (
                    <>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                          Username
                        </label>
                        <input 
                          type="text" 
                          value={newRegistry.username}
                          onChange={(e) => setNewRegistry(prev => ({ ...prev, username: e.target.value }))}
                          className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                          Password
                        </label>
                        <input 
                          type="password" 
                          value={newRegistry.password}
                          onChange={(e) => setNewRegistry(prev => ({ ...prev, password: e.target.value }))}
                          className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                        />
                      </div>
                    </>
                  )}
                  {newRegistry.auth_type === 'token' && (
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Access Token
                      </label>
                      <input 
                        type="password" 
                        value={newRegistry.token}
                        onChange={(e) => setNewRegistry(prev => ({ ...prev, token: e.target.value }))}
                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                      />
                    </div>
                  )}
                </div>
                <div className="flex justify-end space-x-3 mt-6">
                  <Button 
                    variant="outline" 
                    onClick={() => {
                      setShowAddRegistry(false);
                      setNewRegistry({
                        name: '',
                        url: '',
                        auth_type: 'none',
                        username: '',
                        password: '',
                        token: ''
                      });
                    }}
                  >
                    Cancel
                  </Button>
                  <Button 
                    onClick={handleAddRegistry}
                    disabled={!newRegistry.name.trim() || !newRegistry.url.trim()}
                  >
                    Add Registry
                  </Button>
                </div>
              </div>
            </div>
          )}
        </TabsContent>

        <TabsContent value="notifications" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Notification Settings</CardTitle>
              <CardDescription>Configure how you receive notifications</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {orgSettings && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-medium text-gray-900 dark:text-white">Email Notifications</h4>
                      <p className="text-sm text-gray-600 dark:text-gray-400">Receive notifications via email</p>
                    </div>
                    <input 
                      type="checkbox" 
                      checked={orgSettings.notification_settings.email_notifications}
                      onChange={(e) => setOrgSettings(prev => prev ? {
                        ...prev,
                        notification_settings: { ...prev.notification_settings, email_notifications: e.target.checked }
                      } : null)}
                      className="h-4 w-4 text-blue-600 rounded"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Slack Webhook URL
                    </label>
                    <input 
                      type="url" 
                      value={orgSettings.notification_settings.slack_webhook}
                      onChange={(e) => setOrgSettings(prev => prev ? {
                        ...prev,
                        notification_settings: { ...prev.notification_settings, slack_webhook: e.target.value }
                      } : null)}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                      placeholder="https://hooks.slack.com/services/..."
                    />
                  </div>
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-medium text-gray-900 dark:text-white">Notify on New Threats</h4>
                      <p className="text-sm text-gray-600 dark:text-gray-400">Get notified when new threats are detected</p>
                    </div>
                    <input 
                      type="checkbox" 
                      checked={orgSettings.notification_settings.notify_on_new_threats}
                      onChange={(e) => setOrgSettings(prev => prev ? {
                        ...prev,
                        notification_settings: { ...prev.notification_settings, notify_on_new_threats: e.target.checked }
                      } : null)}
                      className="h-4 w-4 text-blue-600 rounded"
                    />
                  </div>
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-medium text-gray-900 dark:text-white">Notify on Scan Completion</h4>
                      <p className="text-sm text-gray-600 dark:text-gray-400">Get notified when scans complete</p>
                    </div>
                    <input 
                      type="checkbox" 
                      checked={orgSettings.notification_settings.notify_on_scan_completion}
                      onChange={(e) => setOrgSettings(prev => prev ? {
                        ...prev,
                        notification_settings: { ...prev.notification_settings, notify_on_scan_completion: e.target.checked }
                      } : null)}
                      className="h-4 w-4 text-blue-600 rounded"
                    />
                  </div>
                </div>
              )}
              <Button onClick={handleSaveSettings} disabled={saving}>
                {saving ? 'Saving...' : 'Save Settings'}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default Settings;