import React, { useState, useEffect } from 'react';
import './Settings.css';

const Settings = () => {
  const [settings, setSettings] = useState({
    // General Settings
    autoScan: true,
    scanInterval: '24',
    maxConcurrentScans: '3',
    retainLogs: '30',
    
    // Notification Settings
    emailNotifications: true,
    slackNotifications: false,
    webhookNotifications: false,
    notificationThreshold: 'medium',
    emailAddress: '',
    slackWebhook: '',
    customWebhook: '',
    
    // Security Settings
    apiKeyRotation: '90',
    sessionTimeout: '60',
    twoFactorAuth: false,
    ipWhitelist: '',
    
    // Scan Settings
    deepScan: true,
    skipDevDependencies: false,
    customRules: '',
    excludePatterns: '',
    includePatterns: '',
    
    // API Settings
    apiRateLimit: '1000',
    apiTimeout: '30',
    enableCors: true,
    corsOrigins: '*',
    
    // Advanced Settings
    debugMode: false,
    verboseLogging: false,
    cacheEnabled: true,
    cacheSize: '500',
    parallelProcessing: true
  });
  
  const [activeTab, setActiveTab] = useState('general');
  const [loading, setLoading] = useState(false);
  const [saveStatus, setSaveStatus] = useState(null);
  const [errors, setErrors] = useState({});

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    setLoading(true);
    try {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // In a real app, this would fetch from an API
      const savedSettings = localStorage.getItem('typosentinel-settings');
      if (savedSettings) {
        setSettings(prev => ({ ...prev, ...JSON.parse(savedSettings) }));
      }
    } catch (error) {
      console.error('Failed to load settings:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (key, value) => {
    setSettings(prev => ({ ...prev, [key]: value }));
    
    // Clear error for this field
    if (errors[key]) {
      setErrors(prev => ({ ...prev, [key]: null }));
    }
  };

  const validateSettings = () => {
    const newErrors = {};
    
    // Validate email
    if (settings.emailNotifications && settings.emailAddress) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(settings.emailAddress)) {
        newErrors.emailAddress = 'Please enter a valid email address';
      }
    }
    
    // Validate numeric fields
    const numericFields = {
      scanInterval: 'Scan interval must be a positive number',
      maxConcurrentScans: 'Max concurrent scans must be a positive number',
      retainLogs: 'Log retention must be a positive number',
      apiKeyRotation: 'API key rotation must be a positive number',
      sessionTimeout: 'Session timeout must be a positive number',
      apiRateLimit: 'API rate limit must be a positive number',
      apiTimeout: 'API timeout must be a positive number',
      cacheSize: 'Cache size must be a positive number'
    };
    
    Object.entries(numericFields).forEach(([field, message]) => {
      const value = parseInt(settings[field]);
      if (isNaN(value) || value <= 0) {
        newErrors[field] = message;
      }
    });
    
    // Validate URLs
    const urlFields = ['slackWebhook', 'customWebhook'];
    urlFields.forEach(field => {
      if (settings[field]) {
        try {
          new URL(settings[field]);
        } catch {
          newErrors[field] = 'Please enter a valid URL';
        }
      }
    });
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSave = async () => {
    if (!validateSettings()) {
      setSaveStatus({ type: 'error', message: 'Please fix the validation errors' });
      return;
    }
    
    setLoading(true);
    setSaveStatus(null);
    
    try {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      // In a real app, this would save to an API
      localStorage.setItem('typosentinel-settings', JSON.stringify(settings));
      
      setSaveStatus({ type: 'success', message: 'Settings saved successfully!' });
    } catch (error) {
      setSaveStatus({ type: 'error', message: 'Failed to save settings. Please try again.' });
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    if (window.confirm('Are you sure you want to reset all settings to defaults?')) {
      setSettings({
        autoScan: true,
        scanInterval: '24',
        maxConcurrentScans: '3',
        retainLogs: '30',
        emailNotifications: true,
        slackNotifications: false,
        webhookNotifications: false,
        notificationThreshold: 'medium',
        emailAddress: '',
        slackWebhook: '',
        customWebhook: '',
        apiKeyRotation: '90',
        sessionTimeout: '60',
        twoFactorAuth: false,
        ipWhitelist: '',
        deepScan: true,
        skipDevDependencies: false,
        customRules: '',
        excludePatterns: '',
        includePatterns: '',
        apiRateLimit: '1000',
        apiTimeout: '30',
        enableCors: true,
        corsOrigins: '*',
        debugMode: false,
        verboseLogging: false,
        cacheEnabled: true,
        cacheSize: '500',
        parallelProcessing: true
      });
      setErrors({});
      setSaveStatus({ type: 'info', message: 'Settings reset to defaults' });
    }
  };

  const tabs = [
    { id: 'general', label: 'General', icon: '⚙️' },
    { id: 'notifications', label: 'Notifications', icon: '🔔' },
    { id: 'security', label: 'Security', icon: '🔒' },
    { id: 'scanning', label: 'Scanning', icon: '🔍' },
    { id: 'api', label: 'API', icon: '🔌' },
    { id: 'advanced', label: 'Advanced', icon: '🛠️' }
  ];

  const renderFormField = (key, label, type = 'text', options = {}) => {
    const { placeholder, description, min, max, step } = options;
    const error = errors[key];
    
    return (
      <div className="form-field">
        <label htmlFor={key} className="field-label">
          {label}
          {description && <span className="field-description">{description}</span>}
        </label>
        
        {type === 'checkbox' ? (
          <div className="checkbox-wrapper">
            <input
              type="checkbox"
              id={key}
              checked={settings[key]}
              onChange={(e) => handleInputChange(key, e.target.checked)}
              className="checkbox-input"
            />
            <span className="checkbox-label">Enable {label.toLowerCase()}</span>
          </div>
        ) : type === 'select' ? (
          <select
            id={key}
            value={settings[key]}
            onChange={(e) => handleInputChange(key, e.target.value)}
            className={`select-input ${error ? 'error' : ''}`}
          >
            {options.options?.map(option => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        ) : type === 'textarea' ? (
          <textarea
            id={key}
            value={settings[key]}
            onChange={(e) => handleInputChange(key, e.target.value)}
            placeholder={placeholder}
            className={`textarea-input ${error ? 'error' : ''}`}
            rows={4}
          />
        ) : (
          <input
            type={type}
            id={key}
            value={settings[key]}
            onChange={(e) => handleInputChange(key, e.target.value)}
            placeholder={placeholder}
            min={min}
            max={max}
            step={step}
            className={`text-input ${error ? 'error' : ''}`}
          />
        )}
        
        {error && <span className="field-error">{error}</span>}
      </div>
    );
  };

  const renderGeneralTab = () => (
    <div className="tab-content">
      <h3>General Settings</h3>
      
      {renderFormField('autoScan', 'Auto Scan', 'checkbox', {
        description: 'Automatically scan for new threats'
      })}
      
      {renderFormField('scanInterval', 'Scan Interval (hours)', 'number', {
        placeholder: '24',
        description: 'How often to run automatic scans',
        min: 1,
        max: 168
      })}
      
      {renderFormField('maxConcurrentScans', 'Max Concurrent Scans', 'number', {
        placeholder: '3',
        description: 'Maximum number of scans to run simultaneously',
        min: 1,
        max: 10
      })}
      
      {renderFormField('retainLogs', 'Log Retention (days)', 'number', {
        placeholder: '30',
        description: 'How long to keep scan logs',
        min: 1,
        max: 365
      })}
    </div>
  );

  const renderNotificationsTab = () => (
    <div className="tab-content">
      <h3>Notification Settings</h3>
      
      {renderFormField('emailNotifications', 'Email Notifications', 'checkbox')}
      
      {settings.emailNotifications && (
        <>
          {renderFormField('emailAddress', 'Email Address', 'email', {
            placeholder: 'admin@company.com',
            description: 'Email address for notifications'
          })}
          
          {renderFormField('notificationThreshold', 'Notification Threshold', 'select', {
            description: 'Minimum severity level for notifications',
            options: [
              { value: 'low', label: 'Low and above' },
              { value: 'medium', label: 'Medium and above' },
              { value: 'high', label: 'High only' },
              { value: 'critical', label: 'Critical only' }
            ]
          })}
        </>
      )}
      
      {renderFormField('slackNotifications', 'Slack Notifications', 'checkbox')}
      
      {settings.slackNotifications && (
        renderFormField('slackWebhook', 'Slack Webhook URL', 'url', {
          placeholder: 'https://hooks.slack.com/services/...',
          description: 'Slack webhook URL for notifications'
        })
      )}
      
      {renderFormField('webhookNotifications', 'Custom Webhook', 'checkbox')}
      
      {settings.webhookNotifications && (
        renderFormField('customWebhook', 'Webhook URL', 'url', {
          placeholder: 'https://your-webhook-url.com/endpoint',
          description: 'Custom webhook URL for notifications'
        })
      )}
    </div>
  );

  const renderSecurityTab = () => (
    <div className="tab-content">
      <h3>Security Settings</h3>
      
      {renderFormField('apiKeyRotation', 'API Key Rotation (days)', 'number', {
        placeholder: '90',
        description: 'How often to rotate API keys',
        min: 1,
        max: 365
      })}
      
      {renderFormField('sessionTimeout', 'Session Timeout (minutes)', 'number', {
        placeholder: '60',
        description: 'User session timeout duration',
        min: 5,
        max: 480
      })}
      
      {renderFormField('twoFactorAuth', 'Two-Factor Authentication', 'checkbox', {
        description: 'Require 2FA for user authentication'
      })}
      
      {renderFormField('ipWhitelist', 'IP Whitelist', 'textarea', {
        placeholder: '192.168.1.0/24\n10.0.0.0/8',
        description: 'Allowed IP addresses (one per line)'
      })}
    </div>
  );

  const renderScanningTab = () => (
    <div className="tab-content">
      <h3>Scanning Settings</h3>
      
      {renderFormField('deepScan', 'Deep Scan', 'checkbox', {
        description: 'Perform thorough analysis of dependencies'
      })}
      
      {renderFormField('skipDevDependencies', 'Skip Dev Dependencies', 'checkbox', {
        description: 'Skip scanning development dependencies'
      })}
      
      {renderFormField('customRules', 'Custom Rules', 'textarea', {
        placeholder: 'rule1: pattern\nrule2: pattern',
        description: 'Custom scanning rules (one per line)'
      })}
      
      {renderFormField('excludePatterns', 'Exclude Patterns', 'textarea', {
        placeholder: '*.test.js\nnode_modules/*',
        description: 'File patterns to exclude from scanning'
      })}
      
      {renderFormField('includePatterns', 'Include Patterns', 'textarea', {
        placeholder: '*.js\n*.ts\n*.json',
        description: 'File patterns to include in scanning'
      })}
    </div>
  );

  const renderApiTab = () => (
    <div className="tab-content">
      <h3>API Settings</h3>
      
      {renderFormField('apiRateLimit', 'Rate Limit (requests/hour)', 'number', {
        placeholder: '1000',
        description: 'Maximum API requests per hour',
        min: 1,
        max: 10000
      })}
      
      {renderFormField('apiTimeout', 'Request Timeout (seconds)', 'number', {
        placeholder: '30',
        description: 'API request timeout duration',
        min: 5,
        max: 300
      })}
      
      {renderFormField('enableCors', 'Enable CORS', 'checkbox', {
        description: 'Allow cross-origin requests'
      })}
      
      {settings.enableCors && (
        renderFormField('corsOrigins', 'CORS Origins', 'text', {
          placeholder: '*',
          description: 'Allowed CORS origins (comma-separated)'
        })
      )}
    </div>
  );

  const renderAdvancedTab = () => (
    <div className="tab-content">
      <h3>Advanced Settings</h3>
      
      {renderFormField('debugMode', 'Debug Mode', 'checkbox', {
        description: 'Enable debug logging and features'
      })}
      
      {renderFormField('verboseLogging', 'Verbose Logging', 'checkbox', {
        description: 'Enable detailed logging output'
      })}
      
      {renderFormField('cacheEnabled', 'Enable Caching', 'checkbox', {
        description: 'Cache scan results for better performance'
      })}
      
      {settings.cacheEnabled && (
        renderFormField('cacheSize', 'Cache Size (MB)', 'number', {
          placeholder: '500',
          description: 'Maximum cache size in megabytes',
          min: 10,
          max: 5000
        })
      )}
      
      {renderFormField('parallelProcessing', 'Parallel Processing', 'checkbox', {
        description: 'Enable parallel processing for faster scans'
      })}
    </div>
  );

  const renderTabContent = () => {
    switch (activeTab) {
      case 'general': return renderGeneralTab();
      case 'notifications': return renderNotificationsTab();
      case 'security': return renderSecurityTab();
      case 'scanning': return renderScanningTab();
      case 'api': return renderApiTab();
      case 'advanced': return renderAdvancedTab();
      default: return renderGeneralTab();
    }
  };

  if (loading && !saveStatus) {
    return (
      <div className="settings loading">
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p>Loading settings...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="settings">
      <div className="settings-header">
        <h1>Settings</h1>
        <p>Configure TypoSentinel to match your security requirements</p>
      </div>

      <div className="settings-container">
        <div className="settings-sidebar">
          <nav className="settings-nav">
            {tabs.map(tab => (
              <button
                key={tab.id}
                className={`nav-item ${activeTab === tab.id ? 'active' : ''}`}
                onClick={() => setActiveTab(tab.id)}
              >
                <span className="nav-icon">{tab.icon}</span>
                <span className="nav-label">{tab.label}</span>
              </button>
            ))}
          </nav>
        </div>

        <div className="settings-main">
          <div className="settings-content">
            {renderTabContent()}
          </div>

          <div className="settings-actions">
            {saveStatus && (
              <div className={`status-message ${saveStatus.type}`}>
                {saveStatus.message}
              </div>
            )}
            
            <div className="action-buttons">
              <button
                className="btn btn-secondary"
                onClick={handleReset}
                disabled={loading}
              >
                Reset to Defaults
              </button>
              
              <button
                className="btn btn-primary"
                onClick={handleSave}
                disabled={loading}
              >
                {loading ? 'Saving...' : 'Save Settings'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;