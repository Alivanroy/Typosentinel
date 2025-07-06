import React, { useState } from 'react';
import './ScanModal.css';

const ScanModal = ({ isOpen, onClose, onStartScan }) => {
  const [scanConfig, setScanConfig] = useState({
    packageName: '',
    scanType: 'vulnerability',
    options: {
      deepScan: true,
      checkDependencies: true,
      checkTyposquatting: true,
      validateIntegrity: true
    }
  });
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleInputChange = (field, value) => {
    setScanConfig(prev => ({
      ...prev,
      [field]: value
    }));
  };

  const handleOptionChange = (option, value) => {
    setScanConfig(prev => ({
      ...prev,
      options: {
        ...prev.options,
        [option]: value
      }
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!scanConfig.packageName.trim()) {
      alert('Please enter a package name');
      return;
    }

    setIsSubmitting(true);
    try {
      await onStartScan(scanConfig);
    } catch (error) {
      console.error('Failed to start scan:', error);
      alert('Failed to start scan. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleQuickScan = (packageName) => {
    setScanConfig(prev => ({
      ...prev,
      packageName
    }));
  };

  const popularPackages = [
    'express',
    'react',
    'lodash',
    'axios',
    'moment',
    'chalk',
    'commander',
    'debug'
  ];

  if (!isOpen) return null;

  return (
    <div className="scan-modal-overlay">
      <div className="scan-modal">
        <div className="scan-modal-header">
          <h2>Start New Scan</h2>
          <button className="close-btn" onClick={onClose}>
            ×
          </button>
        </div>

        <form onSubmit={handleSubmit} className="scan-form">
          <div className="form-group">
            <label htmlFor="packageName">Package Name</label>
            <input
              id="packageName"
              type="text"
              value={scanConfig.packageName}
              onChange={(e) => handleInputChange('packageName', e.target.value)}
              placeholder="e.g., express, react, lodash"
              className="form-input"
              required
            />
            <div className="input-help">
              Enter the name of the npm package you want to scan
            </div>
          </div>

          <div className="form-group">
            <label htmlFor="scanType">Scan Type</label>
            <select
              id="scanType"
              value={scanConfig.scanType}
              onChange={(e) => handleInputChange('scanType', e.target.value)}
              className="form-select"
            >
              <option value="vulnerability">Vulnerability Scan</option>
              <option value="typosquatting">Typosquatting Detection</option>
              <option value="integrity">Package Integrity Check</option>
              <option value="comprehensive">Comprehensive Scan</option>
            </select>
          </div>

          <div className="form-group">
            <label>Scan Options</label>
            <div className="checkbox-group">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={scanConfig.options.deepScan}
                  onChange={(e) => handleOptionChange('deepScan', e.target.checked)}
                />
                <span className="checkbox-text">
                  Deep Scan
                  <small>Perform thorough analysis of package contents</small>
                </span>
              </label>

              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={scanConfig.options.checkDependencies}
                  onChange={(e) => handleOptionChange('checkDependencies', e.target.checked)}
                />
                <span className="checkbox-text">
                  Check Dependencies
                  <small>Scan all package dependencies for vulnerabilities</small>
                </span>
              </label>

              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={scanConfig.options.checkTyposquatting}
                  onChange={(e) => handleOptionChange('checkTyposquatting', e.target.checked)}
                />
                <span className="checkbox-text">
                  Typosquatting Detection
                  <small>Check for similar package names that might be malicious</small>
                </span>
              </label>

              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={scanConfig.options.validateIntegrity}
                  onChange={(e) => handleOptionChange('validateIntegrity', e.target.checked)}
                />
                <span className="checkbox-text">
                  Validate Integrity
                  <small>Verify package authenticity and detect tampering</small>
                </span>
              </label>
            </div>
          </div>

          <div className="form-group">
            <label>Quick Select Popular Packages</label>
            <div className="quick-select">
              {popularPackages.map(pkg => (
                <button
                  key={pkg}
                  type="button"
                  className="quick-select-btn"
                  onClick={() => handleQuickScan(pkg)}
                >
                  {pkg}
                </button>
              ))}
            </div>
          </div>

          <div className="form-actions">
            <button
              type="button"
              className="btn-secondary"
              onClick={onClose}
              disabled={isSubmitting}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn-primary"
              disabled={isSubmitting || !scanConfig.packageName.trim()}
            >
              {isSubmitting ? (
                <>
                  <span className="spinner"></span>
                  Starting Scan...
                </>
              ) : (
                'Start Scan'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default ScanModal;