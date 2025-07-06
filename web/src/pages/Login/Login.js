import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useDispatch, useSelector } from 'react-redux';
import { setAuthenticated } from '../../store/slices/authSlice';
import './Login.css';

const Login = () => {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    rememberMe: false
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const location = useLocation();
  const { isAuthenticated } = useSelector(state => state.auth);
  
  // Get the intended destination or default to dashboard
  const from = location.state?.from?.pathname || '/dashboard';

  useEffect(() => {
    // Check if user is already logged in
    const token = localStorage.getItem('typosentinel-token');
    if (token || isAuthenticated) {
      dispatch(setAuthenticated(true));
      navigate(from, { replace: true });
    }
  }, [navigate, from, isAuthenticated, dispatch]);

  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
    
    // Clear error when user starts typing
    if (error) {
      setError('');
    }
  };

  const validateForm = () => {
    if (!formData.email) {
      setError('Email is required');
      return false;
    }
    
    if (!formData.password) {
      setError('Password is required');
      return false;
    }
    
    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(formData.email)) {
      setError('Please enter a valid email address');
      return false;
    }
    
    return true;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }
    
    setLoading(true);
    setError('');
    
    try {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      // Mock authentication - in a real app, this would call an API
      if (formData.email === 'admin@typosentinel.com' && formData.password === 'admin123') {
        // Generate a mock token
        const token = 'mock-jwt-token-' + Date.now();
        
        // Store token and user info
        localStorage.setItem('typosentinel-token', token);
        localStorage.setItem('typosentinel-user', JSON.stringify({
          id: 1,
          email: formData.email,
          name: 'Admin User',
          role: 'admin'
        }));
        
        // Remember me functionality
        if (formData.rememberMe) {
          localStorage.setItem('typosentinel-remember', 'true');
        }
        
        // Update Redux auth state
        dispatch(setAuthenticated(true));
        
        // Redirect to intended destination
        navigate(from, { replace: true });
      } else {
        setError('Invalid email or password');
      }
    } catch (err) {
      setError('Login failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleForgotPassword = () => {
    // In a real app, this would trigger a password reset flow
    alert('Password reset functionality would be implemented here');
  };

  const handleDemoLogin = async () => {
    setFormData({
      email: 'admin@typosentinel.com',
      password: 'admin123',
      rememberMe: false
    });
    
    // Auto-submit after a short delay
    setTimeout(() => {
      document.getElementById('login-form').requestSubmit();
    }, 500);
  };

  return (
    <div className="login-page">
      <div className="login-container">
        <div className="login-header">
          <div className="logo">
            <span className="logo-icon">🛡️</span>
            <span className="logo-text">TypoSentinel</span>
          </div>
          <h1>Welcome Back</h1>
          <p>Sign in to your account to continue</p>
        </div>

        <form id="login-form" className="login-form" onSubmit={handleSubmit}>
          {error && (
            <div className="error-message">
              <span className="error-icon">⚠️</span>
              {error}
            </div>
          )}

          <div className="form-group">
            <label htmlFor="email" className="form-label">
              Email Address
            </label>
            <input
              type="email"
              id="email"
              name="email"
              value={formData.email}
              onChange={handleInputChange}
              className="form-input"
              placeholder="Enter your email"
              required
              autoComplete="email"
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <label htmlFor="password" className="form-label">
              Password
            </label>
            <div className="password-input-wrapper">
              <input
                type={showPassword ? 'text' : 'password'}
                id="password"
                name="password"
                value={formData.password}
                onChange={handleInputChange}
                className="form-input"
                placeholder="Enter your password"
                required
                autoComplete="current-password"
                disabled={loading}
              />
              <button
                type="button"
                className="password-toggle"
                onClick={() => setShowPassword(!showPassword)}
                disabled={loading}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? '👁️' : '👁️‍🗨️'}
              </button>
            </div>
          </div>

          <div className="form-options">
            <label className="checkbox-label">
              <input
                type="checkbox"
                name="rememberMe"
                checked={formData.rememberMe}
                onChange={handleInputChange}
                disabled={loading}
              />
              <span className="checkbox-text">Remember me</span>
            </label>
            
            <button
              type="button"
              className="forgot-password-link"
              onClick={handleForgotPassword}
              disabled={loading}
            >
              Forgot password?
            </button>
          </div>

          <button
            type="submit"
            className="login-button"
            disabled={loading}
          >
            {loading ? (
              <>
                <span className="loading-spinner"></span>
                Signing in...
              </>
            ) : (
              'Sign In'
            )}
          </button>
        </form>

        <div className="login-footer">
          <div className="demo-section">
            <p className="demo-text">Try the demo:</p>
            <button
              type="button"
              className="demo-button"
              onClick={handleDemoLogin}
              disabled={loading}
            >
              Demo Login
            </button>
          </div>
          
          <div className="demo-credentials">
            <p className="credentials-title">Demo Credentials:</p>
            <div className="credentials">
              <div className="credential-item">
                <span className="credential-label">Email:</span>
                <code>admin@typosentinel.com</code>
              </div>
              <div className="credential-item">
                <span className="credential-label">Password:</span>
                <code>admin123</code>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="login-background">
        <div className="background-pattern"></div>
        <div className="floating-elements">
          <div className="floating-element element-1">🔒</div>
          <div className="floating-element element-2">🛡️</div>
          <div className="floating-element element-3">🔍</div>
          <div className="floating-element element-4">⚡</div>
          <div className="floating-element element-5">🚀</div>
          <div className="floating-element element-6">💎</div>
        </div>
      </div>
    </div>
  );
};

export default Login;