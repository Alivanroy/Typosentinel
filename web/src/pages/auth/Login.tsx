import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  TextField,
  Button,
  Typography,
  Alert,
  Link,
  Divider,
  IconButton,
  InputAdornment,
  FormControlLabel,
  Checkbox,
  Grid,
  Paper,
} from '@mui/material';
import {
  Visibility,
  VisibilityOff,
  Google as GoogleIcon,
  GitHub as GitHubIcon,
  Microsoft as MicrosoftIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';

interface LoginForm {
  email: string;
  password: string;
  rememberMe: boolean;
}

const Login: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { login } = useAuth();
  const [form, setForm] = useState<LoginForm>({
    email: '',
    password: '',
    rememberMe: false,
  });
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Get the intended destination from location state
  const from = location.state?.from?.pathname || '/enterprise/dashboard';

  const handleInputChange = (field: keyof LoginForm) => (event: React.ChangeEvent<HTMLInputElement>) => {
    const value = field === 'rememberMe' ? event.target.checked : event.target.value;
    setForm(prev => ({ ...prev, [field]: value }));
    if (error) setError(null); // Clear error when user starts typing
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setLoading(true);
    setError(null);

    try {
      // Validate form
      if (!form.email || !form.password) {
        throw new Error('Please fill in all required fields');
      }

      if (!isValidEmail(form.email)) {
        throw new Error('Please enter a valid email address');
      }

      // Attempt login
      const success = await login(form.email, form.password, form.rememberMe);
      
      if (success) {
        // Redirect to intended destination
        navigate(from, { replace: true });
      } else {
        throw new Error('Invalid email or password');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const handleSocialLogin = async (provider: 'google' | 'github' | 'microsoft') => {
    setLoading(true);
    setError(null);

    try {
      // Mock social login - in real app, this would redirect to OAuth provider
      console.log(`Initiating ${provider} login...`);
      
      // Simulate OAuth flow
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Mock successful login
      const success = await login(`user@${provider}.com`, 'oauth-token', false);
      
      if (success) {
        navigate(from, { replace: true });
      } else {
        throw new Error(`${provider} login failed`);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : `${provider} login failed`);
    } finally {
      setLoading(false);
    }
  };

  const isValidEmail = (email: string): boolean => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };

  return (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
        p: 2,
      }}
    >
      <Grid container maxWidth="lg" sx={{ height: '100%' }}>
        {/* Left Panel - Branding */}
        <Grid
          item
          xs={12}
          md={6}
          sx={{
            display: { xs: 'none', md: 'flex' },
            flexDirection: 'column',
            justifyContent: 'center',
            alignItems: 'center',
            color: 'white',
            p: 4,
          }}
        >
          <Box sx={{ textAlign: 'center', maxWidth: 400 }}>
            <SecurityIcon sx={{ fontSize: 80, mb: 3, opacity: 0.9 }} />
            <Typography variant="h3" component="h1" gutterBottom sx={{ fontWeight: 'bold' }}>
              TypoSentinel
            </Typography>
            <Typography variant="h6" sx={{ mb: 4, opacity: 0.9 }}>
              Advanced Package Security & Supply Chain Protection
            </Typography>
            <Typography variant="body1" sx={{ opacity: 0.8, lineHeight: 1.6 }}>
              Protect your applications from typosquatting attacks, vulnerable dependencies, 
              and supply chain threats with our comprehensive security platform.
            </Typography>
          </Box>
        </Grid>

        {/* Right Panel - Login Form */}
        <Grid
          item
          xs={12}
          md={6}
          sx={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            p: 2,
          }}
        >
          <Card sx={{ width: '100%', maxWidth: 400, boxShadow: 3 }}>
            <CardContent sx={{ p: 4 }}>
              {/* Mobile Branding */}
              <Box sx={{ display: { xs: 'block', md: 'none' }, textAlign: 'center', mb: 3 }}>
                <SecurityIcon sx={{ fontSize: 48, color: 'primary.main', mb: 1 }} />
                <Typography variant="h5" component="h1" gutterBottom>
                  TypoSentinel
                </Typography>
              </Box>

              <Typography variant="h4" component="h1" gutterBottom sx={{ display: { xs: 'none', md: 'block' } }}>
                Welcome Back
              </Typography>
              <Typography variant="body2" color="textSecondary" gutterBottom sx={{ mb: 3 }}>
                Sign in to your account to continue
              </Typography>

              {error && (
                <Alert severity="error" sx={{ mb: 3 }}>
                  {error}
                </Alert>
              )}

              <form onSubmit={handleSubmit}>
                <TextField
                  fullWidth
                  label="Email Address"
                  type="email"
                  value={form.email}
                  onChange={handleInputChange('email')}
                  margin="normal"
                  required
                  autoComplete="email"
                  autoFocus
                  error={!!error && !form.email}
                />

                <TextField
                  fullWidth
                  label="Password"
                  type={showPassword ? 'text' : 'password'}
                  value={form.password}
                  onChange={handleInputChange('password')}
                  margin="normal"
                  required
                  autoComplete="current-password"
                  error={!!error && !form.password}
                  InputProps={{
                    endAdornment: (
                      <InputAdornment position="end">
                        <IconButton
                          onClick={() => setShowPassword(!showPassword)}
                          edge="end"
                          aria-label="toggle password visibility"
                        >
                          {showPassword ? <VisibilityOff /> : <Visibility />}
                        </IconButton>
                      </InputAdornment>
                    ),
                  }}
                />

                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mt: 2, mb: 3 }}>
                  <FormControlLabel
                    control={
                      <Checkbox
                        checked={form.rememberMe}
                        onChange={handleInputChange('rememberMe')}
                        color="primary"
                      />
                    }
                    label="Remember me"
                  />
                  <Link
                    href="#"
                    variant="body2"
                    onClick={(e) => {
                      e.preventDefault();
                      // Handle forgot password
                      console.log('Forgot password clicked');
                    }}
                  >
                    Forgot password?
                  </Link>
                </Box>

                <Button
                  type="submit"
                  fullWidth
                  variant="contained"
                  size="large"
                  disabled={loading}
                  sx={{ mb: 3 }}
                >
                  {loading ? 'Signing In...' : 'Sign In'}
                </Button>
              </form>

              <Divider sx={{ my: 3 }}>
                <Typography variant="body2" color="textSecondary">
                  Or continue with
                </Typography>
              </Divider>

              {/* Social Login Buttons */}
              <Grid container spacing={2}>
                <Grid item xs={4}>
                  <Button
                    fullWidth
                    variant="outlined"
                    onClick={() => handleSocialLogin('google')}
                    disabled={loading}
                    sx={{ py: 1.5 }}
                  >
                    <GoogleIcon sx={{ color: '#4285f4' }} />
                  </Button>
                </Grid>
                <Grid item xs={4}>
                  <Button
                    fullWidth
                    variant="outlined"
                    onClick={() => handleSocialLogin('github')}
                    disabled={loading}
                    sx={{ py: 1.5 }}
                  >
                    <GitHubIcon sx={{ color: '#333' }} />
                  </Button>
                </Grid>
                <Grid item xs={4}>
                  <Button
                    fullWidth
                    variant="outlined"
                    onClick={() => handleSocialLogin('microsoft')}
                    disabled={loading}
                    sx={{ py: 1.5 }}
                  >
                    <MicrosoftIcon sx={{ color: '#00a1f1' }} />
                  </Button>
                </Grid>
              </Grid>

              <Box sx={{ textAlign: 'center', mt: 3 }}>
                <Typography variant="body2" color="textSecondary">
                  Don't have an account?{' '}
                  <Link
                    href="#"
                    onClick={(e) => {
                      e.preventDefault();
                      // Handle sign up
                      console.log('Sign up clicked');
                    }}
                  >
                    Sign up
                  </Link>
                </Typography>
              </Box>

              {/* Demo Credentials */}
              <Paper sx={{ mt: 3, p: 2, bgcolor: 'grey.50' }}>
                <Typography variant="caption" color="textSecondary" gutterBottom display="block">
                  Demo Credentials:
                </Typography>
                <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                  Email: admin@typosentinel.com<br />
                  Password: demo123
                </Typography>
              </Paper>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Login;