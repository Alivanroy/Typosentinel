import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import { styled, useTheme } from '@mui/material/styles';
import {
  Box,
  Drawer,
  AppBar,
  Toolbar,
  List,
  Typography,
  Divider,
  IconButton,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Avatar,
  Menu,
  MenuItem,
  Tooltip,
  Badge,
  useMediaQuery,
} from '@mui/material';
import {
  Menu as MenuIcon,
  ChevronLeft as ChevronLeftIcon,
  Dashboard as DashboardIcon,
  Security as SecurityIcon,
  AccountTree as AccountTreeIcon,
  Policy as PolicyIcon,
  Code as CodeIcon,
  Terminal as TerminalIcon,
  Notifications as NotificationsIcon,
  Settings as SettingsIcon,
  Brightness4 as DarkModeIcon,
  Brightness7 as LightModeIcon,
  Logout as LogoutIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { useSocket } from '../../contexts/SocketContext';

const drawerWidth = 280;

const Main = styled('main', { shouldForwardProp: (prop) => prop !== 'open' })(
  ({ theme, open }: { theme: any; open: boolean }) => ({
    flexGrow: 1,
    padding: theme.spacing(3),
    transition: theme.transitions.create('margin', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.leavingScreen,
    }),
    marginLeft: 0,
    ...(open && {
      transition: theme.transitions.create('margin', {
        easing: theme.transitions.easing.easeOut,
        duration: theme.transitions.duration.enteringScreen,
      }),
      marginLeft: drawerWidth,
    }),
  }),
);

const AppBarStyled = styled(AppBar, { shouldForwardProp: (prop) => prop !== 'open' })(
  ({ theme, open }: { theme: any; open: boolean }) => ({
    transition: theme.transitions.create(['margin', 'width'], {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.leavingScreen,
    }),
    ...(open && {
      width: `calc(100% - ${drawerWidth}px)`,
      marginLeft: `${drawerWidth}px`,
      transition: theme.transitions.create(['margin', 'width'], {
        easing: theme.transitions.easing.easeOut,
        duration: theme.transitions.duration.enteringScreen,
      }),
    }),
  }),
);

const DrawerHeader = styled('div')(({ theme }) => ({
  display: 'flex',
  alignItems: 'center',
  padding: theme.spacing(0, 1),
  ...theme.mixins.toolbar,
  justifyContent: 'space-between',
}));

const Logo = styled(Box)(({ theme }) => ({
  display: 'flex',
  alignItems: 'center',
  padding: theme.spacing(0, 2),
}));

const LogoIcon = styled(Box)(({ theme }) => ({
  width: 36,
  height: 36,
  backgroundColor: theme.palette.primary.main,
  borderRadius: 8,
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  marginRight: theme.spacing(2),
}));

const EnterpriseLayout: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const { scanEvents } = useSocket();
  const [open, setOpen] = useState(true);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [notificationsAnchorEl, setNotificationsAnchorEl] = useState<null | HTMLElement>(null);
  const isMobile = useMediaQuery(theme.breakpoints.down('lg'));

  // Close drawer on mobile by default
  React.useEffect(() => {
    if (isMobile) {
      setOpen(false);
    } else {
      setOpen(true);
    }
  }, [isMobile]);

  const handleDrawerOpen = () => {
    setOpen(true);
  };

  const handleDrawerClose = () => {
    setOpen(false);
  };

  const handleProfileMenuOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleProfileMenuClose = () => {
    setAnchorEl(null);
  };

  const handleNotificationsOpen = (event: React.MouseEvent<HTMLElement>) => {
    setNotificationsAnchorEl(event.currentTarget);
  };

  const handleNotificationsClose = () => {
    setNotificationsAnchorEl(null);
  };

  const handleLogout = async () => {
    handleProfileMenuClose();
    await logout();
    navigate('/login');
  };

  // Count unread notifications
  const unreadNotifications = scanEvents.filter(event => 
    event.status === 'completed' || event.status === 'error'
  ).length;

  const navigationItems = [
    {
      text: 'Executive Dashboard',
      icon: <DashboardIcon />,
      path: '/enterprise/dashboard',
    },
    {
      text: 'Vulnerability Management',
      icon: <SecurityIcon />,
      path: '/enterprise/vulnerabilities',
    },
    {
      text: 'Supply Chain View',
      icon: <AccountTreeIcon />,
      path: '/enterprise/supply-chain',
    },
    {
      text: 'Policy Management',
      icon: <PolicyIcon />,
      path: '/enterprise/policies',
    },
    {
      text: 'Policy Editor',
      icon: <CodeIcon />,
      path: '/enterprise/policies/editor',
      indent: true,
    },
    {
      text: 'Policy Playground',
      icon: <CodeIcon />,
      path: '/enterprise/policies/playground',
      indent: true,
    },
    {
      text: 'CLI Integration',
      icon: <TerminalIcon />,
      path: '/integration/cli',
    },
    {
      text: 'VSCode Extension',
      icon: <CodeIcon />,
      path: '/integration/vscode',
    },
  ];

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh' }}>
      <AppBarStyled position="fixed" open={open} elevation={1} color="default">
        <Toolbar>
          <IconButton
            color="inherit"
            aria-label="open drawer"
            onClick={handleDrawerOpen}
            edge="start"
            sx={{ mr: 2, ...(open && { display: 'none' }) }}
          >
            <MenuIcon />
          </IconButton>
          
          <Typography variant="h6" noWrap component="div" sx={{ flexGrow: 1 }}>
            TypoSentinel Enterprise
          </Typography>
          
          <Box sx={{ display: 'flex', alignItems: 'center' }}>
            {/* Theme toggle button */}
            <Tooltip title="Toggle theme">
              <IconButton color="inherit">
                {theme.palette.mode === 'dark' ? <LightModeIcon /> : <DarkModeIcon />}
              </IconButton>
            </Tooltip>
            
            {/* Notifications */}
            <Tooltip title="Notifications">
              <IconButton 
                color="inherit" 
                onClick={handleNotificationsOpen}
              >
                <Badge badgeContent={unreadNotifications} color="error">
                  <NotificationsIcon />
                </Badge>
              </IconButton>
            </Tooltip>
            
            {/* Settings */}
            <Tooltip title="Settings">
              <IconButton color="inherit" onClick={() => navigate('/enterprise/settings')}>
                <SettingsIcon />
              </IconButton>
            </Tooltip>
            
            {/* User profile */}
            <Tooltip title={user?.name || 'User'}>
              <IconButton
                onClick={handleProfileMenuOpen}
                size="small"
                sx={{ ml: 2 }}
                aria-controls={Boolean(anchorEl) ? 'account-menu' : undefined}
                aria-haspopup="true"
                aria-expanded={Boolean(anchorEl) ? 'true' : undefined}
              >
                <Avatar sx={{ width: 32, height: 32, bgcolor: 'primary.main' }}>
                  {user?.name?.charAt(0).toUpperCase() || 'U'}
                </Avatar>
              </IconButton>
            </Tooltip>
          </Box>
        </Toolbar>
      </AppBarStyled>
      
      {/* Profile menu */}
      <Menu
        anchorEl={anchorEl}
        id="account-menu"
        open={Boolean(anchorEl)}
        onClose={handleProfileMenuClose}
        transformOrigin={{ horizontal: 'right', vertical: 'top' }}
        anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
      >
        <MenuItem onClick={() => {
          handleProfileMenuClose();
          navigate('/enterprise/profile');
        }}>
          <Avatar sx={{ width: 24, height: 24, mr: 1, bgcolor: 'primary.main' }} />
          My Profile
        </MenuItem>
        <Divider />
        <MenuItem onClick={handleLogout}>
          <ListItemIcon>
            <LogoutIcon fontSize="small" />
          </ListItemIcon>
          Logout
        </MenuItem>
      </Menu>
      
      {/* Notifications menu */}
      <Menu
        anchorEl={notificationsAnchorEl}
        id="notifications-menu"
        open={Boolean(notificationsAnchorEl)}
        onClose={handleNotificationsClose}
        transformOrigin={{ horizontal: 'right', vertical: 'top' }}
        anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
        PaperProps={{
          sx: { width: 320, maxHeight: 500, overflow: 'auto' },
        }}
      >
        <MenuItem sx={{ justifyContent: 'space-between' }}>
          <Typography variant="subtitle1" fontWeight={600}>Notifications</Typography>
          <Typography 
            variant="body2" 
            color="primary" 
            sx={{ cursor: 'pointer' }}
            onClick={() => {
              handleNotificationsClose();
              // Handle mark all as read
            }}
          >
            Mark all as read
          </Typography>
        </MenuItem>
        <Divider />
        
        {scanEvents.length === 0 ? (
          <MenuItem>
            <Typography variant="body2" color="text.secondary">
              No notifications
            </Typography>
          </MenuItem>
        ) : (
          scanEvents.slice(0, 5).map((event) => (
            <MenuItem 
              key={`${event.id}-${event.timestamp.toISOString()}`}
              onClick={() => {
                handleNotificationsClose();
                navigate(`/integration/results/${event.id}`);
              }}
              sx={{ py: 1 }}
            >
              <Box sx={{ width: '100%' }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                  <Typography variant="subtitle2">
                    {event.type === 'cli' ? 'CLI Scan' : 'VSCode Scan'}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {new Date(event.timestamp).toLocaleTimeString()}
                  </Typography>
                </Box>
                <Typography variant="body2" color="text.secondary" noWrap>
                  {event.status === 'started' && 'Scan started'}
                  {event.status === 'progress' && `Progress: ${event.data.progress || 0}%`}
                  {event.status === 'completed' && 'Scan completed'}
                  {event.status === 'error' && `Error: ${event.data.error || 'Unknown error'}`}
                </Typography>
                <Box 
                  sx={{ 
                    mt: 0.5,
                    height: 4, 
                    width: '100%', 
                    bgcolor: 'background.paper',
                    borderRadius: 1,
                    overflow: 'hidden',
                  }}
                >
                  <Box 
                    sx={{ 
                      height: '100%', 
                      width: `${event.status === 'completed' ? 100 : event.data.progress || 0}%`,
                      bgcolor: event.status === 'error' ? 'error.main' : 
                              event.status === 'completed' ? 'success.main' : 'primary.main',
                    }}
                  />
                </Box>
              </Box>
            </MenuItem>
          ))
        )}
        
        {scanEvents.length > 5 && (
          <MenuItem onClick={() => {
            handleNotificationsClose();
            navigate('/enterprise/notifications');
          }}>
            <Typography variant="body2" color="primary" sx={{ width: '100%', textAlign: 'center' }}>
              View all notifications
            </Typography>
          </MenuItem>
        )}
      </Menu>
      
      <Drawer
        sx={{
          width: drawerWidth,
          flexShrink: 0,
          '& .MuiDrawer-paper': {
            width: drawerWidth,
            boxSizing: 'border-box',
          },
        }}
        variant={isMobile ? 'temporary' : 'persistent'}
        anchor="left"
        open={open}
        onClose={handleDrawerClose}
      >
        <DrawerHeader>
          <Logo>
            <LogoIcon>
              <svg 
                width="20" 
                height="20" 
                viewBox="0 0 24 24" 
                fill="none" 
                stroke="white" 
                strokeWidth="2"
              >
                <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </LogoIcon>
            <Typography variant="h6" noWrap component="div">
              TypoSentinel
            </Typography>
          </Logo>
          <IconButton onClick={handleDrawerClose}>
            <ChevronLeftIcon />
          </IconButton>
        </DrawerHeader>
        
        <Divider />
        
        <List>
          {navigationItems.map((item) => (
            <ListItem key={item.path} disablePadding>
              <ListItemButton
                onClick={() => {
                  navigate(item.path);
                  if (isMobile) {
                    handleDrawerClose();
                  }
                }}
                sx={{
                  pl: item.indent ? 4 : 2,
                  py: 1,
                  '&.Mui-selected': {
                    bgcolor: 'primary.light',
                    '&:hover': {
                      bgcolor: 'primary.light',
                    },
                  },
                }}
                selected={window.location.pathname === item.path}
              >
                <ListItemIcon>
                  {item.icon}
                </ListItemIcon>
                <ListItemText primary={item.text} />
              </ListItemButton>
            </ListItem>
          ))}
        </List>
        
        <Box sx={{ flexGrow: 1 }} />
        
        <Divider />
        
        <Box sx={{ p: 2 }}>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
            TypoSentinel Enterprise v2.0.0
          </Typography>
          <Typography variant="caption" color="text.secondary">
            © 2025 TypoSentinel Inc.
          </Typography>
        </Box>
      </Drawer>
      
      <Main open={open}>
        <DrawerHeader />
        <Outlet />
      </Main>
    </Box>
  );
};

export default EnterpriseLayout;