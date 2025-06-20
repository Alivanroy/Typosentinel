import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import api from '../../services/api';

// Async thunks
export const getDashboardMetrics = createAsyncThunk(
  'dashboard/getDashboardMetrics',
  async (timeRange = '7d', { rejectWithValue }) => {
    try {
      const response = await api.get(`/dashboard/metrics?timeRange=${timeRange}`);
      return response.data;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || 'Failed to fetch dashboard metrics'
      );
    }
  }
);

export const getRecentActivity = createAsyncThunk(
  'dashboard/getRecentActivity',
  async (limit = 10, { rejectWithValue }) => {
    try {
      const response = await api.get(`/dashboard/activity?limit=${limit}`);
      return response.data;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || 'Failed to fetch recent activity'
      );
    }
  }
);

export const getSystemHealth = createAsyncThunk(
  'dashboard/getSystemHealth',
  async (_, { rejectWithValue }) => {
    try {
      const response = await api.get('/dashboard/health');
      return response.data;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || 'Failed to fetch system health'
      );
    }
  }
);

export const getThreatTrends = createAsyncThunk(
  'dashboard/getThreatTrends',
  async (timeRange = '30d', { rejectWithValue }) => {
    try {
      const response = await api.get(`/dashboard/trends?timeRange=${timeRange}`);
      return response.data;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || 'Failed to fetch threat trends'
      );
    }
  }
);

const initialState = {
  metrics: {
    totalScans: 0,
    threatsDetected: 0,
    criticalThreats: 0,
    packagesScanned: 0,
    scanSuccessRate: 0,
    averageScanTime: 0,
  },
  recentActivity: [],
  systemHealth: {
    status: 'unknown',
    uptime: 0,
    memoryUsage: 0,
    cpuUsage: 0,
    diskUsage: 0,
    activeConnections: 0,
    lastUpdated: null,
  },
  threatTrends: {
    daily: [],
    weekly: [],
    monthly: [],
    severityDistribution: [],
    typeDistribution: [],
  },
  loading: {
    metrics: false,
    activity: false,
    health: false,
    trends: false,
  },
  error: null,
  selectedTimeRange: '7d',
  autoRefresh: true,
  refreshInterval: 30000, // 30 seconds
};

const dashboardSlice = createSlice({
  name: 'dashboard',
  initialState,
  reducers: {
    clearError: (state) => {
      state.error = null;
    },
    setSelectedTimeRange: (state, action) => {
      state.selectedTimeRange = action.payload;
    },
    setAutoRefresh: (state, action) => {
      state.autoRefresh = action.payload;
    },
    setRefreshInterval: (state, action) => {
      state.refreshInterval = action.payload;
    },
    updateSystemHealth: (state, action) => {
      state.systemHealth = { ...state.systemHealth, ...action.payload };
    },
  },
  extraReducers: (builder) => {
    builder
      // Get dashboard metrics
      .addCase(getDashboardMetrics.pending, (state) => {
        state.loading.metrics = true;
        state.error = null;
      })
      .addCase(getDashboardMetrics.fulfilled, (state, action) => {
        state.loading.metrics = false;
        state.metrics = action.payload;
        state.error = null;
      })
      .addCase(getDashboardMetrics.rejected, (state, action) => {
        state.loading.metrics = false;
        state.error = action.payload;
      })
      // Get recent activity
      .addCase(getRecentActivity.pending, (state) => {
        state.loading.activity = true;
      })
      .addCase(getRecentActivity.fulfilled, (state, action) => {
        state.loading.activity = false;
        state.recentActivity = action.payload;
      })
      .addCase(getRecentActivity.rejected, (state, action) => {
        state.loading.activity = false;
        state.error = action.payload;
      })
      // Get system health
      .addCase(getSystemHealth.pending, (state) => {
        state.loading.health = true;
      })
      .addCase(getSystemHealth.fulfilled, (state, action) => {
        state.loading.health = false;
        state.systemHealth = action.payload;
      })
      .addCase(getSystemHealth.rejected, (state, action) => {
        state.loading.health = false;
        state.error = action.payload;
      })
      // Get threat trends
      .addCase(getThreatTrends.pending, (state) => {
        state.loading.trends = true;
      })
      .addCase(getThreatTrends.fulfilled, (state, action) => {
        state.loading.trends = false;
        state.threatTrends = action.payload;
      })
      .addCase(getThreatTrends.rejected, (state, action) => {
        state.loading.trends = false;
        state.error = action.payload;
      });
  },
});

export const {
  clearError,
  setSelectedTimeRange,
  setAutoRefresh,
  setRefreshInterval,
  updateSystemHealth,
} = dashboardSlice.actions;

export default dashboardSlice.reducer;