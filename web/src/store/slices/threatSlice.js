import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import api from '../../services/api';

// Async thunks
export const getThreatAnalysis = createAsyncThunk(
  'threat/getThreatAnalysis',
  async ({ page = 1, limit = 20, filters = {} }, { rejectWithValue }) => {
    try {
      const params = new URLSearchParams({
        page: page.toString(),
        limit: limit.toString(),
        ...filters,
      });
      const response = await api.get(`/threats/analysis?${params}`);
      return response.data;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || 'Failed to fetch threat analysis'
      );
    }
  }
);

export const getThreatById = createAsyncThunk(
  'threat/getThreatById',
  async (threatId, { rejectWithValue }) => {
    try {
      const response = await api.get(`/threats/${threatId}`);
      return response.data;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || 'Failed to fetch threat details'
      );
    }
  }
);

export const updateThreatStatus = createAsyncThunk(
  'threat/updateThreatStatus',
  async ({ threatId, status, notes }, { rejectWithValue }) => {
    try {
      const response = await api.patch(`/threats/${threatId}/status`, {
        status,
        notes,
      });
      return response.data;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || 'Failed to update threat status'
      );
    }
  }
);

export const getThreatStats = createAsyncThunk(
  'threat/getThreatStats',
  async (timeRange = '7d', { rejectWithValue }) => {
    try {
      const response = await api.get(`/threats/stats?timeRange=${timeRange}`);
      return response.data;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || 'Failed to fetch threat statistics'
      );
    }
  }
);

export const exportThreats = createAsyncThunk(
  'threat/exportThreats',
  async ({ format = 'csv', filters = {} }, { rejectWithValue }) => {
    try {
      const params = new URLSearchParams({
        format,
        ...filters,
      });
      const response = await api.get(`/threats/export?${params}`, {
        responseType: 'blob',
      });
      return response.data;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || 'Failed to export threats'
      );
    }
  }
);

const initialState = {
  threats: [],
  currentThreat: null,
  threatAnalysis: {
    data: [],
    pagination: {
      page: 1,
      limit: 20,
      total: 0,
      totalPages: 0,
    },
  },
  threatStats: {
    totalThreats: 0,
    criticalThreats: 0,
    highThreats: 0,
    mediumThreats: 0,
    lowThreats: 0,
    resolvedThreats: 0,
    trendData: [],
  },
  loading: false,
  statsLoading: false,
  exportLoading: false,
  error: null,
  filters: {
    severity: '',
    status: '',
    type: '',
    dateRange: '',
  },
};

const threatSlice = createSlice({
  name: 'threat',
  initialState,
  reducers: {
    clearError: (state) => {
      state.error = null;
    },
    setFilters: (state, action) => {
      state.filters = { ...state.filters, ...action.payload };
    },
    clearFilters: (state) => {
      state.filters = {
        severity: '',
        status: '',
        type: '',
        dateRange: '',
      };
    },
    updateThreatInList: (state, action) => {
      const { threatId, updates } = action.payload;
      const threatIndex = state.threatAnalysis.data.findIndex(
        threat => threat.id === threatId
      );
      if (threatIndex !== -1) {
        state.threatAnalysis.data[threatIndex] = {
          ...state.threatAnalysis.data[threatIndex],
          ...updates,
        };
      }
    },
  },
  extraReducers: (builder) => {
    builder
      // Get threat analysis
      .addCase(getThreatAnalysis.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(getThreatAnalysis.fulfilled, (state, action) => {
        state.loading = false;
        state.threatAnalysis = action.payload;
        state.error = null;
      })
      .addCase(getThreatAnalysis.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })
      // Get threat by ID
      .addCase(getThreatById.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(getThreatById.fulfilled, (state, action) => {
        state.loading = false;
        state.currentThreat = action.payload;
        state.error = null;
      })
      .addCase(getThreatById.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })
      // Update threat status
      .addCase(updateThreatStatus.fulfilled, (state, action) => {
        const updatedThreat = action.payload;
        if (state.currentThreat && state.currentThreat.id === updatedThreat.id) {
          state.currentThreat = updatedThreat;
        }
        // Update in the list as well
        const threatIndex = state.threatAnalysis.data.findIndex(
          threat => threat.id === updatedThreat.id
        );
        if (threatIndex !== -1) {
          state.threatAnalysis.data[threatIndex] = updatedThreat;
        }
      })
      // Get threat stats
      .addCase(getThreatStats.pending, (state) => {
        state.statsLoading = true;
      })
      .addCase(getThreatStats.fulfilled, (state, action) => {
        state.statsLoading = false;
        state.threatStats = action.payload;
      })
      .addCase(getThreatStats.rejected, (state, action) => {
        state.statsLoading = false;
        state.error = action.payload;
      })
      // Export threats
      .addCase(exportThreats.pending, (state) => {
        state.exportLoading = true;
      })
      .addCase(exportThreats.fulfilled, (state) => {
        state.exportLoading = false;
      })
      .addCase(exportThreats.rejected, (state, action) => {
        state.exportLoading = false;
        state.error = action.payload;
      });
  },
});

export const { clearError, setFilters, clearFilters, updateThreatInList } = threatSlice.actions;
export default threatSlice.reducer;