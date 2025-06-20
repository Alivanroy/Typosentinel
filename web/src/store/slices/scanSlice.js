import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import api from '../../services/api';

// Async thunks
export const startScan = createAsyncThunk(
  'scan/startScan',
  async (scanConfig, { rejectWithValue }) => {
    try {
      const response = await api.post('/scan/start', scanConfig);
      return response.data;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || 'Failed to start scan'
      );
    }
  }
);

export const getScanResults = createAsyncThunk(
  'scan/getScanResults',
  async ({ page = 1, limit = 20, filters = {} }, { rejectWithValue }) => {
    try {
      const params = new URLSearchParams({
        page: page.toString(),
        limit: limit.toString(),
        ...filters,
      });
      const response = await api.get(`/scan/results?${params}`);
      return response.data;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || 'Failed to fetch scan results'
      );
    }
  }
);

export const getScanById = createAsyncThunk(
  'scan/getScanById',
  async (scanId, { rejectWithValue }) => {
    try {
      const response = await api.get(`/scan/${scanId}`);
      return response.data;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || 'Failed to fetch scan details'
      );
    }
  }
);

export const deleteScan = createAsyncThunk(
  'scan/deleteScan',
  async (scanId, { rejectWithValue }) => {
    try {
      await api.delete(`/scan/${scanId}`);
      return scanId;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || 'Failed to delete scan'
      );
    }
  }
);

const initialState = {
  scans: [],
  currentScan: null,
  scanResults: {
    data: [],
    pagination: {
      page: 1,
      limit: 20,
      total: 0,
      totalPages: 0,
    },
  },
  loading: false,
  scanInProgress: false,
  error: null,
  filters: {
    severity: '',
    status: '',
    dateRange: '',
  },
};

const scanSlice = createSlice({
  name: 'scan',
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
        dateRange: '',
      };
    },
    setScanInProgress: (state, action) => {
      state.scanInProgress = action.payload;
    },
  },
  extraReducers: (builder) => {
    builder
      // Start scan
      .addCase(startScan.pending, (state) => {
        state.loading = true;
        state.scanInProgress = true;
        state.error = null;
      })
      .addCase(startScan.fulfilled, (state, action) => {
        state.loading = false;
        state.currentScan = action.payload;
        state.error = null;
      })
      .addCase(startScan.rejected, (state, action) => {
        state.loading = false;
        state.scanInProgress = false;
        state.error = action.payload;
      })
      // Get scan results
      .addCase(getScanResults.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(getScanResults.fulfilled, (state, action) => {
        state.loading = false;
        state.scanResults = action.payload;
        state.error = null;
      })
      .addCase(getScanResults.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })
      // Get scan by ID
      .addCase(getScanById.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(getScanById.fulfilled, (state, action) => {
        state.loading = false;
        state.currentScan = action.payload;
        state.error = null;
      })
      .addCase(getScanById.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })
      // Delete scan
      .addCase(deleteScan.fulfilled, (state, action) => {
        state.scanResults.data = state.scanResults.data.filter(
          scan => scan.id !== action.payload
        );
      });
  },
});

export const { clearError, setFilters, clearFilters, setScanInProgress } = scanSlice.actions;
export default scanSlice.reducer;