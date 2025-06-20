import { configureStore } from '@reduxjs/toolkit';
import authReducer from './slices/authSlice';
import scanReducer from './slices/scanSlice';
import threatReducer from './slices/threatSlice';
import dashboardReducer from './slices/dashboardSlice';

export const store = configureStore({
  reducer: {
    auth: authReducer,
    scan: scanReducer,
    threat: threatReducer,
    dashboard: dashboardReducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        ignoredActions: ['persist/PERSIST'],
      },
    }),
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;