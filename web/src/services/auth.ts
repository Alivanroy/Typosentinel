import { api } from './api'
import type { User, LoginRequest, LoginResponse } from '@/types/auth'

class AuthService {
  async login(email: string, password: string): Promise<LoginResponse> {
    const response = await api.post<LoginResponse>('/auth/login', {
      email,
      password,
    })
    return response.data
  }

  async logout(): Promise<void> {
    await api.post('/auth/logout')
  }

  async getCurrentUser(): Promise<User> {
    const response = await api.get<User>('/auth/me')
    return response.data
  }

  async refreshToken(): Promise<{ token: string; expiresAt: string }> {
    const response = await api.post<{ token: string; expiresAt: string }>('/auth/refresh')
    return response.data
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    await api.post('/auth/change-password', {
      currentPassword,
      newPassword,
    })
  }

  async requestPasswordReset(email: string): Promise<void> {
    await api.post('/auth/forgot-password', { email })
  }

  async resetPassword(token: string, newPassword: string): Promise<void> {
    await api.post('/auth/reset-password', {
      token,
      newPassword,
    })
  }
}

export const authService = new AuthService()