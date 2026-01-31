/**
 * Authentication API Service
 */

import { apiClient } from './client';
import { API_ENDPOINTS } from './config';

export interface User {
  id: string;
  email: string;
  username: string;
  full_name: string;
  role: 'admin' | 'analyst' | 'viewer';
  is_active: boolean;
  created_at: string;
}

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface RegisterData {
  email: string;
  username: string;
  password: string;
  full_name: string;
}

export const authApi = {
  /**
   * Login with email and password
   */
  login: async (email: string, password: string): Promise<LoginResponse> => {
    return apiClient.login(email, password);
  },

  /**
   * Register a new user
   */
  register: async (data: RegisterData): Promise<User> => {
    return apiClient.register(data) as Promise<User>;
  },

  /**
   * Get current user profile
   */
  getMe: async (): Promise<User> => {
    return apiClient.get<User>(API_ENDPOINTS.auth.me);
  },

  /**
   * Logout (clears tokens)
   */
  logout: (): void => {
    apiClient.logout();
  },

  /**
   * Check if user is authenticated
   */
  isAuthenticated: (): boolean => {
    return apiClient.isAuthenticated();
  },
};

export default authApi;
