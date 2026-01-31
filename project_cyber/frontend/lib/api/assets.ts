/**
 * Assets API Service
 */

import { apiClient } from './client';
import { API_ENDPOINTS } from './config';

export interface Asset {
  id: string;
  name: string;
  asset_type: 'server' | 'workstation' | 'network_device' | 'database' | 'application' | 'cloud_service' | 'iot_device';
  criticality: 'critical' | 'high' | 'medium' | 'low';
  ip_address?: string;
  hostname?: string;
  department?: string;
  owner?: string;
  operating_system?: string;
  location?: string;
  status: 'active' | 'inactive' | 'decommissioned';
  vulnerabilities_count?: number;
  risk_score?: number;
  created_at: string;
  updated_at: string;
}

export interface AssetCreate {
  name: string;
  asset_type: string;
  criticality: string;
  ip_address?: string;
  hostname?: string;
  department?: string;
  owner?: string;
  operating_system?: string;
  location?: string;
}

export interface AssetUpdate {
  name?: string;
  criticality?: string;
  department?: string;
  owner?: string;
  operating_system?: string;
  location?: string;
  status?: string;
}

export interface AssetStats {
  total_assets: number;
  by_type: Record<string, number>;
  by_criticality: Record<string, number>;
  at_risk: number;
}

export const assetsApi = {
  /**
   * Get all assets with pagination
   */
  list: async (params?: {
    page?: number;
    page_size?: number;
    asset_type?: string;
    criticality?: string;
  }): Promise<Asset[]> => {
    const searchParams = new URLSearchParams();
    if (params?.page) searchParams.append('page', params.page.toString());
    if (params?.page_size) searchParams.append('page_size', params.page_size.toString());
    if (params?.asset_type) searchParams.append('asset_type', params.asset_type);
    if (params?.criticality) searchParams.append('criticality', params.criticality);
    
    const query = searchParams.toString();
    return apiClient.get<Asset[]>(`${API_ENDPOINTS.assets.list}${query ? `?${query}` : ''}`);
  },

  /**
   * Create a new asset
   */
  create: async (data: AssetCreate): Promise<Asset> => {
    return apiClient.post<Asset>(API_ENDPOINTS.assets.create, data);
  },

  /**
   * Get asset by ID
   */
  getById: async (id: string): Promise<Asset> => {
    return apiClient.get<Asset>(API_ENDPOINTS.assets.byId(id));
  },

  /**
   * Update an asset
   */
  update: async (id: string, data: AssetUpdate): Promise<Asset> => {
    return apiClient.put<Asset>(API_ENDPOINTS.assets.byId(id), data);
  },

  /**
   * Delete an asset
   */
  delete: async (id: string): Promise<void> => {
    return apiClient.delete(API_ENDPOINTS.assets.byId(id));
  },

  /**
   * Get asset statistics
   */
  getStats: async (): Promise<AssetStats> => {
    return apiClient.get<AssetStats>(API_ENDPOINTS.assets.stats);
  },
};

export default assetsApi;
