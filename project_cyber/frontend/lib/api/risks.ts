/**
 * Risks API Service
 */

import { apiClient } from './client';
import { API_ENDPOINTS } from './config';

export interface Risk {
  id: string;
  name: string;
  description?: string;
  bwvs_score: number;
  priority_score: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'open' | 'mitigated' | 'accepted' | 'transferred';
  affected_assets_count: number;
  cve_ids?: string[];
  created_at: string;
  updated_at: string;
}

export interface TopRisksResponse {
  risks: Risk[];
  last_calculated: string;
  calculation_interval_minutes: number;
}

export interface RiskStats {
  total_risks: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  avg_bwvs: number;
  mitigated_count: number;
}

export const risksApi = {
  /**
   * Get top 10 prioritized risks
   */
  getTop10: async (): Promise<TopRisksResponse> => {
    return apiClient.get<TopRisksResponse>(API_ENDPOINTS.risks.top10);
  },

  /**
   * Get all risks with pagination and filtering
   */
  list: async (params?: {
    page?: number;
    page_size?: number;
    status?: string;
    min_bwvs?: number;
  }): Promise<Risk[]> => {
    const searchParams = new URLSearchParams();
    if (params?.page) searchParams.append('page', params.page.toString());
    if (params?.page_size) searchParams.append('page_size', params.page_size.toString());
    if (params?.status) searchParams.append('status', params.status);
    if (params?.min_bwvs) searchParams.append('min_bwvs', params.min_bwvs.toString());
    
    const query = searchParams.toString();
    return apiClient.get<Risk[]>(`${API_ENDPOINTS.risks.list}${query ? `?${query}` : ''}`);
  },

  /**
   * Get risk by ID
   */
  getById: async (id: string): Promise<Risk> => {
    return apiClient.get<Risk>(API_ENDPOINTS.risks.byId(id));
  },

  /**
   * Get risk statistics
   */
  getStats: async (): Promise<RiskStats> => {
    return apiClient.get<RiskStats>(API_ENDPOINTS.risks.stats);
  },
};

export default risksApi;
