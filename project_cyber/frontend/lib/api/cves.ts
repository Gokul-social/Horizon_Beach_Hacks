/**
 * CVEs API Service
 */

import { apiClient } from './client';
import { API_ENDPOINTS } from './config';

export interface CVE {
  id: string;
  cve_id: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cvss_score: number;
  cvss_vector?: string;
  published_date: string;
  modified_date?: string;
  has_exploit: boolean;
  exploit_maturity?: string;
  affected_products?: string[];
  references?: string[];
  source: 'nvd' | 'cisa_kev' | 'manual';
  is_kev: boolean;
  created_at: string;
}

export interface TrendingCVEsResponse {
  trending_cves: CVE[];
  count: number;
}

export interface CVEStats {
  total_cves: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  with_exploits: number;
  kev_count: number;
  recent_24h: number;
}

export const cvesApi = {
  /**
   * Get all CVEs with pagination
   */
  list: async (params?: {
    page?: number;
    page_size?: number;
    severity?: string;
    min_cvss?: number;
    has_exploit?: boolean;
  }): Promise<CVE[]> => {
    const searchParams = new URLSearchParams();
    if (params?.page) searchParams.append('page', params.page.toString());
    if (params?.page_size) searchParams.append('page_size', params.page_size.toString());
    if (params?.severity) searchParams.append('severity', params.severity);
    if (params?.min_cvss) searchParams.append('min_cvss', params.min_cvss.toString());
    if (params?.has_exploit !== undefined) searchParams.append('has_exploit', params.has_exploit.toString());
    
    const query = searchParams.toString();
    return apiClient.get<CVE[]>(`${API_ENDPOINTS.cves.list}${query ? `?${query}` : ''}`);
  },

  /**
   * Get trending CVEs
   */
  getTrending: async (limit: number = 10): Promise<TrendingCVEsResponse> => {
    return apiClient.get<TrendingCVEsResponse>(`${API_ENDPOINTS.cves.trending}?limit=${limit}`);
  },

  /**
   * Get CVE by ID
   */
  getById: async (id: string): Promise<CVE> => {
    return apiClient.get<CVE>(API_ENDPOINTS.cves.byId(id));
  },

  /**
   * Get CVE statistics
   */
  getStats: async (): Promise<CVEStats> => {
    return apiClient.get<CVEStats>(API_ENDPOINTS.cves.stats);
  },
};

export default cvesApi;
