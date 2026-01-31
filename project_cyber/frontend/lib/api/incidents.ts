/**
 * Incidents API Service
 */

import { apiClient } from './client';
import { API_ENDPOINTS } from './config';

export interface Incident {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'open' | 'investigating' | 'contained' | 'resolved' | 'closed';
  incident_type: string;
  risk_id?: string;
  assigned_to?: string;
  affected_assets?: string[];
  iocs?: string[];
  created_by: string;
  created_at: string;
  updated_at: string;
  resolved_at?: string;
}

export interface IncidentCreate {
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  risk_id?: string;
  assigned_to?: string;
  affected_assets?: string[];
  iocs?: string[];
}

export interface IncidentUpdate {
  title?: string;
  description?: string;
  severity?: 'critical' | 'high' | 'medium' | 'low';
  status?: 'open' | 'investigating' | 'contained' | 'resolved' | 'closed';
  assigned_to?: string;
}

export const incidentsApi = {
  /**
   * Get all incidents with pagination
   */
  list: async (params?: {
    page?: number;
    page_size?: number;
    status_filter?: string;
    severity_filter?: string;
  }): Promise<Incident[]> => {
    const searchParams = new URLSearchParams();
    if (params?.page) searchParams.append('page', params.page.toString());
    if (params?.page_size) searchParams.append('page_size', params.page_size.toString());
    if (params?.status_filter) searchParams.append('status_filter', params.status_filter);
    if (params?.severity_filter) searchParams.append('severity_filter', params.severity_filter);
    
    const query = searchParams.toString();
    return apiClient.get<Incident[]>(`${API_ENDPOINTS.incidents.list}${query ? `?${query}` : ''}`);
  },

  /**
   * Create a new incident
   */
  create: async (data: IncidentCreate): Promise<Incident> => {
    return apiClient.post<Incident>(API_ENDPOINTS.incidents.create, data);
  },

  /**
   * Get incident by ID
   */
  getById: async (id: string): Promise<Incident> => {
    return apiClient.get<Incident>(API_ENDPOINTS.incidents.byId(id));
  },

  /**
   * Update an incident
   */
  update: async (id: string, data: IncidentUpdate): Promise<Incident> => {
    return apiClient.put<Incident>(API_ENDPOINTS.incidents.byId(id), data);
  },

  /**
   * Delete an incident
   */
  delete: async (id: string): Promise<void> => {
    return apiClient.delete(API_ENDPOINTS.incidents.byId(id));
  },
};

export default incidentsApi;
