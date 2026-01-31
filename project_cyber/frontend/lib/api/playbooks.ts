/**
 * Playbooks API Service
 */

import { apiClient } from './client';
import { API_ENDPOINTS } from './config';

export interface PlaybookStep {
  id: string;
  name: string;
  description: string;
  action_type: string;
  parameters?: Record<string, unknown>;
  order: number;
}

export interface Playbook {
  id: string;
  name: string;
  description: string;
  category: string;
  severity_triggers?: string[];
  steps: PlaybookStep[];
  is_active: boolean;
  created_by: string;
  created_at: string;
  updated_at: string;
  execution_count: number;
}

export interface PlaybookCreate {
  name: string;
  description: string;
  category: string;
  severity_triggers?: string[];
  steps: Omit<PlaybookStep, 'id'>[];
}

export interface PlaybookExecution {
  id: string;
  playbook_id: string;
  incident_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  current_step?: number;
  results?: Record<string, unknown>[];
  started_at: string;
  completed_at?: string;
  executed_by: string;
}

export const playbooksApi = {
  /**
   * Get all playbooks
   */
  list: async (params?: {
    page?: number;
    page_size?: number;
    category?: string;
  }): Promise<Playbook[]> => {
    const searchParams = new URLSearchParams();
    if (params?.page) searchParams.append('page', params.page.toString());
    if (params?.page_size) searchParams.append('page_size', params.page_size.toString());
    if (params?.category) searchParams.append('category', params.category);
    
    const query = searchParams.toString();
    return apiClient.get<Playbook[]>(`${API_ENDPOINTS.playbooks.list}${query ? `?${query}` : ''}`);
  },

  /**
   * Create a new playbook
   */
  create: async (data: PlaybookCreate): Promise<Playbook> => {
    return apiClient.post<Playbook>(API_ENDPOINTS.playbooks.create, data);
  },

  /**
   * Get playbook by ID
   */
  getById: async (id: string): Promise<Playbook> => {
    return apiClient.get<Playbook>(API_ENDPOINTS.playbooks.byId(id));
  },

  /**
   * Execute a playbook
   */
  execute: async (
    playbookId: string,
    incidentId: string,
    parameters?: Record<string, unknown>
  ): Promise<PlaybookExecution> => {
    const searchParams = new URLSearchParams();
    searchParams.append('incident_id', incidentId);
    
    return apiClient.post<PlaybookExecution>(
      `${API_ENDPOINTS.playbooks.execute(playbookId)}?${searchParams.toString()}`,
      parameters
    );
  },
};

export default playbooksApi;
