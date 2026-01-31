/**
 * Digital Twin API Service
 */

import { apiClient } from './client';
import { API_ENDPOINTS } from './config';

export interface TwinAsset {
  id: string;
  name: string;
  asset_type: string;
  criticality: string;
  zone: string;
  metadata?: Record<string, unknown>;
}

export interface TwinConnection {
  source_id: string;
  target_id: string;
  connection_type: string;
  protocols?: string[];
  bidirectional: boolean;
}

export interface AttackPath {
  path: string[];
  risk_score: number;
  description: string;
  mitigations: string[];
}

export interface TwinStats {
  total_nodes: number;
  total_edges: number;
  zones: Record<string, number>;
  asset_types: Record<string, number>;
  criticality_distribution: Record<string, number>;
}

export interface SimulationResult {
  simulation_id: string;
  attack_type: string;
  entry_point: string;
  target?: string;
  paths_found: AttackPath[];
  blast_radius: string[];
  risk_assessment: string;
  recommendations: string[];
}

export const twinApi = {
  /**
   * Get digital twin statistics
   */
  getStats: async (): Promise<TwinStats> => {
    return apiClient.get<TwinStats>(API_ENDPOINTS.twin.stats);
  },

  /**
   * Export digital twin data
   */
  export: async (): Promise<{ nodes: TwinAsset[]; edges: TwinConnection[] }> => {
    return apiClient.get(API_ENDPOINTS.twin.export);
  },

  /**
   * Import digital twin data
   */
  import: async (data: { nodes: TwinAsset[]; edges: TwinConnection[] }): Promise<{ message: string; stats: TwinStats }> => {
    return apiClient.post(API_ENDPOINTS.twin.import, data);
  },

  /**
   * Add asset to digital twin
   */
  addAsset: async (asset: Omit<TwinAsset, 'id'> & { asset_id: string }): Promise<{ message: string; asset_id: string }> => {
    const searchParams = new URLSearchParams();
    searchParams.append('asset_id', asset.asset_id);
    searchParams.append('asset_type', asset.asset_type);
    searchParams.append('name', asset.name);
    searchParams.append('criticality', asset.criticality);
    searchParams.append('zone', asset.zone);
    
    return apiClient.post(`${API_ENDPOINTS.twin.assets}?${searchParams.toString()}`, asset.metadata);
  },

  /**
   * Add connection between assets
   */
  addConnection: async (connection: TwinConnection): Promise<{ message: string }> => {
    const searchParams = new URLSearchParams();
    searchParams.append('source_id', connection.source_id);
    searchParams.append('target_id', connection.target_id);
    searchParams.append('connection_type', connection.connection_type);
    if (connection.bidirectional) searchParams.append('bidirectional', 'true');
    if (connection.protocols) {
      connection.protocols.forEach(p => searchParams.append('protocols', p));
    }
    
    return apiClient.post(`${API_ENDPOINTS.twin.connections}?${searchParams.toString()}`);
  },

  /**
   * Find attack paths
   */
  findAttackPaths: async (sourceId: string, targetId?: string): Promise<AttackPath[]> => {
    const searchParams = new URLSearchParams();
    searchParams.append('source_id', sourceId);
    if (targetId) searchParams.append('target_id', targetId);
    
    return apiClient.get(`${API_ENDPOINTS.twin.attackPaths}?${searchParams.toString()}`);
  },

  /**
   * Run attack simulation
   */
  simulate: async (params: {
    attack_type: string;
    entry_point: string;
    target?: string;
  }): Promise<SimulationResult> => {
    // Convert attack_type to lowercase to ensure compatibility
    const normalizedAttackType = params.attack_type.toLowerCase();
    
    const searchParams = new URLSearchParams();
    searchParams.append('attack_type', normalizedAttackType);
    searchParams.append('entry_point', params.entry_point);
    if (params.target) searchParams.append('target', params.target);
    
    const url = `${API_ENDPOINTS.twin.simulate}?${searchParams.toString()}`;
    console.log('Calling simulate endpoint:', url);
    
    return apiClient.post<SimulationResult>(url);
  },
};

export default twinApi;
