/**
 * Ledger API Service
 */

import { apiClient } from './client';
import { API_ENDPOINTS } from './config';

export interface LedgerBlock {
  index: number;
  timestamp: string;
  event_type: string;
  data: Record<string, unknown>;
  actor: string;
  previous_hash: string;
  hash: string;
}

export interface LedgerStats {
  total_blocks: number;
  genesis_timestamp: string;
  latest_timestamp: string;
  event_types: Record<string, number>;
  actors: Record<string, number>;
  chain_valid: boolean;
}

export interface LedgerBlocksResponse {
  blocks: LedgerBlock[];
  total: number;
  skip: number;
  limit: number;
}

export const ledgerApi = {
  /**
   * Get ledger information and statistics
   */
  getInfo: async (): Promise<LedgerStats> => {
    return apiClient.get<LedgerStats>(API_ENDPOINTS.ledger.info);
  },

  /**
   * Get blocks with pagination and filtering
   */
  getBlocks: async (params?: {
    skip?: number;
    limit?: number;
    event_type?: string;
    actor?: string;
  }): Promise<LedgerBlocksResponse> => {
    const searchParams = new URLSearchParams();
    if (params?.skip) searchParams.append('skip', params.skip.toString());
    if (params?.limit) searchParams.append('limit', params.limit.toString());
    if (params?.event_type) searchParams.append('event_type', params.event_type);
    if (params?.actor) searchParams.append('actor', params.actor);
    
    const query = searchParams.toString();
    return apiClient.get<LedgerBlocksResponse>(`${API_ENDPOINTS.ledger.blocks}${query ? `?${query}` : ''}`);
  },

  /**
   * Get a specific block by index
   */
  getBlock: async (index: number): Promise<LedgerBlock> => {
    return apiClient.get<LedgerBlock>(`${API_ENDPOINTS.ledger.blocks}/${index}`);
  },

  /**
   * Verify chain integrity
   */
  verifyChain: async (): Promise<{ valid: boolean; error?: string }> => {
    return apiClient.get(API_ENDPOINTS.ledger.verify);
  },
};

export default ledgerApi;
