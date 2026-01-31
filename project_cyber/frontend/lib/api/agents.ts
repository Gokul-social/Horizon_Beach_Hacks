/**
 * AI Agents API Service
 */

import { apiClient } from './client';
import { API_ENDPOINTS } from './config';

export type AgentType = 'analyst' | 'intel' | 'forensics' | 'business' | 'response';

export interface AgentAnalysis {
  agent: AgentType;
  summary: string;
  findings: string[];
  severity_assessment: string;
  confidence: number;
  recommendations: string[];
  timestamp: string;
}

export interface ConsensusReport {
  consensus_severity: string;
  confidence: number;
  key_findings: string[];
  recommended_actions: string[];
  priority_level: string;
}

export interface AnalysisResult {
  incident_id: string;
  analyses: AgentAnalysis[];
  consensus_report: ConsensusReport;
  execution_time_ms: number;
  timestamp: string;
}

export interface AgentStatus {
  agent: AgentType;
  status: 'active' | 'idle' | 'error';
  last_active: string;
  tasks_completed: number;
}

export const agentsApi = {
  /**
   * Run AI agent analysis on an incident
   */
  analyzeIncident: async (
    incidentId: string,
    agents?: AgentType[]
  ): Promise<AnalysisResult> => {
    const searchParams = new URLSearchParams();
    if (agents && agents.length > 0) {
      agents.forEach(agent => searchParams.append('agents', agent));
    }
    
    const query = searchParams.toString();
    return apiClient.post<AnalysisResult>(
      `${API_ENDPOINTS.agents.analyze(incidentId)}${query ? `?${query}` : ''}`
    );
  },

  /**
   * Get agent statuses
   */
  getStatus: async (): Promise<AgentStatus[]> => {
    return apiClient.get<AgentStatus[]>(API_ENDPOINTS.agents.status);
  },
};

export default agentsApi;
