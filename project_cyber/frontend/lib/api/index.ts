/**
 * Contexta Frontend - API Module
 * 
 * Centralized API exports for all services
 */

// Core
export { apiClient } from './client';
export { API_CONFIG, API_ENDPOINTS } from './config';

// Services
export { authApi, type User, type LoginResponse, type RegisterData } from './auth';
export { risksApi, type Risk, type TopRisksResponse, type RiskStats } from './risks';
export { incidentsApi, type Incident, type IncidentCreate, type IncidentUpdate } from './incidents';
export { assetsApi, type Asset, type AssetCreate, type AssetUpdate, type AssetStats } from './assets';
export { cvesApi, type CVE, type TrendingCVEsResponse, type CVEStats } from './cves';
export { agentsApi, type AgentType, type AgentAnalysis, type AnalysisResult } from './agents';
export { playbooksApi, type Playbook, type PlaybookCreate, type PlaybookExecution } from './playbooks';
export { twinApi, type TwinAsset, type TwinConnection, type TwinStats, type SimulationResult } from './twin';
export { ledgerApi, type LedgerBlock, type LedgerStats } from './ledger';
