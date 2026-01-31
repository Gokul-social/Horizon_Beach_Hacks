/**
 * API Configuration for Contexta Frontend
 */

export const API_CONFIG = {
  baseUrl: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1',
  baseApiUrl: process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000',
  tokenKey: process.env.NEXT_PUBLIC_TOKEN_KEY || 'contexta_access_token',
  refreshTokenKey: process.env.NEXT_PUBLIC_REFRESH_TOKEN_KEY || 'contexta_refresh_token',
};

export const API_ENDPOINTS = {
  // Authentication
  auth: {
    login: '/auth/login',
    register: '/auth/register',
    refresh: '/auth/refresh',
    me: '/auth/me',
    logout: '/auth/logout',
  },
  // Risks
  risks: {
    list: '/risks',
    top10: '/risks/top10',
    stats: '/risks/stats/summary',
    byId: (id: string) => `/risks/${id}`,
  },
  // Incidents
  incidents: {
    list: '/incidents',
    create: '/incidents',
    byId: (id: string) => `/incidents/${id}`,
    stats: '/incidents/stats',
  },
  // Assets
  assets: {
    list: '/assets',
    create: '/assets',
    byId: (id: string) => `/assets/${id}`,
    stats: '/assets/stats',
  },
  // CVEs
  cves: {
    list: '/cves',
    trending: '/cves/trending',
    stats: '/cves/stats/summary',
    byId: (id: string) => `/cves/${id}`,
  },
  // Agents
  agents: {
    analyze: (incidentId: string) => `/agents/analyze/${incidentId}`,
    status: '/agents/status',
  },
  // Playbooks
  playbooks: {
    list: '/playbooks',
    create: '/playbooks',
    byId: (id: string) => `/playbooks/${id}`,
    execute: (id: string) => `/playbooks/${id}/execute`,
  },
  // Digital Twin
  twin: {
    stats: '/twin/stats',
    export: '/twin/export',
    import: '/twin/import',
    assets: '/twin/assets',
    connections: '/twin/connections',
    attackPaths: '/twin/attack-paths',
    simulate: '/twin/simulate',
  },
  // Ledger
  ledger: {
    info: '/ledger',
    blocks: '/ledger/blocks',
    verify: '/ledger/verify',
  },
};
