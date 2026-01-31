/**
 * ============================================================================
 * RiskLens AI - Context-Aware Threat Intelligence & Business Risk Platform
 * ============================================================================
 * 
 * A functional prototype backend that simulates a real SOC intelligence engine.
 * This backend powers all frontend views with live, dynamic data and demonstrates
 * intelligent risk scoring, attack simulation, and business impact analysis.
 * 
 * Author: RiskLens AI Team
 * Version: 1.0.0
 * ============================================================================
 */

const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 5000;

// ============================================================================
// MIDDLEWARE CONFIGURATION
// ============================================================================
app.use(cors());
app.use(express.json());

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Generates a random ID for new entities
 */
const generateId = () => Math.random().toString(36).substr(2, 9);

/**
 * Calculates relative time string from timestamp
 */
const getRelativeTime = (timestamp) => {
  const now = new Date();
  const diff = now - new Date(timestamp);
  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24) return `${hours}h ago`;
  return `${days}d ago`;
};

/**
 * Generates a random value within a range
 */
const randomInRange = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;

/**
 * Picks a random item from an array
 */
const randomPick = (arr) => arr[Math.floor(Math.random() * arr.length)];

// ============================================================================
// 1️⃣ ASSET INVENTORY SERVICE
// ============================================================================
/**
 * Each asset represents a monitored entity in the organization's infrastructure.
 * Assets have business criticality levels that affect risk scoring.
 */

const assetTypes = ['server', 'database', 'application', 'network', 'endpoint', 'cloud'];
const departments = ['finance', 'hr', 'it', 'sales', 'engineering', 'operations', 'legal', 'executive'];
const criticalities = ['low', 'medium', 'high', 'critical'];
const locations = ['US-EAST-1', 'US-WEST-2', 'EU-WEST-1', 'AP-SOUTH-1', 'US-CENTRAL-1'];
const operatingSystems = ['Ubuntu 22.04 LTS', 'CentOS 8', 'Windows Server 2022', 'Amazon Linux 2', 'RHEL 9', 'Debian 11'];

// Generate comprehensive asset inventory
const assets = [
  { id: 'AST-001', name: 'Primary Database Server', type: 'database', businessCriticality: 'critical', department: 'it', internetExposed: false, status: 'healthy', vulnerabilities: 2, lastScanned: new Date(Date.now() - 3600000).toISOString(), owner: 'Data Team', location: 'US-EAST-1', osVersion: 'PostgreSQL 15 on Ubuntu 22.04' },
  { id: 'AST-002', name: 'Payment Gateway API', type: 'application', businessCriticality: 'critical', department: 'finance', internetExposed: true, status: 'warning', vulnerabilities: 5, lastScanned: new Date(Date.now() - 86400000).toISOString(), owner: 'Finance Team', location: 'US-EAST-1', osVersion: 'Node.js 20 LTS' },
  { id: 'AST-003', name: 'HR Portal', type: 'application', businessCriticality: 'high', department: 'hr', internetExposed: true, status: 'healthy', vulnerabilities: 1, lastScanned: new Date(Date.now() - 7200000).toISOString(), owner: 'HR Team', location: 'US-WEST-2', osVersion: 'React + Next.js' },
  { id: 'AST-004', name: 'VPN Gateway', type: 'network', businessCriticality: 'critical', department: 'it', internetExposed: true, status: 'critical', vulnerabilities: 8, lastScanned: new Date(Date.now() - 1800000).toISOString(), owner: 'Infrastructure Team', location: 'US-EAST-1', osVersion: 'Cisco ASA 9.x' },
  { id: 'AST-005', name: 'Email Server', type: 'server', businessCriticality: 'high', department: 'it', internetExposed: true, status: 'warning', vulnerabilities: 3, lastScanned: new Date(Date.now() - 43200000).toISOString(), owner: 'IT Operations', location: 'US-CENTRAL-1', osVersion: 'Exchange Server 2019' },
  { id: 'AST-006', name: 'CRM System', type: 'application', businessCriticality: 'high', department: 'sales', internetExposed: true, status: 'healthy', vulnerabilities: 2, lastScanned: new Date(Date.now() - 14400000).toISOString(), owner: 'Sales Team', location: 'EU-WEST-1', osVersion: 'Salesforce Cloud' },
  { id: 'AST-007', name: 'Data Warehouse', type: 'database', businessCriticality: 'high', department: 'engineering', internetExposed: false, status: 'healthy', vulnerabilities: 0, lastScanned: new Date(Date.now() - 3600000).toISOString(), owner: 'Data Engineering', location: 'US-WEST-2', osVersion: 'Snowflake' },
  { id: 'AST-008', name: 'CI/CD Pipeline Server', type: 'server', businessCriticality: 'high', department: 'engineering', internetExposed: false, status: 'warning', vulnerabilities: 4, lastScanned: new Date(Date.now() - 28800000).toISOString(), owner: 'DevOps Team', location: 'US-EAST-1', osVersion: 'Jenkins on Ubuntu 22.04' },
  { id: 'AST-009', name: 'Executive Dashboard', type: 'application', businessCriticality: 'critical', department: 'executive', internetExposed: true, status: 'healthy', vulnerabilities: 1, lastScanned: new Date(Date.now() - 7200000).toISOString(), owner: 'Executive Office', location: 'US-EAST-1', osVersion: 'Power BI Service' },
  { id: 'AST-010', name: 'Backup Storage', type: 'server', businessCriticality: 'critical', department: 'it', internetExposed: false, status: 'healthy', vulnerabilities: 0, lastScanned: new Date(Date.now() - 1800000).toISOString(), owner: 'Infrastructure Team', location: 'US-WEST-2', osVersion: 'NetApp ONTAP 9.12' },
  { id: 'AST-011', name: 'Load Balancer', type: 'network', businessCriticality: 'critical', department: 'it', internetExposed: true, status: 'healthy', vulnerabilities: 1, lastScanned: new Date(Date.now() - 3600000).toISOString(), owner: 'Infrastructure Team', location: 'US-EAST-1', osVersion: 'F5 BIG-IP 17.x' },
  { id: 'AST-012', name: 'API Gateway', type: 'application', businessCriticality: 'critical', department: 'engineering', internetExposed: true, status: 'warning', vulnerabilities: 6, lastScanned: new Date(Date.now() - 5400000).toISOString(), owner: 'Platform Team', location: 'US-EAST-1', osVersion: 'Kong Gateway 3.x' },
  { id: 'AST-013', name: 'Workstation Fleet', type: 'endpoint', businessCriticality: 'medium', department: 'operations', internetExposed: false, status: 'warning', vulnerabilities: 12, lastScanned: new Date(Date.now() - 172800000).toISOString(), owner: 'IT Support', location: 'US-CENTRAL-1', osVersion: 'Windows 11 Enterprise' },
  { id: 'AST-014', name: 'Legal Document Server', type: 'server', businessCriticality: 'high', department: 'legal', internetExposed: false, status: 'healthy', vulnerabilities: 1, lastScanned: new Date(Date.now() - 10800000).toISOString(), owner: 'Legal Team', location: 'US-EAST-1', osVersion: 'Windows Server 2022' },
  { id: 'AST-015', name: 'Cloud Infrastructure (AWS)', type: 'cloud', businessCriticality: 'critical', department: 'it', internetExposed: true, status: 'healthy', vulnerabilities: 3, lastScanned: new Date(Date.now() - 900000).toISOString(), owner: 'Cloud Team', location: 'US-EAST-1', osVersion: 'AWS Multi-Region' },
];

// ============================================================================
// 2️⃣ THREAT & ALERT SIMULATION ENGINE
// ============================================================================
/**
 * Simulates real-world cybersecurity alerts from various sources.
 * Each alert is linked to an asset and has severity scoring.
 */

const alertTypes = [
  { type: 'failed_login', name: 'Failed Login Attempts', baseWeight: 3 },
  { type: 'malware_detected', name: 'Malware Detection', baseWeight: 9 },
  { type: 'cve_exposure', name: 'CVE Vulnerability Exposure', baseWeight: 7 },
  { type: 'phishing_attempt', name: 'Phishing Attempt Detected', baseWeight: 6 },
  { type: 'ransomware', name: 'Ransomware Activity', baseWeight: 10 },
  { type: 'data_exfiltration', name: 'Suspicious Data Transfer', baseWeight: 8 },
  { type: 'brute_force', name: 'Brute Force Attack', baseWeight: 5 },
  { type: 'privilege_escalation', name: 'Privilege Escalation Attempt', baseWeight: 8 },
  { type: 'unauthorized_access', name: 'Unauthorized Access', baseWeight: 7 },
  { type: 'ddos', name: 'DDoS Attack Pattern', baseWeight: 6 },
  { type: 'zero_day', name: 'Zero-Day Exploit Attempt', baseWeight: 10 },
  { type: 'insider_threat', name: 'Insider Threat Indicator', baseWeight: 8 },
];

const alertSources = ['siem', 'edr', 'threat_feed', 'firewall', 'ids', 'dlp', 'email_gateway', 'ad', 'cloud_security'];
const severities = ['low', 'medium', 'high', 'critical'];

// Generate dynamic alerts based on assets
const generateAlerts = () => {
  const alerts = [];
  const now = Date.now();
  
  // Generate 25-35 alerts
  const alertCount = randomInRange(25, 35);
  
  for (let i = 0; i < alertCount; i++) {
    const alertType = randomPick(alertTypes);
    const asset = randomPick(assets);
    const timeOffset = randomInRange(60000, 259200000); // 1 min to 3 days ago
    
    // Calculate severity based on asset criticality and alert type
    let severityScore = alertType.baseWeight;
    if (asset.businessCriticality === 'critical') severityScore += 2;
    else if (asset.businessCriticality === 'high') severityScore += 1;
    if (asset.internetExposed) severityScore += 1;
    
    let severity;
    if (severityScore >= 10) severity = 'critical';
    else if (severityScore >= 7) severity = 'high';
    else if (severityScore >= 4) severity = 'medium';
    else severity = 'low';
    
    alerts.push({
      id: `ALT-${String(i + 1).padStart(4, '0')}`,
      type: alertType.type,
      title: alertType.name,
      message: `${alertType.name} detected on ${asset.name}`,
      severity,
      severityScore,
      relatedAssetId: asset.id,
      relatedAssetName: asset.name,
      timestamp: new Date(now - timeOffset).toISOString(),
      relativeTime: getRelativeTime(new Date(now - timeOffset)),
      source: randomPick(alertSources),
      status: randomPick(['active', 'investigating', 'contained', 'resolved']),
      affectedDepartment: asset.department,
    });
  }
  
  // Sort by timestamp (newest first)
  return alerts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
};

let alerts = generateAlerts();

// Regenerate alerts every 5 minutes to simulate real-time data
setInterval(() => {
  alerts = generateAlerts();
  console.log('🔄 Alerts regenerated at', new Date().toISOString());
}, 300000);

// ============================================================================
// 3️⃣ BUSINESS-AWARE RISK SCORING ENGINE
// ============================================================================
/**
 * Implements dynamic risk scoring formula:
 * riskScore = severityWeight + assetCriticalityWeight + internetExposureWeight + threatActivityWeight
 * 
 * This creates a business-contextualized risk score that prioritizes threats
 * based on actual business impact, not just technical severity.
 */

const severityWeights = { low: 1, medium: 3, high: 6, critical: 10 };
const criticalityWeights = { low: 1, medium: 2, high: 4, critical: 8 };
const exposureWeight = 3; // Added if internet-exposed

const calculateRiskScore = (alert, asset) => {
  // Base severity weight
  let score = severityWeights[alert.severity] || 5;
  
  // Asset criticality weight
  score += criticalityWeights[asset.businessCriticality] || 2;
  
  // Internet exposure weight
  if (asset.internetExposed) score += exposureWeight;
  
  // Threat activity weight (based on recent alerts for same asset)
  const recentAlerts = alerts.filter(a => 
    a.relatedAssetId === asset.id && 
    new Date(a.timestamp) > new Date(Date.now() - 86400000) // Last 24 hours
  );
  score += Math.min(recentAlerts.length * 0.5, 5); // Max 5 points from activity
  
  return Math.min(Math.round(score * 10) / 10, 100); // Cap at 100, round to 1 decimal
};

const getRiskLevel = (score) => {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  return 'LOW';
};

// Generate comprehensive risk assessments
const generateRisks = () => {
  const riskCategories = [
    { name: 'Ransomware Campaign - LockBit 3.0', category: 'Malware', baseScore: 95 },
    { name: 'VPN Zero-Day RCE (CVE-2025-1234)', category: 'Vulnerability', baseScore: 92 },
    { name: 'Phishing Campaign - Finance Dept', category: 'Social Engineering', baseScore: 85 },
    { name: 'Unpatched Apache Struts (CVE-2025-5678)', category: 'Vulnerability', baseScore: 78 },
    { name: 'Insider Threat - Data Exfiltration', category: 'Insider Threat', baseScore: 74 },
    { name: 'DDoS Attack Pattern Detected', category: 'Network Attack', baseScore: 68 },
    { name: 'Weak Password Policy Violations', category: 'Policy Violation', baseScore: 62 },
    { name: 'Outdated SSL/TLS Certificates', category: 'Configuration', baseScore: 55 },
    { name: 'Misconfigured S3 Buckets', category: 'Cloud Security', baseScore: 48 },
    { name: 'Shadow IT - Unapproved SaaS', category: 'Policy Violation', baseScore: 42 },
    { name: 'SQL Injection Vulnerability', category: 'Vulnerability', baseScore: 88 },
    { name: 'Credential Stuffing Attack', category: 'Network Attack', baseScore: 72 },
    { name: 'API Authentication Bypass', category: 'Vulnerability', baseScore: 82 },
    { name: 'Unsecured MongoDB Instance', category: 'Cloud Security', baseScore: 65 },
    { name: 'Privilege Escalation Vector', category: 'Access Control', baseScore: 76 },
  ];
  
  return riskCategories.map((risk, index) => {
    const affectedAssets = assets.filter(a => 
      (risk.category === 'Vulnerability' && a.vulnerabilities > 0) ||
      (risk.category === 'Cloud Security' && a.type === 'cloud') ||
      Math.random() > 0.7
    );
    
    // Add some variability to scores
    const variability = randomInRange(-5, 5);
    const score = Math.min(100, Math.max(0, risk.baseScore + variability));
    
    return {
      id: `RSK-${String(index + 1).padStart(3, '0')}`,
      rank: index + 1,
      name: risk.name,
      category: risk.category,
      score,
      severity: getRiskLevel(score),
      affectedAssets: affectedAssets.length || randomInRange(3, 50),
      affectedAssetIds: affectedAssets.map(a => a.id),
      lastDetected: getRelativeTime(new Date(Date.now() - randomInRange(60000, 259200000))),
      trend: randomPick(['increasing', 'stable', 'decreasing']),
      mitigation: getMitigationRecommendation(risk.category),
      businessImpact: getBusinessImpact(score),
    };
  }).sort((a, b) => b.score - a.score);
};

const getMitigationRecommendation = (category) => {
  const recommendations = {
    'Malware': 'Deploy advanced EDR, isolate affected systems, initiate incident response',
    'Vulnerability': 'Apply security patches, implement compensating controls, update WAF rules',
    'Social Engineering': 'Enhance security awareness training, implement email filtering',
    'Insider Threat': 'Review access permissions, enable DLP policies, monitor user behavior',
    'Network Attack': 'Enable DDoS protection, update firewall rules, implement rate limiting',
    'Policy Violation': 'Enforce security policies, conduct user training, automate compliance',
    'Configuration': 'Update certificates, implement configuration management, scan regularly',
    'Cloud Security': 'Review IAM policies, enable encryption, implement cloud security posture management',
    'Access Control': 'Implement least privilege, enable MFA, review service accounts',
  };
  return recommendations[category] || 'Review and remediate according to security policy';
};

const getBusinessImpact = (score) => {
  if (score >= 80) return { level: 'Severe', financialImpact: '$2M - $10M', downtime: '24-72 hours' };
  if (score >= 60) return { level: 'Major', financialImpact: '$500K - $2M', downtime: '8-24 hours' };
  if (score >= 40) return { level: 'Moderate', financialImpact: '$100K - $500K', downtime: '2-8 hours' };
  return { level: 'Minor', financialImpact: '$10K - $100K', downtime: '< 2 hours' };
};

let risks = generateRisks();

// ============================================================================
// 4️⃣ ATTACK SIMULATION (WHAT-IF ENGINE)
// ============================================================================
/**
 * Simulates attack paths using MITRE ATT&CK framework techniques.
 * Estimates business impact including downtime, data loss, and financial impact.
 */

const mitreTactics = [
  { id: 'TA0001', name: 'Initial Access', techniques: ['Phishing', 'Exploit Public-Facing Application', 'Valid Accounts'] },
  { id: 'TA0002', name: 'Execution', techniques: ['Command and Scripting Interpreter', 'User Execution', 'Windows Management Instrumentation'] },
  { id: 'TA0003', name: 'Persistence', techniques: ['Boot or Logon Autostart', 'Account Manipulation', 'Create Account'] },
  { id: 'TA0004', name: 'Privilege Escalation', techniques: ['Exploitation for Privilege Escalation', 'Access Token Manipulation', 'Sudo and Sudo Caching'] },
  { id: 'TA0005', name: 'Defense Evasion', techniques: ['Obfuscated Files', 'Masquerading', 'Rootkit'] },
  { id: 'TA0006', name: 'Credential Access', techniques: ['Brute Force', 'Credential Dumping', 'Keylogging'] },
  { id: 'TA0007', name: 'Discovery', techniques: ['Account Discovery', 'System Information Discovery', 'Network Service Scanning'] },
  { id: 'TA0008', name: 'Lateral Movement', techniques: ['Remote Services', 'Internal Spearphishing', 'Pass the Hash'] },
  { id: 'TA0009', name: 'Collection', techniques: ['Data from Local System', 'Email Collection', 'Screen Capture'] },
  { id: 'TA0010', name: 'Exfiltration', techniques: ['Exfiltration Over C2 Channel', 'Exfiltration Over Web Service', 'Scheduled Transfer'] },
  { id: 'TA0040', name: 'Impact', techniques: ['Data Destruction', 'Data Encrypted for Impact', 'Service Stop'] },
];

const simulateAttack = (riskId) => {
  const risk = risks.find(r => r.id === riskId);
  if (!risk) return null;
  
  // Determine attack path based on risk category
  let relevantTactics;
  switch (risk.category) {
    case 'Malware':
    case 'Ransomware':
      relevantTactics = mitreTactics.slice(0, 5).concat(mitreTactics.slice(-1));
      break;
    case 'Social Engineering':
      relevantTactics = mitreTactics.slice(0, 3);
      break;
    case 'Network Attack':
      relevantTactics = [mitreTactics[0], mitreTactics[6], mitreTactics[7]];
      break;
    case 'Insider Threat':
      relevantTactics = [mitreTactics[5], mitreTactics[8], mitreTactics[9]];
      break;
    default:
      relevantTactics = mitreTactics.slice(0, 6);
  }
  
  const attackSteps = relevantTactics.map((tactic, index) => ({
    step: index + 1,
    tacticId: tactic.id,
    tacticName: tactic.name,
    technique: randomPick(tactic.techniques),
    likelihood: Math.round((100 - index * 10 - Math.random() * 15)),
    timeToDetect: `${randomInRange(5, 120)} minutes`,
    mitigationAvailable: Math.random() > 0.3,
  }));
  
  // Calculate estimated impact based on risk score and affected assets
  const baseFinancialImpact = risk.score * 50000; // $50K per risk point
  const assetMultiplier = Math.min(risk.affectedAssets * 0.1, 2); // Max 2x multiplier
  
  return {
    riskId: risk.id,
    riskName: risk.name,
    attackSteps,
    estimatedImpact: {
      downtimeHours: Math.round(risk.score * 0.72), // ~72 hours for score 100
      dataLoss: risk.score >= 60,
      dataLossDescription: risk.score >= 60 ? 'Potential exposure of sensitive customer/business data' : 'Limited data exposure risk',
      financialImpact: Math.round(baseFinancialImpact * assetMultiplier),
      financialImpactFormatted: `$${(Math.round(baseFinancialImpact * assetMultiplier) / 1000000).toFixed(1)}M`,
      reputationalDamage: risk.score >= 70 ? 'HIGH' : risk.score >= 50 ? 'MEDIUM' : 'LOW',
      regulatoryRisk: risk.category === 'Cloud Security' || risk.score >= 80,
      affectedSystems: risk.affectedAssets,
      recoveryTimeEstimate: `${Math.round(risk.score * 0.5)} - ${Math.round(risk.score * 1)} hours`,
    },
    mitreMappings: relevantTactics.map(t => ({ id: t.id, name: t.name })),
    recommendations: [
      { priority: 'Immediate', action: risk.mitigation },
      { priority: 'Short-term', action: 'Implement additional monitoring and detection rules' },
      { priority: 'Long-term', action: 'Review and enhance security architecture' },
    ],
  };
};

// ============================================================================
// 5️⃣ EXECUTIVE / BUSINESS SUMMARY API
// ============================================================================
/**
 * Aggregates all backend data to produce executive-level insights.
 * Provides business-focused metrics and trends.
 */

const calculateExecutiveSummary = () => {
  // Calculate overall risk score (weighted average of top risks)
  const topRisks = risks.slice(0, 10);
  const overallRiskScore = Math.round(
    topRisks.reduce((sum, r, idx) => sum + r.score * (10 - idx), 0) / 55 // Weighted by rank
  );
  
  // Department risk breakdown
  const departmentRiskBreakdown = departments.map(dept => {
    const deptAssets = assets.filter(a => a.department === dept);
    const deptAlerts = alerts.filter(a => a.affectedDepartment === dept);
    
    let riskScore = 0;
    if (deptAlerts.length > 0) {
      riskScore = Math.min(100, deptAlerts.reduce((sum, a) => sum + a.severityScore, 0) / deptAlerts.length * 10);
    }
    
    return {
      department: dept.charAt(0).toUpperCase() + dept.slice(1),
      riskScore: Math.round(riskScore * 10) / 10,
      alertCount: deptAlerts.length,
      assetCount: deptAssets.length,
      criticalAlerts: deptAlerts.filter(a => a.severity === 'critical').length,
    };
  }).sort((a, b) => b.riskScore - a.riskScore);
  
  // Calculate potential financial impact
  const criticalRisks = risks.filter(r => r.severity === 'CRITICAL');
  const highRisks = risks.filter(r => r.severity === 'HIGH');
  const potentialFinancialImpact = {
    dataBreachCost: criticalRisks.length * 2000000 + highRisks.length * 500000,
    ransomwareImpact: criticalRisks.some(r => r.category === 'Malware') ? 2800000 : 0,
    regulatoryFines: risks.filter(r => r.score >= 70).length * 150000,
    downtimeCost: topRisks.reduce((sum, r) => sum + r.score * 10000, 0),
  };
  potentialFinancialImpact.total = Object.values(potentialFinancialImpact).reduce((a, b) => a + b, 0);
  
  // Generate mock 7-day trend
  const riskTrend = [];
  let trendScore = overallRiskScore - 5;
  for (let i = 6; i >= 0; i--) {
    const date = new Date(Date.now() - i * 86400000);
    trendScore += randomInRange(-3, 4);
    trendScore = Math.max(0, Math.min(100, trendScore));
    riskTrend.push({
      date: date.toISOString().split('T')[0],
      day: date.toLocaleDateString('en-US', { weekday: 'short' }),
      score: Math.round(trendScore),
      criticalAlerts: randomInRange(2, 8),
      highAlerts: randomInRange(5, 15),
    });
  }
  
  return {
    overallRiskScore,
    riskLevel: getRiskLevel(overallRiskScore),
    departmentRiskBreakdown,
    potentialFinancialImpact: {
      ...potentialFinancialImpact,
      formatted: `$${(potentialFinancialImpact.total / 1000000).toFixed(1)}M`,
    },
    riskTrend,
    complianceStatus: {
      overall: 94,
      frameworks: [
        { name: 'SOC 2 Type II', score: 98, status: 'Compliant' },
        { name: 'ISO 27001', score: 96, status: 'Compliant' },
        { name: 'GDPR', score: 92, status: 'Compliant' },
        { name: 'HIPAA', score: 88, status: 'Attention Required' },
        { name: 'PCI DSS', score: 85, status: 'Attention Required' },
      ],
    },
    keyMetrics: {
      totalAssets: assets.length,
      monitoredAssets: assets.filter(a => a.status !== 'offline').length,
      criticalAssets: assets.filter(a => a.businessCriticality === 'critical').length,
      totalVulnerabilities: assets.reduce((sum, a) => sum + a.vulnerabilities, 0),
      activeAlerts: alerts.filter(a => a.status === 'active').length,
      criticalAlerts: alerts.filter(a => a.severity === 'critical').length,
      meanTimeToDetect: '15 minutes',
      meanTimeToRespond: '45 minutes',
    },
    lastUpdated: new Date().toISOString(),
  };
};

// ============================================================================
// 📊 DASHBOARD DATA AGGREGATION
// ============================================================================
/**
 * Provides aggregated data for the main dashboard view.
 */

const getDashboardData = () => {
  const activeAlerts = alerts.filter(a => a.status === 'active' || a.status === 'investigating');
  const criticalAlerts = alerts.filter(a => a.severity === 'critical');
  const topRisks = risks.slice(0, 5);
  
  return {
    kpis: {
      totalRisks: risks.length,
      criticalRisks: risks.filter(r => r.severity === 'CRITICAL').length,
      criticalAlerts: criticalAlerts.length,
      activeAlerts: activeAlerts.length,
      assetsMonitored: assets.length,
      vulnerableAssets: assets.filter(a => a.vulnerabilities > 0).length,
      complianceScore: 94,
      overallRiskScore: Math.round(risks.slice(0, 10).reduce((sum, r) => sum + r.score, 0) / 10),
    },
    recentAlerts: alerts.slice(0, 5).map(a => ({
      id: a.id,
      severity: a.severity,
      title: a.title,
      message: a.message,
      timestamp: a.relativeTime,
      source: a.source,
      affected: a.relatedAssetName,
    })),
    topRisks: topRisks.map(r => ({
      id: r.id,
      rank: r.rank,
      name: r.name,
      score: r.score,
      severity: r.severity,
      category: r.category,
      affected: r.affectedAssets,
      trend: r.trend,
    })),
    threatInsights: [
      { category: 'Malware', count: alerts.filter(a => a.type === 'malware_detected' || a.type === 'ransomware').length, trend: 'up' },
      { category: 'Phishing', count: alerts.filter(a => a.type === 'phishing_attempt').length, trend: 'down' },
      { category: 'Unauthorized Access', count: alerts.filter(a => a.type === 'unauthorized_access').length, trend: 'up' },
      { category: 'Data Exfiltration', count: alerts.filter(a => a.type === 'data_exfiltration').length, trend: 'stable' },
      { category: 'Brute Force', count: alerts.filter(a => a.type === 'brute_force' || a.type === 'failed_login').length, trend: 'up' },
    ],
    departmentHeatmap: calculateExecutiveSummary().departmentRiskBreakdown.slice(0, 6),
    riskTrend: [
      { month: 'Sep', critical: 12, high: 23, medium: 45, low: 67 },
      { month: 'Oct', critical: 15, high: 28, medium: 42, low: 63 },
      { month: 'Nov', critical: 18, high: 32, medium: 38, low: 58 },
      { month: 'Dec', critical: 14, high: 25, medium: 40, low: 65 },
      { month: 'Jan', critical: criticalAlerts.length, high: alerts.filter(a => a.severity === 'high').length, medium: alerts.filter(a => a.severity === 'medium').length, low: alerts.filter(a => a.severity === 'low').length },
    ],
    vulnerabilities: [
      { name: 'Critical', value: risks.filter(r => r.severity === 'CRITICAL').length },
      { name: 'High', value: risks.filter(r => r.severity === 'HIGH').length },
      { name: 'Medium', value: risks.filter(r => r.severity === 'MEDIUM').length },
      { name: 'Low', value: risks.filter(r => r.severity === 'LOW').length },
    ],
    recommendedActions: [
      { id: 1, title: 'Patch VPN Gateway Critical CVE', priority: 'Critical', eta: '2 hours', category: 'Vulnerability', riskReduction: 15 },
      { id: 2, title: 'Isolate compromised endpoints', priority: 'Critical', eta: '1 hour', category: 'Incident Response', riskReduction: 12 },
      { id: 3, title: 'Update firewall rules for DDoS protection', priority: 'High', eta: '4 hours', category: 'Network Security', riskReduction: 8 },
      { id: 4, title: 'Rotate exposed API credentials', priority: 'High', eta: '2 hours', category: 'Access Control', riskReduction: 10 },
      { id: 5, title: 'Deploy additional EDR sensors', priority: 'Medium', eta: '1 day', category: 'Endpoint Security', riskReduction: 5 },
    ],
  };
};

// ============================================================================
// 🛣️ API ROUTES
// ============================================================================

// Health Check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'RiskLens AI Backend is operational',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
  });
});

// ============================================================================
// DASHBOARD ENDPOINTS
// ============================================================================

// Full dashboard data
app.get('/api/dashboard', (req, res) => {
  res.json(getDashboardData());
});

// KPIs only
app.get('/api/kpis', (req, res) => {
  res.json(getDashboardData().kpis);
});

// ============================================================================
// ASSET ENDPOINTS
// ============================================================================

// Get all assets
app.get('/api/assets', (req, res) => {
  const { department, type, criticality, status } = req.query;
  
  let filteredAssets = [...assets];
  
  if (department) filteredAssets = filteredAssets.filter(a => a.department === department.toLowerCase());
  if (type) filteredAssets = filteredAssets.filter(a => a.type === type.toLowerCase());
  if (criticality) filteredAssets = filteredAssets.filter(a => a.businessCriticality === criticality.toLowerCase());
  if (status) filteredAssets = filteredAssets.filter(a => a.status === status.toLowerCase());
  
  res.json({
    total: filteredAssets.length,
    assets: filteredAssets.map(a => ({
      ...a,
      lastScannedRelative: getRelativeTime(new Date(a.lastScanned)),
    })),
    summary: {
      total: assets.length,
      healthy: assets.filter(a => a.status === 'healthy').length,
      warning: assets.filter(a => a.status === 'warning').length,
      critical: assets.filter(a => a.status === 'critical').length,
      byType: assetTypes.map(type => ({ type, count: assets.filter(a => a.type === type).length })),
      byDepartment: departments.map(dept => ({ department: dept, count: assets.filter(a => a.department === dept).length })),
    },
  });
});

// Get asset by ID
app.get('/api/assets/:id', (req, res) => {
  const asset = assets.find(a => a.id === req.params.id);
  
  if (!asset) {
    return res.status(404).json({ error: 'Asset not found' });
  }
  
  // Get related alerts for this asset
  const relatedAlerts = alerts.filter(a => a.relatedAssetId === asset.id);
  
  res.json({
    ...asset,
    lastScannedRelative: getRelativeTime(new Date(asset.lastScanned)),
    relatedAlerts: relatedAlerts.slice(0, 10),
    riskScore: calculateAssetRiskScore(asset),
  });
});

const calculateAssetRiskScore = (asset) => {
  let score = 0;
  
  // Base score from criticality
  score += criticalityWeights[asset.businessCriticality] * 5;
  
  // Vulnerability score
  score += asset.vulnerabilities * 3;
  
  // Internet exposure
  if (asset.internetExposed) score += 10;
  
  // Status penalty
  if (asset.status === 'critical') score += 20;
  else if (asset.status === 'warning') score += 10;
  
  return Math.min(100, score);
};

// ============================================================================
// ALERT ENDPOINTS
// ============================================================================

// Get all alerts
app.get('/api/alerts', (req, res) => {
  const { severity, status, source, limit } = req.query;
  
  let filteredAlerts = [...alerts];
  
  if (severity) filteredAlerts = filteredAlerts.filter(a => a.severity === severity.toLowerCase());
  if (status) filteredAlerts = filteredAlerts.filter(a => a.status === status.toLowerCase());
  if (source) filteredAlerts = filteredAlerts.filter(a => a.source === source.toLowerCase());
  
  const resultLimit = limit ? parseInt(limit) : filteredAlerts.length;
  
  res.json({
    total: filteredAlerts.length,
    alerts: filteredAlerts.slice(0, resultLimit),
    summary: {
      total: alerts.length,
      bySeverity: {
        critical: alerts.filter(a => a.severity === 'critical').length,
        high: alerts.filter(a => a.severity === 'high').length,
        medium: alerts.filter(a => a.severity === 'medium').length,
        low: alerts.filter(a => a.severity === 'low').length,
      },
      byStatus: {
        active: alerts.filter(a => a.status === 'active').length,
        investigating: alerts.filter(a => a.status === 'investigating').length,
        contained: alerts.filter(a => a.status === 'contained').length,
        resolved: alerts.filter(a => a.status === 'resolved').length,
      },
    },
  });
});

// Get recent alerts (last 24 hours)
app.get('/api/alerts/recent', (req, res) => {
  const cutoff = new Date(Date.now() - 86400000); // 24 hours ago
  const recentAlerts = alerts.filter(a => new Date(a.timestamp) > cutoff);
  
  res.json({
    total: recentAlerts.length,
    alerts: recentAlerts,
    summary: {
      critical: recentAlerts.filter(a => a.severity === 'critical').length,
      high: recentAlerts.filter(a => a.severity === 'high').length,
      medium: recentAlerts.filter(a => a.severity === 'medium').length,
      low: recentAlerts.filter(a => a.severity === 'low').length,
    },
  });
});

// ============================================================================
// RISK ENDPOINTS
// ============================================================================

// Get all risks
app.get('/api/risks', (req, res) => {
  const { severity, category, limit } = req.query;
  
  let filteredRisks = [...risks];
  
  if (severity) filteredRisks = filteredRisks.filter(r => r.severity === severity.toUpperCase());
  if (category) filteredRisks = filteredRisks.filter(r => r.category.toLowerCase().includes(category.toLowerCase()));
  
  const resultLimit = limit ? parseInt(limit) : filteredRisks.length;
  
  res.json({
    total: filteredRisks.length,
    risks: filteredRisks.slice(0, resultLimit),
    summary: {
      bySeverity: {
        critical: risks.filter(r => r.severity === 'CRITICAL').length,
        high: risks.filter(r => r.severity === 'HIGH').length,
        medium: risks.filter(r => r.severity === 'MEDIUM').length,
        low: risks.filter(r => r.severity === 'LOW').length,
      },
    },
  });
});

// Get top risks
app.get('/api/risks/top', (req, res) => {
  const limit = req.query.limit ? parseInt(req.query.limit) : 10;
  
  res.json({
    topRisks: risks.slice(0, limit),
    overallRiskScore: Math.round(risks.slice(0, 10).reduce((sum, r) => sum + r.score, 0) / 10),
    lastUpdated: new Date().toISOString(),
  });
});

// Get risk by ID
app.get('/api/risks/:id', (req, res) => {
  const risk = risks.find(r => r.id === req.params.id);
  
  if (!risk) {
    return res.status(404).json({ error: 'Risk not found' });
  }
  
  // Get affected assets details
  const affectedAssets = assets.filter(a => risk.affectedAssetIds.includes(a.id));
  
  res.json({
    ...risk,
    affectedAssetsDetails: affectedAssets,
    relatedAlerts: alerts.filter(a => risk.affectedAssetIds.includes(a.relatedAssetId)).slice(0, 5),
  });
});

// ============================================================================
// ATTACK SIMULATOR ENDPOINTS
// ============================================================================

// Simulate attack for a risk
app.get('/api/simulator/:riskId', (req, res) => {
  const simulation = simulateAttack(req.params.riskId);
  
  if (!simulation) {
    return res.status(404).json({ error: 'Risk not found for simulation' });
  }
  
  res.json(simulation);
});

// Get all MITRE tactics
app.get('/api/simulator/mitre/tactics', (req, res) => {
  res.json({
    tactics: mitreTactics,
    total: mitreTactics.length,
  });
});

// ============================================================================
// EXECUTIVE SUMMARY ENDPOINTS
// ============================================================================

// Get executive summary
app.get('/api/executive/summary', (req, res) => {
  res.json(calculateExecutiveSummary());
});

// Get quarterly report data
app.get('/api/executive/quarterly', (req, res) => {
  const summary = calculateExecutiveSummary();
  
  res.json({
    quarter: 'Q1 2026',
    overallRiskScore: summary.overallRiskScore,
    previousQuarterScore: summary.overallRiskScore - randomInRange(-5, 8),
    keyFindings: [
      'Ransomware threats increased 23% compared to Q4 2025',
      'Mean time to detect improved by 15 minutes',
      'Cloud security posture strengthened after S3 remediation',
      'Phishing simulation success rate decreased to 12%',
    ],
    recommendations: [
      { priority: 'Critical', item: 'Implement zero-trust network architecture' },
      { priority: 'High', item: 'Enhance API security monitoring' },
      { priority: 'Medium', item: 'Expand security awareness training' },
    ],
    complianceStatus: summary.complianceStatus,
    financialSummary: summary.potentialFinancialImpact,
  });
});

// ============================================================================
// ADDITIONAL DASHBOARD COMPONENT ENDPOINTS
// ============================================================================

app.get('/api/threat-insights', (req, res) => {
  res.json(getDashboardData().threatInsights);
});

app.get('/api/department-heatmap', (req, res) => {
  res.json(getDashboardData().departmentHeatmap);
});

app.get('/api/risk-trend', (req, res) => {
  res.json(getDashboardData().riskTrend);
});

app.get('/api/vulnerabilities', (req, res) => {
  res.json(getDashboardData().vulnerabilities);
});

app.get('/api/recommended-actions', (req, res) => {
  res.json(getDashboardData().recommendedActions);
});

// ============================================================================
// ERROR HANDLING
// ============================================================================

app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    message: err.message,
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: `Endpoint ${req.method} ${req.path} not found`,
    availableEndpoints: [
      'GET /api/health',
      'GET /api/dashboard',
      'GET /api/kpis',
      'GET /api/assets',
      'GET /api/assets/:id',
      'GET /api/alerts',
      'GET /api/alerts/recent',
      'GET /api/risks',
      'GET /api/risks/top',
      'GET /api/risks/:id',
      'GET /api/simulator/:riskId',
      'GET /api/simulator/mitre/tactics',
      'GET /api/executive/summary',
      'GET /api/executive/quarterly',
      'GET /api/threat-insights',
      'GET /api/department-heatmap',
      'GET /api/risk-trend',
      'GET /api/vulnerabilities',
      'GET /api/recommended-actions',
    ],
  });
});

// ============================================================================
// START SERVER
// ============================================================================

app.listen(PORT, () => {
  console.log('\n' + '='.repeat(60));
  console.log('🛡️  RiskLens AI - Threat Intelligence Platform Backend');
  console.log('='.repeat(60));
  console.log(`\n🚀 Server running on http://localhost:${PORT}`);
  console.log(`📊 Dashboard API: http://localhost:${PORT}/api/dashboard`);
  console.log(`🎯 Risks API: http://localhost:${PORT}/api/risks`);
  console.log(`⚠️  Alerts API: http://localhost:${PORT}/api/alerts`);
  console.log(`🖥️  Assets API: http://localhost:${PORT}/api/assets`);
  console.log(`💼 Executive API: http://localhost:${PORT}/api/executive/summary`);
  console.log(`🎮 Simulator API: http://localhost:${PORT}/api/simulator/:riskId`);
  console.log('\n' + '='.repeat(60));
  console.log(`\n📈 Loaded ${assets.length} assets, ${alerts.length} alerts, ${risks.length} risks`);
  console.log('🔄 Alerts auto-regenerate every 5 minutes for real-time simulation\n');
});
