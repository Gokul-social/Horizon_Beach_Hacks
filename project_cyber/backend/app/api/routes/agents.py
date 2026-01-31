"""
Contexta Backend - AI Agents Routes

Provides endpoints for multi-agent analysis and orchestration.
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.database import get_db
from app.agents.orchestrator import get_orchestrator
from app.services.incident_service import IncidentService
from app.auth.jwt import get_current_active_user, TokenData
from app.ledger.chain import get_ledger, LedgerEventTypes

logger = structlog.get_logger()
router = APIRouter()


@router.post("/analyze/{incident_id}")
async def analyze_incident(
    incident_id: str,
    risk_title: Optional[str] = Query(None),
    agents: Optional[List[str]] = Query(
        None,
        description="Specific agents to use (analyst, intel, forensics, business, response). Uses all if not specified."
    ),
    current_user: Optional[TokenData] = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Run AI agent analysis on an incident.
    """
    
    # DEMO MODE: Bypass auth and logic if incident_id is 'demo'
    if incident_id == "demo":
        import asyncio
        from datetime import datetime, timedelta
        import random
        
        # Simulate processing time
        await asyncio.sleep(1.5)
        
        current_time_obj = datetime.now()
        
        def get_time(offset_seconds):
            return (current_time_obj + timedelta(seconds=offset_seconds)).strftime("%H:%M:%S")

        # Dynamic discussion generation based on risk_title
        title = risk_title or "Detected Security Event"
        title_lower = title.lower()
        
        discussion = []
        
        # Helper functions for dynamic data
        def rand_ip():
            return f"{random.randint(10, 192)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        
        def rand_user():
            return random.choice(['j.doe', 'm.smith', 'a.jones', 'c.lee', 'finance_admin', 'sys_operator'])
            
        def rand_file():
            return random.choice(['payroll_2025.db', 'client_list.xlsx', 'passwords.txt', 'network_map.vsd', 'marketing_budget.pptx'])

        def rand_money():
            return f"${random.randint(10, 200)}k/hour"

        if "ransomware" in title_lower or "lockbit" in title_lower:
            analyst_msgs = [
                f"Team, urgent alert! 🚨 I'm seeing a massive spike in file writes on the Finance VLAN. {random.randint(300, 900)} files encrypted in the last minute. It looks like ransomware.",
                f"Critical Alert: Anomaly detection system has flagged simultaneous file encryption on {random.randint(5, 15)} endpoints. Signature resembles LockBit.",
                f"I'm detecting high-IOPS activity matching ransomware behavior on subnet 10.20.5.x. Multiple users reporting 'cannot open files'."
            ]
            intel_msgs = [
                f"On it. Checking the file artifacts... Okay, the extension signature matches **LockBit 3.0**. They've been active in our sector this week.",
                f"Threat Intelligence Feed correlation confirms this is **BlackBase** or **LockBit** variant. C2 traffic is going to {rand_ip()}.",
                f"Confirmed. This hash was seen 4 hours ago in a bulletin for the Financial sector. It's a double-extortion campaign."
            ]
            forensics_msgs = [
                f"Tracing the entry point... Found it. Reviewing the logs on Server-DB-04. Someone brute-forced RDP for user '{rand_user()}'. I see a 'Mimikatz' dump in the temp folder.",
                f"Patient Zero identified. Workstation {rand_ip()} executed a malicious macro. I found a PowerShell script running in memory.",
                f"Analysis of the dropped binary shows it kills SQL services before encrypting. It entered via an unpatched Exchange vulnerability."
            ]
            business_msgs = [
                f"Calculated impact: That server holds the {random.choice(['payroll', 'customer', 'legal'])} data. If we lose it, we face severe compliance fines. Impact: {rand_money()}.",
                f"Stop the bleeding! That segment processes ${random.randint(1, 10)}M in daily transactions. We cannot afford downtime > 1 hour.",
                f"Legal is asking if we need to declare a breach. If data left the building, we have 72 hours to notify regulators."
            ]
            
            discussion = [
                {"agent": "analyst", "message": random.choice(analyst_msgs), "timestamp": get_time(0)},
                {"agent": "intel", "message": random.choice(intel_msgs), "timestamp": get_time(3)},
                {"agent": "forensics", "message": random.choice(forensics_msgs), "timestamp": get_time(7)},
                {"agent": "business", "message": random.choice(business_msgs), "timestamp": get_time(12)},
                {"agent": "analyst", "message": "Isolating the infected subnet now to prevent lateral movement.", "timestamp": get_time(15)},
                {"agent": "forensics", "message": "Capturing memory dump for decryptor extraction.", "timestamp": get_time(18)}
            ]

        elif "phishing" in title_lower:
            domain = f"login-{random.choice(['secure', 'update', 'verify', 'support'])}-microsoft.com"
            analyst_msgs = [
                 f"Hey Intel, are you seeing this domain '{domain}'? {random.randint(10, 50)} users just clicked it from an email labeled 'Urgent Invoice'.",
                 f"Phishing wave detected. Email gateway let through 200 emails with subject 'Account Verification'. Users are clicking link to '{domain}'.",
                 f"User '{rand_user()}' reported a suspicious login page. I'm seeing traffic to '{domain}'."
            ]
            intel_msgs = [
                 f"Checking whois data... It was registered {random.randint(1, 12)} hours ago via NameCheap. Definitely malicious credential harvester.",
                 f"That domain is flagged in OTX. It's associated with 'Cozy Bear' campaigns targeting enterprise credentials.",
                 f"Looks like a Typosquatting attack. The IP resolves to a known phishing host in {random.choice(['Netherlands', 'Russia', 'Vietnam'])}."
            ]
            forensics_msgs = [
                 f"I'm looking at the endpoint logs. {random.randint(2, 5)} users actually entered credentials. I see a POST request with their hashes.",
                 f"Browser history confirms user '{rand_user()}' submitted the form. Session token exfiltration probable.",
                 f"No malware dropped, but they captured MFA tokens via a reverse proxy setup on that site."
            ]
            
            discussion = [
                {"agent": "analyst", "message": random.choice(analyst_msgs), "timestamp": get_time(0)},
                {"agent": "intel", "message": random.choice(intel_msgs), "timestamp": get_time(4)},
                {"agent": "forensics", "message": random.choice(forensics_msgs), "timestamp": get_time(9)},
                {"agent": "business", "message": "We need to force reset those passwords immediately. One of them is a VIP account.", "timestamp": get_time(14)},
                {"agent": "analyst", "message": "Executing 'Account_Compromise_Containment' playbook. Revoking sessions.", "timestamp": get_time(17)}
            ]

        elif "vpn" in title_lower or "unpatched" in title_lower or "cve" in title_lower or "vulnerability" in title_lower:
            cve = f"CVE-202{random.randint(4, 5)}-{random.randint(1000, 9999)}"
            discussion = [
                {
                    "agent": "analyst",
                    "message": f"Critical Alert: Vulnerability Scanner is flagging our VPN gateway for {cve}. It's a 9.8 Severity RCE.",
                    "timestamp": get_time(0)
                },
                {
                    "agent": "intel",
                    "message": f"I confirm. Exploit code was just published on Twitter/X. Threat actors are actively scanning for this. We are exposed.",
                    "timestamp": get_time(4)
                },
                {
                    "agent": "forensics",
                    "message": f"Checking firewall logs... I see connection attempts from {rand_ip()} trying to trigger the buffer overflow.",
                    "timestamp": get_time(8)
                },
                 {
                    "agent": "analyst",
                    "message": "We need to patch immediately. The attack surface is too wide to block IPs.",
                    "timestamp": get_time(12)
                },
                {
                    "agent": "business",
                    "message": "It's mid-day. Patching takes down the remote sales team. Can we wait 4 hours?",
                    "timestamp": get_time(15)
                },
                {
                    "agent": "intel",
                    "message": "Too risky. If they get in, they deploy ransomware. Downtime cost < Breach cost.",
                    "timestamp": get_time(18)
                },
                {
                    "agent": "business",
                    "message": "Authorized. Deploy the hotfix now.",
                    "timestamp": get_time(21)
                }
            ]

        elif "insider" in title_lower or "exfiltration" in title_lower:
            user = rand_user()
            file = rand_file()
            discussion = [
                {
                    "agent": "analyst",
                    "message": f"DLP Alert: User '{user}' is uploading huge files to personal cloud. {random.randint(2, 10)}GB transferred in 10 minutes.",
                    "timestamp": get_time(0)
                },
                {
                    "agent": "intel",
                    "message": f"Context check: '{user}' just submitted a resignation letter 2 days ago. Flight risk confirmed.",
                    "timestamp": get_time(3)
                },
                {
                    "agent": "forensics",
                    "message": f"I've identified the files. It's '{file}' and the customer database. This isn't personal data.",
                    "timestamp": get_time(7)
                },
                {
                    "agent": "analyst",
                    "message": "I'm killing the session and disabling the account. Access revoked.",
                    "timestamp": get_time(11)
                },
                {
                    "agent": "business",
                    "message": "Notify Legal. We need to send a cease & desist. That intellectual property is valued at $5M+.",
                    "timestamp": get_time(14)
                }
            ]

        elif "ddos" in title_lower or "denial" in title_lower:
            gbps = random.randint(40, 120)
            discussion = [
                {
                    "agent": "analyst",
                    "message": f"Traffic spike! {gbps} Gbps hitting the main load balancer. API latency is through the roof.",
                    "timestamp": get_time(0)
                },
                {
                    "agent": "forensics",
                    "message": "It's volumetric UDP flood. Reflection info showing DNS and NTP amplification vectors.",
                    "timestamp": get_time(4)
                },
                 {
                    "agent": "intel",
                    "message": "Botnet signature matches. This looks like a paid 'Stresser' attack hired by a competitor.",
                    "timestamp": get_time(8)
                },
                {
                    "agent": "business",
                    "message": f"Our SLAs are breaching. Costs are racking up at {rand_money()}. Fix it!",
                    "timestamp": get_time(12)
                },
                 {
                    "agent": "analyst",
                    "message": "Activating CloudFlare 'Under Attack' mode. Rerouting traffic.",
                    "timestamp": get_time(15)
                },
                {
                    "agent": "business",
                    "message": "Traffic normalizing. Good work.",
                    "timestamp": get_time(17)
                }
            ]

        elif "s3" in title_lower or "cloud" in title_lower or "misconfigured" in title_lower:
            discussion = [
                {
                    "agent": "analyst",
                    "message": "CSPM Alert: S3 bucket 'production-data' was just made PUBLIC. ⚠️",
                    "timestamp": get_time(0)
                },
                {
                    "agent": "forensics",
                    "message": f"CloudTrail says user '{rand_user()}' made the change via CLI. Likely an accident.",
                    "timestamp": get_time(4)
                },
                {
                    "agent": "intel",
                    "message": "Public scanners are already hitting it. I see connections from unknown IPs.",
                    "timestamp": get_time(8)
                },
                {
                    "agent": "analyst",
                    "message": "Remediated. Permissions reverted to Private. Access blocked.",
                    "timestamp": get_time(11)
                },
                {
                    "agent": "business",
                    "message": "We need to audit what was accessed. If PII was leaked, we have regulatory reporting duties.",
                    "timestamp": get_time(14)
                }
            ]

        elif "policy" in title_lower or "password" in title_lower or "shadow" in title_lower:
            discussion = [
                {
                    "agent": "analyst",
                    "message": "Audit finding: 30% of accounts have weak passwords. Also detecting unauthorized Notion usage.",
                    "timestamp": get_time(0)
                },
                 {
                    "agent": "intel",
                    "message": "Those Notion pages are indexed on Google. I found our Q3 roadmap publicly visible.",
                    "timestamp": get_time(5)
                },
                {
                    "agent": "business",
                    "message": "Take it down immediately! That contains unreleased product features.",
                    "timestamp": get_time(9)
                },
                {
                    "agent": "analyst",
                    "message": "Blocking Notion at the CASB level. Enforcing MFA for all users tonight.",
                    "timestamp": get_time(13)
                }
            ]

        elif "ssl" in title_lower or "certificate" in title_lower:
            discussion = [
                {
                    "agent": "analyst",
                    "message": "Alert: SSL Certificate for api.contexta.com expires in 12 hours. Renewal bot failed.",
                    "timestamp": get_time(0)
                },
                {
                    "agent": "forensics",
                    "message": "DNS challenge failed again. The TXT record is missing from the zone.",
                    "timestamp": get_time(5)
                },
                {
                    "agent": "business",
                    "message": "If that cert dies, the mobile app dies. 50k users affected. Priority One.",
                    "timestamp": get_time(10)
                },
                {
                    "agent": "analyst",
                    "message": "Manually pushing the cert update now.",
                    "timestamp": get_time(14)
                }
            ]

        else:
            # Fallback generic formatted for 4 agents
            discussion = [
                {
                    "agent": "analyst",
                    "message": f"Team, correlating multiple alerts on '{title}'. Traffic volume is abnormal.",
                    "timestamp": get_time(0)
                },
                {
                    "agent": "intel",
                    "message": "I'm checking threat feeds... No direct matches for this specific signature yet, but it resembles known C2 behavior.",
                    "timestamp": get_time(3)
                },
                 {
                    "agent": "analyst",
                    "message": "Forensics, can you check the host?",
                    "timestamp": get_time(6)
                },
                {
                    "agent": "forensics",
                    "message": "Checking... Yes, found a suspicious process spawning from svchost. It's beaconing out to an unknown IP.",
                    "timestamp": get_time(9)
                },
                {
                    "agent": "business",
                    "message": "What system is this?",
                    "timestamp": get_time(12)
                },
                 {
                    "agent": "analyst",
                    "message": "It's the backup customer support portal.",
                    "timestamp": get_time(14)
                },
                {
                    "agent": "business",
                    "message": "Okay, non-critical for revenue, but protect the data. Isolate it.",
                    "timestamp": get_time(17)
                }
            ]

        return {
            "status": "completed",
            "incident_id": "demo",
            "discussion": discussion
        }

    # Normal flow requires auth
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )

    # Get incident data
    incident_service = IncidentService(db)
    incident = await incident_service.get_incident(incident_id)
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    # Prepare incident data for agents
    incident_data = {
        "id": str(incident.id),
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "type": incident.incident_type,
        "status": incident.status,
        "created_at": incident.created_at.isoformat() if incident.created_at else None
    }
    
    # Get orchestrator
    orchestrator = get_orchestrator()
    
    # Run analysis
    if agents:
        # Targeted analysis with specific agents
        valid_agents = ["analyst", "intel", "forensics", "business", "response"]
        invalid = [a for a in agents if a not in valid_agents]
        if invalid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid agent types: {invalid}. Valid options: {valid_agents}"
            )
        
        result = await orchestrator.targeted_analysis(
            incident_data=incident_data,
            agent_types=agents
        )
    else:
        # Full multi-agent analysis
        result = await orchestrator.full_analysis(incident_data=incident_data)
    
    # Log to ledger
    ledger = get_ledger()
    ledger.add_block(
        event_type=LedgerEventTypes.ANALYSIS_COMPLETE,
        data={
            "incident_id": incident_id,
            "agents_used": agents or ["all"],
            "consensus_severity": result.get("consensus_report", {}).get("consensus_severity")
        },
        actor=current_user.user_id
    )
    
    logger.info(
        "Agent analysis complete",
        incident_id=incident_id,
        agents=agents or "all",
        user_id=current_user.user_id
    )
    
    return result


@router.get("/status")
async def get_agent_status(
    current_user: TokenData = Depends(get_current_active_user)
):
    """
    Get status of all AI agents.
    """
    orchestrator = get_orchestrator()
    
    return {
        "agents": {
            name: {
                "name": agent.name,
                "type": agent.agent_type,
                "status": "active"
            }
            for name, agent in orchestrator.agents.items()
        },
        "orchestrator_status": "active"
    }


@router.post("/query")
async def query_agent(
    agent_type: str,
    query: str,
    context: Optional[Dict[str, Any]] = None,
    current_user: TokenData = Depends(get_current_active_user)
):
    """
    Query a specific agent directly with custom input.
    
    - **agent_type**: Agent to query (analyst, intel, forensics, business, response)
    - **query**: Question or analysis request
    - **context**: Optional additional context
    """
    valid_agents = ["analyst", "intel", "forensics", "business", "response"]
    
    if agent_type not in valid_agents:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid agent type. Must be one of: {valid_agents}"
        )
    
    orchestrator = get_orchestrator()
    agent = orchestrator.agents[agent_type]
    
    # Create pseudo-incident data from query
    incident_data = {
        "id": "direct-query",
        "type": "custom_query",
        "severity": "medium",
        "description": query
    }
    
    result = await agent.analyze(incident_data, context)
    
    # Log to ledger
    ledger = get_ledger()
    ledger.add_block(
        event_type=LedgerEventTypes.AGENT_INVOKED,
        data={
            "agent_type": agent_type,
            "query_length": len(query),
            "has_context": context is not None
        },
        actor=current_user.user_id
    )
    
    return result


@router.get("/capabilities")
async def get_agent_capabilities(
    current_user: TokenData = Depends(get_current_active_user)
):
    """
    Get capabilities of all AI agents.
    """
    return {
        "agents": [
            {
                "type": "analyst",
                "name": "Security Analyst",
                "capabilities": [
                    "Log analysis and correlation",
                    "Attack pattern recognition",
                    "Initial triage and classification",
                    "Severity assessment"
                ]
            },
            {
                "type": "intel",
                "name": "Threat Intelligence Specialist",
                "capabilities": [
                    "Threat actor attribution",
                    "TTP mapping to MITRE ATT&CK",
                    "IOC extraction and correlation",
                    "Threat landscape assessment"
                ]
            },
            {
                "type": "forensics",
                "name": "Digital Forensics Analyst",
                "capabilities": [
                    "Evidence analysis",
                    "Timeline reconstruction",
                    "Artifact examination",
                    "Chain of custody documentation"
                ]
            },
            {
                "type": "business",
                "name": "Business Impact Analyst",
                "capabilities": [
                    "Financial impact assessment",
                    "Operational impact analysis",
                    "Regulatory compliance checking",
                    "Stakeholder communication planning"
                ]
            },
            {
                "type": "response",
                "name": "Response Coordinator",
                "capabilities": [
                    "Incident response planning",
                    "Playbook recommendations",
                    "Resource coordination",
                    "Recovery planning"
                ]
            }
        ],
        "orchestrator": {
            "name": "Multi-Agent Orchestrator",
            "capabilities": [
                "Parallel agent execution",
                "Consensus generation",
                "Cross-agent validation",
                "Prioritized recommendations"
            ]
        }
    }
