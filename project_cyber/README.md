# 🛡️ Contexta

## Autonomous Context-Aware Threat Intelligence & Business Risk Platform

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/Next.js-14-black?style=for-the-badge&logo=next.js" alt="Next.js">
  <img src="https://img.shields.io/badge/FastAPI-0.100+-green?style=for-the-badge&logo=fastapi" alt="FastAPI">
  <img src="https://img.shields.io/badge/PostgreSQL-15+-blue?style=for-the-badge&logo=postgresql" alt="PostgreSQL">
  <img src="https://img.shields.io/badge/Google%20Gemini-AI-orange?style=for-the-badge&logo=google" alt="Gemini">
</p>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [System Workflow](#system-workflow)
- [Core Components](#core-components)
  - [Multi-Agent SOC System](#1-multi-agent-soc-system)
  - [BWVS Risk Scoring](#2-bwvs-risk-scoring-engine)
  - [Digital Twin Network](#3-digital-twin-network-simulation)
  - [Private Blockchain Ledger](#4-private-blockchain-ledger)
  - [CVE Feed Collector](#5-cve-feed-collector)
  - [Playbook Engine](#6-playbook-engine)
- [Data Flow Diagrams](#data-flow-diagrams)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
- [API Reference](#api-reference)
- [Project Structure](#project-structure)

---

## 🎯 Overview

**Contexta** is an enterprise-grade Security Operations Center (SOC) platform that combines AI-powered multi-agent analysis, custom risk scoring (BWVS), network topology simulation, and immutable audit logging to provide context-aware threat intelligence and business risk assessment.

### Key Capabilities

| Feature                    | Description                                                                 |
| -------------------------- | --------------------------------------------------------------------------- |
| 🤖 **AI-Powered Analysis** | Multi-agent system with specialized roles for comprehensive threat analysis |
| 📊 **BWVS Scoring**        | Business-Weighted Vulnerability Scoring that considers operational context  |
| 🌐 **Digital Twin**        | Network topology simulation for attack path analysis                        |
| ⛓️ **Blockchain Ledger**   | Immutable audit trail for compliance and forensics                          |
| 🔄 **Automated Response**  | Playbook-driven incident response workflows                                 |
| 📡 **CVE Intelligence**    | Real-time vulnerability feed from CISA KEV and NVD                          |

---

## 🏗️ Architecture

### High-Level System Architecture

```mermaid
graph TB
    subgraph Frontend["🖥️ Frontend (Next.js 14)"]
        UI[Dashboard UI]
        EXEC[Executive View]
        ATTACK[Attack Simulator]
        ALERTS[Alert Feed]
    end

    subgraph Backend["⚙️ Backend (FastAPI)"]
        API[API Gateway]

        subgraph Agents["🤖 Multi-Agent System"]
            ORCH[Orchestrator]
            AN[Analyst Agent]
            INT[Intel Agent]
            FOR[Forensics Agent]
            BUS[Business Agent]
            RES[Response Agent]
        end

        subgraph Engines["🔧 Core Engines"]
            BWVS[BWVS Calculator]
            TWIN[Digital Twin]
            LEDGER[Blockchain Ledger]
            PLAY[Playbook Engine]
        end

        subgraph Services["📦 Services"]
            CVE[CVE Service]
            RISK[Risk Service]
            INC[Incident Service]
            ASSET[Asset Service]
        end
    end

    subgraph External["🌍 External"]
        GEMINI[Google Gemini AI]
        CISA[CISA KEV Feed]
        NVD[NVD Database]
    end

    subgraph Storage["💾 Data Layer"]
        PG[(PostgreSQL)]
        REDIS[(Redis Cache)]
    end

    Frontend --> API
    API --> Agents
    API --> Engines
    API --> Services

    ORCH --> AN & INT & FOR & BUS & RES
    AN & INT & FOR & BUS & RES --> GEMINI

    CVE --> CISA & NVD
    Services --> PG
    Services --> REDIS
    Engines --> PG
```

---

## 🔄 System Workflow

### Complete Incident Analysis Pipeline

```mermaid
sequenceDiagram
    autonumber
    participant U as User/SIEM
    participant API as API Gateway
    participant INC as Incident Service
    participant ORCH as Orchestrator
    participant AN as Analyst Agent
    participant INT as Intel Agent
    participant FOR as Forensics Agent
    participant BUS as Business Agent
    participant RES as Response Agent
    participant BWVS as BWVS Engine
    participant TWIN as Digital Twin
    participant LEDGER as Blockchain
    participant PLAY as Playbook

    U->>API: New Incident/Alert
    API->>INC: Create Incident
    INC->>LEDGER: Log: incident_created

    rect rgb(200, 220, 250)
        Note over ORCH,RES: Parallel Multi-Agent Analysis
        INC->>ORCH: Request Analysis
        par Agent Analysis
            ORCH->>AN: Analyze (Triage)
            ORCH->>INT: Analyze (CTI)
            ORCH->>FOR: Analyze (Evidence)
            ORCH->>BUS: Analyze (Impact)
            ORCH->>RES: Analyze (Response)
        end
        AN-->>ORCH: Security Analysis
        INT-->>ORCH: Threat Intel
        FOR-->>ORCH: Forensic Report
        BUS-->>ORCH: Business Impact
        RES-->>ORCH: Response Plan
    end

    ORCH->>ORCH: Generate Consensus
    ORCH->>LEDGER: Log: consensus_generated

    rect rgb(250, 220, 200)
        Note over BWVS,TWIN: Risk Assessment
        ORCH->>BWVS: Calculate Risk Score
        BWVS-->>ORCH: BWVS Score
        ORCH->>TWIN: Analyze Attack Paths
        TWIN-->>ORCH: Blast Radius
    end

    ORCH->>PLAY: Trigger Playbook
    PLAY->>LEDGER: Log: playbook_triggered
    ORCH-->>API: Full Analysis Report
    API-->>U: Response + Actions
```

---

## 🧩 Core Components

### 1. Multi-Agent SOC System

The heart of Contexta is a sophisticated multi-agent system powered by **Google Gemini AI**. Each agent specializes in a specific security domain.

```mermaid
graph TB
    subgraph Orchestrator["🎭 Agent Orchestrator"]
        COORD[Coordinator]
        CONSENSUS[Consensus Engine]
    end

    subgraph Agents["Specialized Agents"]
        AN["🔍 Analyst Agent<br/><i>Security Triage</i>"]
        INT["🌐 Intel Agent<br/><i>Threat Intelligence</i>"]
        FOR["🔬 Forensics Agent<br/><i>Evidence Analysis</i>"]
        BUS["💼 Business Agent<br/><i>Impact Assessment</i>"]
        RES["🚀 Response Agent<br/><i>Action Planning</i>"]
    end

    INCIDENT[Incident Data] --> COORD
    COORD --> AN & INT & FOR & BUS & RES
    AN & INT & FOR & BUS & RES --> CONSENSUS
    CONSENSUS --> REPORT[Consensus Report]

    style AN fill:#e1f5fe
    style INT fill:#fff3e0
    style FOR fill:#f3e5f5
    style BUS fill:#e8f5e9
    style RES fill:#fce4ec
```

#### Agent Responsibilities

| Agent            | Role                              | Key Outputs                                |
| ---------------- | --------------------------------- | ------------------------------------------ |
| **🔍 Analyst**   | Initial triage & classification   | Attack type, vector, severity              |
| **🌐 Intel**     | Threat intelligence & attribution | TTPs, threat actors, IOCs                  |
| **🔬 Forensics** | Evidence analysis                 | Timeline, artifacts, chain of custody      |
| **💼 Business**  | Business impact assessment        | Financial impact, compliance, stakeholders |
| **🚀 Response**  | Response planning                 | Actions, playbooks, resources              |

#### Agent Analysis Flow

```mermaid
flowchart LR
    subgraph Input
        I1[Logs]
        I2[Alerts]
        I3[Context]
    end

    subgraph Processing
        A1[Parse & Classify]
        A2[Enrich with CTI]
        A3[Correlate Events]
        A4[Score Risk]
    end

    subgraph Output
        O1[Classification]
        O2[Recommendations]
        O3[Action Items]
    end

    I1 & I2 & I3 --> A1 --> A2 --> A3 --> A4 --> O1 & O2 & O3
```

---

### 2. BWVS Risk Scoring Engine

**Business-Weighted Vulnerability Score (BWVS)** is a custom risk scoring methodology that enhances traditional CVSS by incorporating business context.

#### BWVS Formula

```
BWVS = (CVSS×0.20 + Exploit×0.20 + Exposure×0.15 + Asset_Crit×0.20 + Business_Impact×0.15 + AI_Relevance×0.10) × 10
```

```mermaid
pie title BWVS Weight Distribution
    "CVSS Score" : 20
    "Exploit Availability" : 20
    "Asset Criticality" : 20
    "Exposure Level" : 15
    "Business Impact" : 15
    "AI Relevance" : 10
```

#### BWVS Calculation Flow

```mermaid
flowchart TB
    subgraph Inputs["📥 Input Factors"]
        CVSS[CVSS Score<br/>0-10]
        EXPLOIT[Exploit Status<br/>0-10]
        EXPOSURE[Exposure Level<br/>0-10]
        ASSET[Asset Criticality<br/>0-10]
        IMPACT[Business Impact<br/>0-10]
        AI[AI Relevance<br/>0-10]
    end

    subgraph Weights["⚖️ Apply Weights"]
        W1["×0.20"]
        W2["×0.20"]
        W3["×0.15"]
        W4["×0.20"]
        W5["×0.15"]
        W6["×0.10"]
    end

    subgraph Calculation["🧮 Calculate"]
        SUM[Sum Weighted Scores]
        MULT["×10"]
        SCORE[Final BWVS<br/>0-100]
    end

    CVSS --> W1 --> SUM
    EXPLOIT --> W2 --> SUM
    EXPOSURE --> W3 --> SUM
    ASSET --> W4 --> SUM
    IMPACT --> W5 --> SUM
    AI --> W6 --> SUM
    SUM --> MULT --> SCORE

    style SCORE fill:#ff6b6b,color:#fff
```

#### Priority Ranking Formula

For the Top-10 Risk Dashboard:

```
Priority = BWVS × Freshness × TrendFactor
```

| Factor          | Formula            | Description                               |
| --------------- | ------------------ | ----------------------------------------- |
| **Freshness**   | `0.5^(age_days/7)` | Exponential decay based on discovery time |
| **TrendFactor** | `1.0 - 2.0`        | Velocity of spread/exploitation           |

#### Risk Level Thresholds

| BWVS Range | Risk Level  | Color  |
| ---------- | ----------- | ------ |
| 80-100     | 🔴 Critical | Red    |
| 60-79      | 🟠 High     | Orange |
| 40-59      | 🟡 Medium   | Yellow |
| 0-39       | 🟢 Low      | Green  |

---

### 3. Digital Twin Network Simulation

The **Digital Twin Engine** uses NetworkX to create a virtual representation of your network infrastructure for attack path analysis.

```mermaid
graph TB
    subgraph DigitalTwin["🌐 Digital Twin Engine"]
        subgraph Network["Network Topology (NetworkX DiGraph)"]
            DMZ[DMZ Server]
            WEB[Web Server]
            FW[Firewall]
            APP[App Server]
            DB[(Database)]
            FILE[File Server]
            DC[Domain Controller]
            BACKUP[Backup Server]
        end

        DMZ --- FW
        FW --- WEB & APP
        WEB --- APP
        APP --- DB & FILE
        DB --- BACKUP
        FILE --- DC
        BACKUP --- DC
    end

    subgraph Analysis["🔍 Analysis Capabilities"]
        BFS[BFS Attack Paths]
        DFS[DFS Attack Paths]
        LATERAL[Lateral Movement]
        BLAST[Blast Radius]
    end

    Network --> BFS & DFS & LATERAL & BLAST
```

#### Attack Path Discovery

```mermaid
flowchart LR
    subgraph BFS["BFS (Breadth-First)"]
        B1[Find Shortest Paths]
        B2[Minimum Hops]
        B3[Emergency Triage]
    end

    subgraph DFS["DFS (Depth-First)"]
        D1[Find ALL Paths]
        D2[Comprehensive Analysis]
        D3[Security Assessment]
    end

    COMP[Compromised Asset] --> BFS & DFS
    BFS --> CRITICAL[Critical Assets]
    DFS --> CRITICAL
```

#### Lateral Movement Simulation

```mermaid
stateDiagram-v2
    [*] --> InitialCompromise
    InitialCompromise --> Reconnaissance
    Reconnaissance --> CredentialHarvest
    CredentialHarvest --> PrivilegeEscalation
    PrivilegeEscalation --> LateralMovement
    LateralMovement --> DataExfiltration
    LateralMovement --> Persistence
    DataExfiltration --> [*]
    Persistence --> LateralMovement
```

---

### 4. Private Blockchain Ledger

Immutable audit logging using a hash chain for complete traceability and tamper detection.

#### Hash Chain Structure

```
hash = SHA256(prev_hash + data)
```

```mermaid
graph LR
    subgraph Genesis["Block 0 (Genesis)"]
        G_H["hash: a1b2c3..."]
        G_P["prev: 0000..."]
        G_D["data: genesis"]
    end

    subgraph Block1["Block 1"]
        B1_H["hash: d4e5f6..."]
        B1_P["prev: a1b2c3..."]
        B1_D["event: incident_created"]
    end

    subgraph Block2["Block 2"]
        B2_H["hash: g7h8i9..."]
        B2_P["prev: d4e5f6..."]
        B2_D["event: analysis_complete"]
    end

    subgraph Block3["Block N"]
        B3_H["hash: j1k2l3..."]
        B3_P["prev: g7h8i9..."]
        B3_D["event: ..."]
    end

    Genesis --> Block1 --> Block2 --> Block3

    style Genesis fill:#4caf50,color:#fff
    style Block1 fill:#2196f3,color:#fff
    style Block2 fill:#2196f3,color:#fff
    style Block3 fill:#9c27b0,color:#fff
```

#### Ledger Event Types

```mermaid
graph TB
    subgraph Events["📋 Event Categories"]
        subgraph Incident["Incident Events"]
            IE1[incident_created]
            IE2[incident_updated]
            IE3[incident_closed]
        end

        subgraph Analysis["Analysis Events"]
            AE1[analysis_started]
            AE2[agent_invoked]
            AE3[consensus_generated]
        end

        subgraph Risk["Risk Events"]
            RE1[risk_calculated]
            RE2[risk_escalated]
            RE3[risk_mitigated]
        end

        subgraph Response["Response Events"]
            RSE1[playbook_triggered]
            RSE2[action_taken]
            RSE3[playbook_completed]
        end
    end
```

---

### 5. CVE Feed Collector

Real-time vulnerability intelligence from authoritative sources.

```mermaid
flowchart LR
    subgraph Sources["🌐 External Sources"]
        CISA[CISA KEV<br/>Known Exploited]
        NVD[NVD<br/>All CVEs]
    end

    subgraph Collector["📥 CVE Collector"]
        FETCH[Fetch CVEs]
        PARSE[Parse & Normalize]
        ENRICH[Enrich Data]
        STORE[Store in DB]
    end

    subgraph Enrichment["✨ Enrichment"]
        EXPLOIT[Exploit Availability]
        MITRE[MITRE Mapping]
        CONTEXT[Context Tags]
    end

    CISA & NVD --> FETCH --> PARSE --> ENRICH --> STORE
    EXPLOIT & MITRE & CONTEXT --> ENRICH
```

---

### 6. Playbook Engine

Automated response workflows with step-by-step execution.

```mermaid
flowchart TB
    subgraph Trigger["🎯 Trigger"]
        INCIDENT[Incident]
        SEVERITY[Severity Check]
    end

    subgraph Playbook["📋 Playbook Execution"]
        SELECT[Select Playbook]

        subgraph Steps["Execution Steps"]
            S1[Step 1: Isolate]
            S2[Step 2: Collect Evidence]
            S3[Step 3: Analyze]
            S4[Step 4: Remediate]
            S5[Step 5: Verify]
        end

        TIMEOUT{Timeout?}
        ESCALATE[Escalate]
    end

    subgraph Complete["✅ Completion"]
        NOTIFY[Send Notifications]
        LOG[Log to Ledger]
        CLOSE[Close Incident]
    end

    INCIDENT --> SEVERITY --> SELECT
    SELECT --> S1 --> S2 --> S3 --> S4 --> S5
    S1 & S2 & S3 & S4 --> TIMEOUT
    TIMEOUT -->|Yes| ESCALATE
    TIMEOUT -->|No| S5
    S5 --> NOTIFY --> LOG --> CLOSE
```

---

## 📊 Data Flow Diagrams

### Complete Data Flow

```mermaid
flowchart TB
    subgraph DataSources["📡 Data Sources"]
        SIEM[SIEM Logs]
        CVE_FEED[CVE Feeds]
        ASSETS[Asset Inventory]
        USER_INPUT[User Input]
    end

    subgraph Processing["⚙️ Processing Layer"]
        INGEST[Data Ingestion]
        NORMALIZE[Normalization]
        CORRELATE[Correlation Engine]
    end

    subgraph Analysis["🧠 Analysis Layer"]
        AGENTS[Multi-Agent Analysis]
        BWVS_CALC[BWVS Calculation]
        TWIN_SIM[Digital Twin Simulation]
    end

    subgraph Storage["💾 Storage Layer"]
        PG[(PostgreSQL)]
        REDIS[(Redis)]
        LEDGER[(Blockchain)]
    end

    subgraph Output["📤 Output Layer"]
        DASH[Dashboard]
        ALERTS[Alerts]
        REPORTS[Reports]
        API_OUT[API Response]
    end

    DataSources --> Processing --> Analysis
    Analysis --> Storage
    Storage --> Output

    INGEST --> PG
    CORRELATE --> REDIS
    AGENTS --> LEDGER
```

### Request/Response Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant N as Next.js Frontend
    participant F as FastAPI Backend
    participant P as PostgreSQL
    participant R as Redis
    participant G as Gemini AI

    C->>N: Dashboard Request
    N->>F: API Call
    F->>R: Check Cache

    alt Cache Hit
        R-->>F: Cached Data
    else Cache Miss
        F->>P: Query Database
        P-->>F: Data
        F->>R: Update Cache
    end

    F->>G: AI Analysis Request
    G-->>F: Analysis Result
    F-->>N: JSON Response
    N-->>C: Rendered Dashboard
```

---

## 🛠️ Tech Stack

### Backend

| Technology         | Purpose                  |
| ------------------ | ------------------------ |
| **Python 3.11+**   | Core language            |
| **FastAPI**        | Async web framework      |
| **SQLAlchemy 2.0** | Async ORM                |
| **PostgreSQL**     | Primary database         |
| **Redis**          | Caching & rate limiting  |
| **Google Gemini**  | AI/LLM provider          |
| **NetworkX**       | Graph-based digital twin |
| **APScheduler**    | Background tasks         |
| **Docker**         | Containerization         |

### Frontend

| Technology       | Purpose            |
| ---------------- | ------------------ |
| **Next.js 14**   | React framework    |
| **TypeScript**   | Type safety        |
| **TailwindCSS**  | Styling            |
| **Recharts**     | Data visualization |
| **Lucide React** | Icons              |

---

## 🚀 Getting Started

### Prerequisites

- Python 3.11+
- Node.js 18+
- PostgreSQL 15+
- Redis 7+
- Docker (optional)

### Quick Start

#### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/contexta.git
cd contexta
```

#### 2. Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your configuration

# Run database migrations
alembic upgrade head

# Start the server
uvicorn app.main:app --reload --port 8000
```

#### 3. Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

#### 4. Access the Application

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs

### Docker Deployment

```bash
cd backend
docker-compose up -d
```

---

## 📚 API Reference

### Core Endpoints

| Method | Endpoint                         | Description           |
| ------ | -------------------------------- | --------------------- |
| `POST` | `/api/v1/incidents`              | Create new incident   |
| `GET`  | `/api/v1/incidents/{id}`         | Get incident details  |
| `POST` | `/api/v1/incidents/{id}/analyze` | Trigger full analysis |
| `GET`  | `/api/v1/risks/top10`            | Get top 10 risks      |
| `GET`  | `/api/v1/cves`                   | List CVEs             |
| `POST` | `/api/v1/twin/simulate`          | Run attack simulation |
| `GET`  | `/api/v1/ledger/chain`           | Get audit log         |
| `POST` | `/api/v1/playbooks/{id}/execute` | Execute playbook      |

### API Documentation

Full interactive API documentation available at:

- **Swagger UI**: `/docs`
- **ReDoc**: `/redoc`

---

## 📁 Project Structure

```
project_cyber/
├── 📁 backend/                    # FastAPI Backend
│   ├── 📁 app/
│   │   ├── 📁 agents/             # Multi-agent system
│   │   │   ├── orchestrator.py    # Agent coordinator
│   │   │   ├── analyst.py         # Security analyst agent
│   │   │   ├── intel.py           # Threat intel agent
│   │   │   ├── forensics.py       # Forensics agent
│   │   │   ├── business.py        # Business impact agent
│   │   │   └── response.py        # Response agent
│   │   ├── 📁 api/                # API routes
│   │   ├── 📁 ingestion/          # Data collectors
│   │   │   ├── cve_collector.py   # CVE feed collector
│   │   │   └── log_generator.py   # SIEM log generator
│   │   ├── 📁 ledger/             # Blockchain ledger
│   │   │   └── chain.py           # Hash chain implementation
│   │   ├── 📁 models/             # Database models
│   │   ├── 📁 risk_engine/        # Risk scoring
│   │   │   ├── bwvs.py            # BWVS calculator
│   │   │   └── ranking.py         # Priority ranking
│   │   ├── 📁 schemas/            # Pydantic schemas
│   │   ├── 📁 services/           # Business logic
│   │   ├── 📁 twin/               # Digital twin
│   │   │   └── engine.py          # NetworkX simulation
│   │   └── main.py                # Application entry point
│   ├── 📁 docs/                   # Documentation
│   ├── 📁 migrations/             # Alembic migrations
│   ├── 📁 playbooks/              # Response playbooks
│   └── 📁 tests/                  # Test suite
│
├── 📁 frontend/                   # Next.js Frontend
│   ├── 📁 app/                    # Next.js app router
│   ├── 📁 components/             # React components
│   │   ├── Dashboard.tsx          # Main dashboard
│   │   ├── AttackSimulator.tsx    # Attack simulation UI
│   │   ├── ExecutiveView.tsx      # Executive dashboard
│   │   └── 📁 dashboard/          # Dashboard widgets
│   └── 📁 contexts/               # React contexts
│
└── README.md                      # This file
```

---

## 📖 Additional Documentation

- [Agent System Documentation](backend/docs/AGENTS.md)
- [BWVS Scoring Methodology](backend/docs/BWVS.md)
- [Digital Twin Engine](backend/docs/DIGITAL_TWIN.md)
- [Blockchain Ledger](backend/docs/LEDGER.md)

---

## 🔒 Security Considerations

- All API endpoints require authentication
- Role-based access control (RBAC)
- Immutable audit logging via blockchain
- Rate limiting via Redis
- Input validation and sanitization
- CORS configuration

---

## 📜 License

Proprietary - Contexta Platform

---

<p align="center">
  <b>Built with ❤️ for Security Operations Centers</b>
</p>
