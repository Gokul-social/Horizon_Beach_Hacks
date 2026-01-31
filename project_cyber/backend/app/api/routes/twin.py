"""
Contexta Backend - Digital Twin Routes

Provides endpoints for digital twin simulation and attack path analysis.
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query, Body
import structlog

from app.twin.engine import get_twin_engine
from app.auth.jwt import get_current_user_optional, TokenData

logger = structlog.get_logger()
router = APIRouter()


@router.get("/stats")
async def get_twin_stats(
    current_user: Optional[TokenData] = Depends(get_current_user_optional)
):
    """
    Get digital twin network statistics.
    """
    twin = get_twin_engine()
    
    # Initialize sample network if empty
    if twin.graph.number_of_nodes() == 0:
        twin.initialize_sample_network()
    
    return twin.get_network_stats()


@router.get("/export")
async def export_twin(
    current_user: Optional[TokenData] = Depends(get_current_user_optional)
):
    """
    Export the digital twin graph data.
    """
    twin = get_twin_engine()
    
    return twin.export_to_dict()


@router.post("/import")
async def import_twin(
    data: Dict[str, Any] = Body(...),
    current_user: Optional[TokenData] = Depends(get_current_user_optional)
):
    """
    Import digital twin graph data.
    """
    twin = get_twin_engine()
    
    twin.import_from_dict(data)
    
    logger.info(
        "Digital twin imported",
        user_id=current_user.user_id,
        nodes=twin.graph.number_of_nodes()
    )
    
    return {"message": "Digital twin imported", "stats": twin.get_network_stats()}


@router.post("/assets")
async def add_asset_to_twin(
    asset_id: str,
    asset_type: str,
    name: str,
    criticality: str = "medium",
    zone: str = "internal",
    metadata: Optional[Dict[str, Any]] = None,
    current_user: Optional[TokenData] = Depends(get_current_user_optional)
):
    """
    Add an asset to the digital twin.
    """
    twin = get_twin_engine()
    
    twin.add_asset(
        asset_id=asset_id,
        asset_type=asset_type,
        name=name,
        criticality=criticality,
        zone=zone,
        metadata=metadata
    )
    
    return {"message": "Asset added", "asset_id": asset_id}


@router.post("/connections")
async def add_connection(
    source_id: str,
    target_id: str,
    connection_type: str = "network",
    protocols: Optional[List[str]] = None,
    bidirectional: bool = False,
    current_user: Optional[TokenData] = Depends(get_current_user_optional)
):
    """
    Add a connection between assets.
    """
    twin = get_twin_engine()
    
    twin.add_connection(
        source_id=source_id,
        target_id=target_id,
        connection_type=connection_type,
        protocols=protocols or ["tcp"],
        bidirectional=bidirectional
    )
    
    return {"message": "Connection added", "source": source_id, "target": target_id}


@router.post("/vulnerabilities")
async def add_vulnerability(
    asset_id: str,
    cve_id: str,
    cvss_score: float,
    exploitable: bool = False,
    network_exploitable: bool = False,
    current_user: Optional[TokenData] = Depends(get_current_user_optional)
):
    """
    Add a vulnerability to an asset in the digital twin.
    """
    twin = get_twin_engine()
    
    twin.add_vulnerability(
        asset_id=asset_id,
        cve_id=cve_id,
        cvss_score=cvss_score,
        exploitable=exploitable,
        network_exploitable=network_exploitable
    )
    
    return {"message": "Vulnerability added", "asset_id": asset_id, "cve_id": cve_id}


@router.get("/attack-paths/bfs")
async def find_attack_paths_bfs(
    start_id: str,
    target_id: str,
    max_depth: int = Query(10, ge=1, le=20),
    current_user: Optional[TokenData] = Depends(get_current_user_optional)
):
    """
    Find attack paths using Breadth-First Search.
    
    BFS finds the shortest paths first, useful for identifying
    the quickest routes an attacker might take.
    """
    twin = get_twin_engine()
    
    paths = twin.find_attack_paths_bfs(
        start_id=start_id,
        target_id=target_id,
        max_depth=max_depth
    )
    
    logger.info(
        "BFS attack paths found",
        start=start_id,
        target=target_id,
        paths_count=len(paths)
    )
    
    return {
        "start": start_id,
        "target": target_id,
        "algorithm": "bfs",
        "paths_found": len(paths),
        "paths": paths[:50]  # Limit response size
    }


@router.get("/attack-paths/dfs")
async def find_attack_paths_dfs(
    start_id: str,
    target_id: str,
    max_depth: int = Query(10, ge=1, le=20),
    current_user: Optional[TokenData] = Depends(get_current_user_optional)
):
    """
    Find attack paths using Depth-First Search.
    
    DFS explores all possible paths, useful for comprehensive
    attack surface analysis.
    """
    twin = get_twin_engine()
    
    paths = twin.find_attack_paths_dfs(
        start_id=start_id,
        target_id=target_id,
        max_depth=max_depth
    )
    
    logger.info(
        "DFS attack paths found",
        start=start_id,
        target=target_id,
        paths_count=len(paths)
    )
    
    return {
        "start": start_id,
        "target": target_id,
        "algorithm": "dfs",
        "paths_found": len(paths),
        "paths": paths[:50]  # Limit response size
    }


@router.post("/simulate/lateral-movement")
async def simulate_lateral_movement(
    initial_compromise: str,
    time_steps: int = Query(10, ge=1, le=100),
    propagation_probability: float = Query(0.3, ge=0.0, le=1.0),
    current_user: Optional[TokenData] = Depends(get_current_user_optional)
):
    """
    Simulate lateral movement from an initial compromise.
    
    Uses a probabilistic model to simulate how an attacker
    might spread through the network over time.
    """
    twin = get_twin_engine()
    
    result = twin.simulate_lateral_movement(
        initial_compromise=initial_compromise,
        time_steps=time_steps,
        propagation_probability=propagation_probability
    )
    
    logger.info(
        "Lateral movement simulation complete",
        initial=initial_compromise,
        compromised=result.get("total_compromised", 0)
    )
    
    return result


@router.get("/blast-radius/{asset_id}")
async def calculate_blast_radius(
    asset_id: str,
    max_hops: int = Query(3, ge=1, le=10),
    current_user: Optional[TokenData] = Depends(get_current_user_optional)
):
    """
    Calculate the blast radius of a compromised asset.
    
    Shows all assets that could be impacted within a certain
    number of network hops.
    """
    twin = get_twin_engine()
    
    result = twin.calculate_blast_radius(
        asset_id=asset_id,
        max_hops=max_hops
    )
    
    return result


@router.get("/critical-paths")
async def find_critical_paths(
    current_user: Optional[TokenData] = Depends(get_current_user_optional)
):
    """
    Find paths that lead to critical assets.
    
    Identifies attack paths from external-facing assets to
    critical internal systems.
    """
    twin = get_twin_engine()
    
    paths = twin.find_critical_paths()
    
    return {
        "critical_paths": paths,
        "total_paths": len(paths)
    }


@router.post("/simulate")
async def run_attack_simulation(
    attack_type: str = Query(..., description="Type of attack: ransomware, apt, insider, ddos"),
    entry_point: str = Query(..., description="Initial entry point asset ID"),
    target: Optional[str] = Query(None, description="Target asset ID (optional)"),
    current_user: Optional[TokenData] = Depends(get_current_user_optional)
):
    """
    Run a comprehensive attack simulation.
    
    Simulates an attack scenario from an entry point, analyzing
    possible attack paths, blast radius, and potential impact.
    """
    import uuid
    
    twin = get_twin_engine()
    
    # Initialize with sample network if empty
    if twin.graph.number_of_nodes() == 0:
        twin.initialize_sample_network()
    
    # Get network stats for context
    stats = twin.get_network_stats()
    
    # Find critical paths from entry point
    paths_found = []
    blast_radius = []
    recommendations = []
    risk_assessment = "LOW"
    
    # Check if entry point exists, if not use a default
    if entry_point not in twin.graph:
        # Use first available external-facing asset or any asset
        external_assets = [
            aid for aid, meta in twin.asset_metadata.items()
            if meta.get("zone") == "dmz" or meta.get("zone") == "external"
        ]
        if external_assets:
            entry_point = external_assets[0]
        elif twin.graph.nodes():
            entry_point = list(twin.graph.nodes())[0]
        else:
            return {
                "simulation_id": str(uuid.uuid4()),
                "attack_type": attack_type,
                "entry_point": entry_point,
                "target": target,
                "paths_found": [],
                "blast_radius": [],
                "risk_assessment": "UNKNOWN",
                "recommendations": ["No assets in network topology. Add assets first."]
            }
    
    # Calculate blast radius
    blast_result = twin.calculate_blast_radius(entry_point, max_hops=4)
    if "affected_assets" in blast_result:
        blast_radius = blast_result.get("affected_assets", [])
    elif "reachable_by_hop" in blast_result:
        for hop_assets in blast_result.get("reachable_by_hop", {}).values():
            blast_radius.extend(hop_assets)
    
    # Find attack paths to critical assets or target
    critical_assets = [
        aid for aid, meta in twin.asset_metadata.items()
        if meta.get("criticality") == "critical"
    ]
    
    targets_to_check = [target] if target else critical_assets[:5]
    
    for t in targets_to_check:
        if t and t != entry_point and t in twin.graph:
            found_paths = twin.find_attack_paths_bfs(entry_point, t, max_depth=6)
            for path in found_paths[:3]:  # Limit paths per target
                path_risk = len(path) * 2  # Simple risk calculation
                paths_found.append({
                    "path": path,
                    "risk_score": min(10, 10 - path_risk / 2),
                    "description": f"Attack path via {len(path)} hops",
                    "mitigations": [
                        f"Segment network to isolate {path[1] if len(path) > 1 else entry_point}",
                        "Implement zero-trust access controls",
                        "Enable enhanced monitoring on path nodes"
                    ]
                })
    
    # Simulate lateral movement for impact assessment
    sim_result = twin.simulate_lateral_movement(
        initial_compromise=entry_point,
        time_steps=10,
        propagation_probability=0.4 if attack_type == "apt" else 0.3
    )
    
    # Calculate risk assessment based on simulation
    compromised_count = sim_result.get("total_compromised", 0)
    critical_compromised = len(sim_result.get("critical_assets_compromised", []))
    
    if critical_compromised > 0:
        risk_assessment = "CRITICAL"
    elif compromised_count > stats.get("total_nodes", 1) * 0.5:
        risk_assessment = "HIGH"
    elif compromised_count > stats.get("total_nodes", 1) * 0.25:
        risk_assessment = "MEDIUM"
    else:
        risk_assessment = "LOW"
    
    # Generate recommendations based on attack type
    base_recommendations = [
        "Implement network segmentation to limit lateral movement",
        "Deploy endpoint detection and response (EDR) solutions",
        "Enable multi-factor authentication on all critical systems",
        "Review and restrict privileged access"
    ]
    
    if attack_type == "ransomware":
        recommendations = [
            "Maintain offline backups of critical data",
            "Disable SMB v1 and restrict lateral SMB access",
            *base_recommendations[:2]
        ]
    elif attack_type == "apt":
        recommendations = [
            "Implement advanced threat hunting procedures",
            "Deploy network traffic analysis tools",
            "Enable enhanced logging and SIEM correlation",
            *base_recommendations[:1]
        ]
    elif attack_type == "insider":
        recommendations = [
            "Implement data loss prevention (DLP) controls",
            "Monitor privileged user activity",
            "Apply principle of least privilege",
            *base_recommendations[:1]
        ]
    else:
        recommendations = base_recommendations[:4]
    
    logger.info(
        "Attack simulation complete",
        attack_type=attack_type,
        entry_point=entry_point,
        paths_found=len(paths_found),
        risk=risk_assessment,
        user_id=current_user.user_id
    )
    
    return {
        "simulation_id": str(uuid.uuid4()),
        "attack_type": attack_type,
        "entry_point": entry_point,
        "target": target,
        "paths_found": paths_found,
        "blast_radius": list(set(blast_radius)),
        "risk_assessment": risk_assessment,
        "recommendations": recommendations,
        "simulation_details": {
            "total_compromised": compromised_count,
            "critical_compromised": critical_compromised,
            "propagation_rate": sim_result.get("propagation_rate", 0)
        }
    }
