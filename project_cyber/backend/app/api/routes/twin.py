"""
Contexta Backend - Digital Twin Routes

Provides endpoints for digital twin simulation and attack path analysis.
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query, Body
import structlog

from app.twin.engine import get_twin_engine
from app.auth.jwt import get_current_active_user, TokenData

logger = structlog.get_logger()
router = APIRouter()


@router.get("/stats")
async def get_twin_stats(
    current_user: TokenData = Depends(get_current_active_user)
):
    """
    Get digital twin network statistics.
    """
    twin = get_twin_engine()
    
    return twin.get_network_stats()


@router.get("/export")
async def export_twin(
    current_user: TokenData = Depends(get_current_active_user)
):
    """
    Export the digital twin graph data.
    """
    twin = get_twin_engine()
    
    return twin.export_to_dict()


@router.post("/import")
async def import_twin(
    data: Dict[str, Any] = Body(...),
    current_user: TokenData = Depends(get_current_active_user)
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
    current_user: TokenData = Depends(get_current_active_user)
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
    current_user: TokenData = Depends(get_current_active_user)
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
    current_user: TokenData = Depends(get_current_active_user)
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
    current_user: TokenData = Depends(get_current_active_user)
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
    current_user: TokenData = Depends(get_current_active_user)
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
    current_user: TokenData = Depends(get_current_active_user)
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
    current_user: TokenData = Depends(get_current_active_user)
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
    current_user: TokenData = Depends(get_current_active_user)
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
