"""
Graph-based threat analysis endpoints
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, Any, Optional

from app.core.database import get_db
from app.core.security import get_current_user
from app.services.graph_analysis import ThreatGraphService

router = APIRouter()
graph_service = ThreatGraphService()


@router.get("/lateral-movement")
async def detect_lateral_movement(
    hours: int = Query(24, ge=1, le=168, description="Time window in hours"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Detect lateral movement patterns in threat data
    """
    movements = await graph_service.detect_lateral_movement(db, hours)
    
    return {
        'time_window_hours': hours,
        'lateral_movements_detected': len(movements),
        'movements': movements
    }


@router.get("/attack-paths")
async def find_attack_paths(
    source: Optional[str] = Query(None, description="Source node (e.g., 'ip:192.168.1.1')"),
    target: Optional[str] = Query(None, description="Target node (e.g., 'resource:data')"),
    max_length: int = Query(5, ge=2, le=10, description="Maximum path length"),
    hours: int = Query(24, ge=1, le=168, description="Time window in hours"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Find attack paths in the threat graph
    """
    paths = await graph_service.find_attack_paths(db, source, target, max_length)
    
    return {
        'source': source,
        'target': target,
        'paths_found': len(paths),
        'paths': [
            {
                'path': path,
                'length': len(path),
                'nodes': path
            }
            for path in paths
        ]
    }


@router.get("/centrality")
async def analyze_centrality(
    hours: int = Query(24, ge=1, le=168, description="Time window in hours"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Analyze network centrality to identify critical nodes
    """
    await graph_service.build_threat_graph(db, hours)
    analysis = graph_service.analyze_network_centrality()
    
    return analysis


@router.get("/visualization")
async def get_graph_visualization(
    hours: int = Query(24, ge=1, le=168, description="Time window in hours"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Get graph data for visualization
    """
    await graph_service.build_threat_graph(db, hours)
    viz_data = graph_service.get_graph_visualization_data()
    
    return viz_data
