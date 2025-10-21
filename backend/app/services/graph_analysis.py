"""
Graph-based Threat Analysis Service
Analyzes entity relationships and detects lateral movement
"""
import networkx as nx
from typing import Dict, List, Any, Set, Tuple
from datetime import datetime, timedelta
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import ThreatAlert, CloudLog

logger = structlog.get_logger()


class ThreatGraphService:
    """
    Service for graph-based threat analysis
    """
    
    def __init__(self):
        self.graph = nx.DiGraph()
    
    async def build_threat_graph(
        self,
        db: AsyncSession,
        time_window_hours: int = 24
    ) -> nx.DiGraph:
        """
        Build a graph of threat relationships
        
        Nodes: users, IPs, resources
        Edges: access patterns, privilege changes, data flows
        """
        graph = nx.DiGraph()
        
        # Get recent alerts
        start_time = datetime.now() - timedelta(hours=time_window_hours)
        result = await db.execute(
            select(ThreatAlert).where(ThreatAlert.detected_at >= start_time)
        )
        alerts = result.scalars().all()
        
        # Build graph from alerts
        for alert in alerts:
            # Add user node
            if alert.user_id:
                self._add_user_node(graph, alert.user_id, alert)
            
            # Add IP node
            if alert.ip_address:
                self._add_ip_node(graph, alert.ip_address, alert)
            
            # Add edges
            if alert.user_id and alert.ip_address:
                graph.add_edge(
                    f"user:{alert.user_id}",
                    f"ip:{alert.ip_address}",
                    alert_id=alert.alert_id,
                    severity=alert.severity,
                    category=alert.category,
                    timestamp=alert.detected_at,
                    threat_score=alert.threat_score
                )
            
            # Add resource nodes
            if alert.affected_resources:
                for resource in alert.affected_resources:
                    resource_id = f"resource:{resource}"
                    graph.add_node(
                        resource_id,
                        type='resource',
                        name=resource
                    )
                    if alert.user_id:
                        graph.add_edge(
                            f"user:{alert.user_id}",
                            resource_id,
                            alert_id=alert.alert_id,
                            action=alert.category
                        )
        
        self.graph = graph
        return graph
    
    def _add_user_node(self, graph: nx.DiGraph, user_id: str, alert: ThreatAlert):
        """Add or update user node"""
        node_id = f"user:{user_id}"
        
        if graph.has_node(node_id):
            # Update existing node
            node_data = graph.nodes[node_id]
            node_data['alert_count'] = node_data.get('alert_count', 0) + 1
            node_data['max_severity'] = max(
                node_data.get('max_severity', 0),
                self._severity_to_number(alert.severity)
            )
        else:
            # Add new node
            graph.add_node(
                node_id,
                type='user',
                user_id=user_id,
                alert_count=1,
                max_severity=self._severity_to_number(alert.severity)
            )
    
    def _add_ip_node(self, graph: nx.DiGraph, ip_address: str, alert: ThreatAlert):
        """Add or update IP node"""
        node_id = f"ip:{ip_address}"
        
        if graph.has_node(node_id):
            node_data = graph.nodes[node_id]
            node_data['alert_count'] = node_data.get('alert_count', 0) + 1
            node_data['max_severity'] = max(
                node_data.get('max_severity', 0),
                self._severity_to_number(alert.severity)
            )
        else:
            graph.add_node(
                node_id,
                type='ip',
                ip_address=ip_address,
                alert_count=1,
                max_severity=self._severity_to_number(alert.severity),
                country=alert.geo_location.get('country') if alert.geo_location else None
            )
    
    def _severity_to_number(self, severity: str) -> int:
        """Convert severity to number for comparison"""
        severity_map = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1
        }
        return severity_map.get(severity, 0)
    
    async def detect_lateral_movement(
        self,
        db: AsyncSession,
        time_window_hours: int = 24
    ) -> List[Dict[str, Any]]:
        """
        Detect lateral movement patterns in the threat graph
        
        Lateral movement indicators:
        - User accessing multiple resources rapidly
        - Privilege escalation followed by resource access
        - Chained access through multiple accounts/IPs
        """
        await self.build_threat_graph(db, time_window_hours)
        
        lateral_movements = []
        
        # Find users with multiple resource accesses
        for node in self.graph.nodes():
            if node.startswith('user:'):
                user_resources = list(self.graph.successors(node))
                resource_count = sum(1 for r in user_resources if r.startswith('resource:'))
                
                if resource_count >= 3:  # Threshold for suspicious activity
                    # Check if accesses were rapid
                    edges = [(node, succ) for succ in user_resources]
                    timestamps = [
                        self.graph.edges[edge].get('timestamp')
                        for edge in edges
                        if self.graph.edges[edge].get('timestamp')
                    ]
                    
                    if timestamps and len(timestamps) >= 2:
                        time_span = max(timestamps) - min(timestamps)
                        if time_span < timedelta(hours=1):
                            lateral_movements.append({
                                'type': 'rapid_resource_access',
                                'user_id': node.replace('user:', ''),
                                'resource_count': resource_count,
                                'time_span_minutes': time_span.total_seconds() / 60,
                                'severity': 'high',
                                'description': f'User accessed {resource_count} resources in {time_span.total_seconds()/60:.1f} minutes'
                            })
        
        # Find privilege escalation chains
        escalation_chains = self._find_escalation_chains()
        lateral_movements.extend(escalation_chains)
        
        return lateral_movements
    
    def _find_escalation_chains(self) -> List[Dict[str, Any]]:
        """Find chains of privilege escalation"""
        chains = []
        
        # Look for paths where privilege_escalation alerts lead to other alerts
        for node in self.graph.nodes():
            if node.startswith('user:'):
                # Check outgoing edges for privilege escalation
                for successor in self.graph.successors(node):
                    edge_data = self.graph.edges[(node, successor)]
                    if edge_data.get('category') == 'privilege_escalation':
                        # Check if followed by other suspicious activity
                        for next_successor in self.graph.successors(successor):
                            chains.append({
                                'type': 'privilege_escalation_chain',
                                'user_id': node.replace('user:', ''),
                                'escalation_target': successor,
                                'follow_up_activity': next_successor,
                                'severity': 'critical',
                                'description': 'Privilege escalation followed by suspicious activity'
                            })
        
        return chains
    
    async def find_attack_paths(
        self,
        db: AsyncSession,
        source_node: str = None,
        target_node: str = None,
        max_path_length: int = 5
    ) -> List[List[str]]:
        """
        Find attack paths in the threat graph
        
        Args:
            source_node: Starting node (e.g., 'ip:192.168.1.1')
            target_node: Target node (e.g., 'resource:sensitive_data')
            max_path_length: Maximum path length to consider
        """
        await self.build_threat_graph(db)
        
        paths = []
        
        if source_node and target_node:
            # Find specific path
            try:
                if nx.has_path(self.graph, source_node, target_node):
                    all_paths = nx.all_simple_paths(
                        self.graph,
                        source_node,
                        target_node,
                        cutoff=max_path_length
                    )
                    paths = list(all_paths)
            except nx.NetworkXError:
                pass
        else:
            # Find all critical paths (high severity nodes)
            critical_nodes = [
                node for node, data in self.graph.nodes(data=True)
                if data.get('max_severity', 0) >= 3
            ]
            
            for i, source in enumerate(critical_nodes):
                for target in critical_nodes[i+1:]:
                    try:
                        if nx.has_path(self.graph, source, target):
                            shortest = nx.shortest_path(self.graph, source, target)
                            if len(shortest) <= max_path_length:
                                paths.append(shortest)
                    except nx.NetworkXError:
                        continue
        
        return paths
    
    def analyze_network_centrality(self) -> Dict[str, Any]:
        """
        Analyze network centrality to identify key nodes
        
        High centrality nodes are critical in the attack graph
        """
        if not self.graph.nodes():
            return {}
        
        # Calculate centrality metrics
        degree_centrality = nx.degree_centrality(self.graph)
        betweenness_centrality = nx.betweenness_centrality(self.graph)
        
        # Find top central nodes
        top_degree = sorted(
            degree_centrality.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        top_betweenness = sorted(
            betweenness_centrality.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        return {
            'most_connected_nodes': [
                {
                    'node': node,
                    'centrality': score,
                    'type': self.graph.nodes[node].get('type'),
                    'alert_count': self.graph.nodes[node].get('alert_count', 0)
                }
                for node, score in top_degree
            ],
            'critical_intermediaries': [
                {
                    'node': node,
                    'centrality': score,
                    'type': self.graph.nodes[node].get('type')
                }
                for node, score in top_betweenness
            ],
            'network_stats': {
                'total_nodes': self.graph.number_of_nodes(),
                'total_edges': self.graph.number_of_edges(),
                'density': nx.density(self.graph),
                'connected_components': nx.number_weakly_connected_components(self.graph)
            }
        }
    
    def get_graph_visualization_data(self) -> Dict[str, Any]:
        """
        Get graph data in format suitable for visualization
        """
        nodes = []
        edges = []
        
        for node, data in self.graph.nodes(data=True):
            nodes.append({
                'id': node,
                'label': node.split(':', 1)[1] if ':' in node else node,
                'type': data.get('type', 'unknown'),
                'alert_count': data.get('alert_count', 0),
                'severity': data.get('max_severity', 0)
            })
        
        for source, target, data in self.graph.edges(data=True):
            edges.append({
                'source': source,
                'target': target,
                'alert_id': data.get('alert_id'),
                'severity': data.get('severity'),
                'category': data.get('category'),
                'threat_score': data.get('threat_score')
            })
        
        return {
            'nodes': nodes,
            'edges': edges
        }
