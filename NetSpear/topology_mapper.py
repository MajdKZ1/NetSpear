"""
Network topology mapping and visualization system.
"""
import logging
from typing import Optional, Dict, List, Any, Tuple
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from database import get_db_manager, NetworkTopology, Scan, Port

logger = logging.getLogger(__name__)


class TopologyMapper:
    """Map network topology from scan data."""
    
    def __init__(self, db_session: Optional[Session] = None):
        """
        Initialize topology mapper.
        
        Args:
            db_session: Optional database session
        """
        self.db = get_db_manager()
        self.db_session = db_session
    
    def _get_session(self) -> Session:
        """Get or create database session."""
        return self.db_session or self.db.get_session()
    
    def add_relationship(
        self,
        source_ip: str,
        target_ip: str,
        relationship_type: str = "communicates_with",
        protocol: Optional[str] = None,
        port: Optional[int] = None,
    ) -> Optional[NetworkTopology]:
        """
        Add a network relationship.
        
        Args:
            source_ip: Source IP address
            target_ip: Target IP address
            relationship_type: Type of relationship
            protocol: Optional protocol
            port: Optional port number
            
        Returns:
            Created topology relationship
        """
        db = self._get_session()
        try:
            # Check if relationship already exists
            existing = db.query(NetworkTopology).filter(
                NetworkTopology.source_ip == source_ip,
                NetworkTopology.target_ip == target_ip,
                NetworkTopology.relationship_type == relationship_type,
            ).first()
            
            if existing:
                return existing
            
            relationship = NetworkTopology(
                source_ip=source_ip,
                target_ip=target_ip,
                relationship_type=relationship_type,
                protocol=protocol,
                port=port,
            )
            db.add(relationship)
            db.commit()
            db.refresh(relationship)
            return relationship
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to add relationship: {e}")
            return None
    
    def build_topology_from_scans(self, scan_ids: Optional[List[int]] = None) -> Dict[str, Any]:
        """
        Build network topology from scan data.
        
        Args:
            scan_ids: Optional list of scan IDs (uses all if not provided)
            
        Returns:
            Topology data structure
        """
        db = self._get_session()
        
        # Get all scans
        query = db.query(Scan)
        if scan_ids:
            from sqlalchemy import and_
            query = query.filter(Scan.id.in_(scan_ids))
        scans = query.all()
        
        nodes = {}  # IP -> node data
        edges = []  # List of relationships
        
        for scan in scans:
            # Add node for scanned target
            if scan.target_ip not in nodes:
                nodes[scan.target_ip] = {
                    "ip": scan.target_ip,
                    "hostname": scan.target_hostname,
                    "services": [],
                    "open_ports": 0,
                    "vulnerabilities": 0,
                }
            
            node = nodes[scan.target_ip]
            
            # Add services from ports
            for port in scan.ports:
                if port.state == "open":
                    node["open_ports"] += 1
                    service_info = {
                        "port": port.port_number,
                        "protocol": port.protocol,
                        "service": port.service,
                        "version": port.version,
                    }
                    node["services"].append(service_info)
            
            # Count vulnerabilities
            node["vulnerabilities"] = len(scan.vulnerabilities)
            
            # Infer relationships from services
            # E.g., if SQL server is found, it might connect to a database server
            for port in scan.ports:
                if port.state == "open":
                    if port.service in ["mysql", "postgresql", "mssql"]:
                        # Database service - might have connections from other hosts
                        self.add_relationship(
                            source_ip="unknown",
                            target_ip=scan.target_ip,
                            relationship_type="database_server",
                            protocol=port.protocol,
                            port=port.port_number,
                        )
                    
                    elif port.service in ["smb", "netbios-ssn"]:
                        # SMB service - might share files with other hosts
                        self.add_relationship(
                            source_ip="unknown",
                            target_ip=scan.target_ip,
                            relationship_type="file_sharing",
                            protocol=port.protocol,
                            port=port.port_number,
                        )
        
        # Get all relationships
        relationships = db.query(NetworkTopology).all()
        for rel in relationships:
            edges.append({
                "source": rel.source_ip,
                "target": rel.target_ip,
                "type": rel.relationship_type,
                "protocol": rel.protocol,
                "port": rel.port,
            })
        
        return {
            "nodes": list(nodes.values()),
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges),
        }
    
    def get_topology_graph(self, target_ip: Optional[str] = None) -> Dict[str, Any]:
        """
        Get network topology as a graph structure.
        
        Args:
            target_ip: Optional root node IP
            
        Returns:
            Graph structure suitable for visualization
        """
        db = self._get_session()
        
        if target_ip:
            # Start from specific IP and build graph
            relationships = db.query(NetworkTopology).filter(
                (NetworkTopology.source_ip == target_ip) | 
                (NetworkTopology.target_ip == target_ip)
            ).all()
        else:
            # Get all relationships
            relationships = db.query(NetworkTopology).all()
        
        nodes = set()
        edges = []
        
        for rel in relationships:
            nodes.add(rel.source_ip)
            nodes.add(rel.target_ip)
            edges.append({
                "source": rel.source_ip,
                "target": rel.target_ip,
                "type": rel.relationship_type,
                "protocol": rel.protocol,
                "port": rel.port,
            })
        
        # Get node details
        node_data = {}
        for ip in nodes:
            scan = db.query(Scan).filter(Scan.target_ip == ip).order_by(Scan.timestamp.desc()).first()
            if scan:
                node_data[ip] = {
                    "ip": ip,
                    "hostname": scan.target_hostname,
                    "open_ports": len([p for p in scan.ports if p.state == "open"]),
                    "vulnerabilities": len(scan.vulnerabilities),
                    "last_scan": scan.timestamp.isoformat() if scan.timestamp else None,
                }
            else:
                node_data[ip] = {
                    "ip": ip,
                    "hostname": None,
                    "open_ports": 0,
                    "vulnerabilities": 0,
                }
        
        return {
            "nodes": list(node_data.values()),
            "edges": edges,
        }
    
    def export_topology(self, format: str = "json", target_ip: Optional[str] = None) -> str:
        """
        Export topology to various formats.
        
        Args:
            format: Export format (json, dot, graphml)
            target_ip: Optional root node
            
        Returns:
            Exported topology as string
        """
        graph = self.get_topology_graph(target_ip)
        
        if format == "json":
            import json
            return json.dumps(graph, indent=2)
        
        elif format == "dot":
            # Graphviz DOT format
            lines = ["digraph NetworkTopology {"]
            lines.append("  rankdir=LR;")
            
            # Add nodes
            for node in graph["nodes"]:
                label = f"{node['ip']}"
                if node.get("hostname"):
                    label += f"\\n{node['hostname']}"
                lines.append(f'  "{node["ip"]}" [label="{label}"];')
            
            # Add edges
            for edge in graph["edges"]:
                label = edge.get("type", "")
                if edge.get("port"):
                    label += f"\\n{edge['protocol']}:{edge['port']}"
                lines.append(f'  "{edge["source"]}" -> "{edge["target"]}" [label="{label}"];')
            
            lines.append("}")
            return "\n".join(lines)
        
        elif format == "graphml":
            # GraphML format for yEd and other tools
            lines = [
                '<?xml version="1.0" encoding="UTF-8"?>',
                '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
                '  <graph id="network_topology" edgedefault="directed">',
            ]
            
            # Add nodes
            for node in graph["nodes"]:
                lines.append(f'    <node id="{node["ip"]}">')
                lines.append(f'      <data key="label">{node["ip"]}</data>')
                if node.get("hostname"):
                    lines.append(f'      <data key="hostname">{node["hostname"]}</data>')
                lines.append('    </node>')
            
            # Add edges
            for i, edge in enumerate(graph["edges"]):
                lines.append(f'    <edge id="e{i}" source="{edge["source"]}" target="{edge["target"]}">')
                lines.append(f'      <data key="label">{edge.get("type", "")}</data>')
                lines.append('    </edge>')
            
            lines.append("  </graph>")
            lines.append("</graphml>")
            return "\n".join(lines)
        
        else:
            return "Unsupported format"
    
    def find_attack_paths(self, source_ip: str, target_ip: str) -> List[List[str]]:
        """
        Find potential attack paths between two hosts.
        
        Args:
            source_ip: Source IP
            target_ip: Target IP
            
        Returns:
            List of paths (each path is a list of IPs)
        """
        db = self._get_session()
        
        # Simple BFS to find paths
        from collections import deque
        
        paths = []
        queue = deque([(source_ip, [source_ip])])
        visited = {source_ip}
        
        while queue:
            current_ip, path = queue.popleft()
            
            if current_ip == target_ip:
                paths.append(path)
                continue
            
            # Get neighbors
            relationships = db.query(NetworkTopology).filter(
                NetworkTopology.source_ip == current_ip
            ).all()
            
            for rel in relationships:
                if rel.target_ip not in visited:
                    visited.add(rel.target_ip)
                    queue.append((rel.target_ip, path + [rel.target_ip]))
        
        return paths

