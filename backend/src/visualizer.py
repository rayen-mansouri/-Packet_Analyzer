import networkx as nx
import json
from typing import List, Dict, Tuple
from collections import defaultdict


class NetworkVisualizer:
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.flows_data = []
    
    def create_ip_relationship_graph(self, packet_data: List[Dict]) -> Dict:
        """
        Create graph of IP relationships
        Returns JSON format for D3.js or Plotly visualization
        """
        
        self.graph = nx.DiGraph()
        edges = defaultdict(int)
        
        # Build graph from packets
        for pkt in packet_data:
            if pkt['src_ip'] and pkt['dst_ip']:
                src, dst = pkt['src_ip'], pkt['dst_ip']
                self.graph.add_edge(src, dst)
                
                edge_key = (src, dst)
                edges[edge_key] += 1
        
        # Prepare nodes
        nodes = []
        for node in self.graph.nodes():
            nodes.append({
                'id': node,
                'label': node,
                'size': self._calculate_node_size(node),
                'color': self._get_node_color(node),
                'incoming': self.graph.in_degree(node),
                'outgoing': self.graph.out_degree(node)
            })
        
        # Prepare edges
        edges_list = []
        for (src, dst), weight in edges.items():
            edges_list.append({
                'source': src,
                'target': dst,
                'weight': weight,
                'value': weight
            })
        
        return {
            'nodes': nodes,
            'links': edges_list,
            'graph_type': 'ip_relationship'
        }
    
    def create_protocol_flow_graph(self, packet_data: List[Dict]) -> Dict:
        """
        Create graph showing protocol relationships and flow
        """
        
        proto_graph = nx.DiGraph()
        flows = defaultdict(int)
        
        for pkt in packet_data:
            protocols = pkt.get('protocols', [])
            if len(protocols) >= 2:
                for i in range(len(protocols) - 1):
                    src_proto = protocols[i]
                    dst_proto = protocols[i + 1]
                    proto_graph.add_edge(src_proto, dst_proto)
                    flows[(src_proto, dst_proto)] += 1
        
        nodes = []
        for node in proto_graph.nodes():
            nodes.append({
                'id': node,
                'label': node,
                'size': proto_graph.degree(node) * 10
            })
        
        edges_list = []
        for (src, dst), weight in flows.items():
            edges_list.append({
                'source': src,
                'target': dst,
                'weight': weight
            })
        
        return {
            'nodes': nodes,
            'links': edges_list,
            'graph_type': 'protocol_flow'
        }
    
    def create_traffic_timeline(self, packet_data: List[Dict]) -> Dict:
        """
        Create timeline data showing traffic patterns over time
        """
        
        timeline_data = defaultdict(int)
        
        for pkt in packet_data:
            timestamp = pkt.get('timestamp', 0)
            # Round to nearest second for binning
            bin_time = int(timestamp)
            timeline_data[bin_time] += 1
        
        timeline = [
            {'time': t, 'packets': count}
            for t, count in sorted(timeline_data.items())
        ]
        
        return {
            'timeline': timeline,
            'total_packets': sum(d['packets'] for d in timeline),
            'duration': max(d['time'] for d in timeline) - min(d['time'] for d in timeline) if timeline else 0
        }
    
    def create_port_usage_graph(self, packet_data: List[Dict]) -> Dict:
        """
        Create visualization of port usage distribution
        """
        
        ports = defaultdict(int)
        
        for pkt in packet_data:
            if pkt['dst_port']:
                ports[pkt['dst_port']] += 1
        
        # Sort by frequency
        top_ports = sorted(ports.items(), key=lambda x: x[1], reverse=True)[:15]
        
        return {
            'ports': [
                {
                    'port': port,
                    'count': count,
                    'service': self._get_port_service(port)
                }
                for port, count in top_ports
            ]
        }
    
    def create_geolocation_map_data(self, packet_data: List[Dict], geoip_db=None) -> Dict:
        """
        Prepare data for geolocation mapping
        Requires GeoIP database for IP lookups
        """
        
        locations = []
        unique_ips = set()
        
        for pkt in packet_data:
            if pkt['dst_ip'] and pkt['dst_ip'] not in unique_ips:
                unique_ips.add(pkt['dst_ip'])
                
                location_data = {
                    'ip': pkt['dst_ip'],
                    'latitude': None,
                    'longitude': None,
                    'country': 'Unknown',
                    'city': 'Unknown'
                }
                
                # If GeoIP DB available, lookup location
                if geoip_db:
                    try:
                        response = geoip_db.city(pkt['dst_ip'])
                        location_data['latitude'] = response.location.latitude
                        location_data['longitude'] = response.location.longitude
                        location_data['country'] = response.country.iso_code
                        location_data['city'] = response.city.name or 'Unknown'
                    except:
                        pass
                
                locations.append(location_data)
        
        return {
            'locations': locations,
            'total_unique_ips': len(unique_ips)
        }
    
    def _calculate_node_size(self, ip: str) -> int:
        """Calculate node size based on degree"""
        degree = self.graph.degree(ip)
        return min(100, max(10, degree * 5))
    
    def _get_node_color(self, ip: str) -> str:
        """Get node color based on activity"""
        degree = self.graph.degree(ip)
        if degree > 20:
            return '#ff4444'  # Red - high activity
        elif degree > 10:
            return '#ff9900'  # Orange - medium activity
        else:
            return '#4444ff'  # Blue - low activity
    
    def _get_port_service(self, port: int) -> str:
        """Get common service name for port"""
        
        port_services = {
            20: 'FTP-DATA',
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt'
        }
        
        return port_services.get(port, 'Unknown')
