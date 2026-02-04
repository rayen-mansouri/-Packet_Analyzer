import openai
from typing import Dict, Any, List
import json
from collections import Counter


class PacketAnalyzer:
    
    def __init__(self, api_key: str = None):
        if api_key:
            openai.api_key = api_key
    
    def generate_summary(self, packet_data: List[Dict], statistics: Dict) -> str:
        """Generate AI-powered summary of packet capture"""
        
        # Prepare data for AI
        summary_context = self._prepare_context(packet_data, statistics)
        
        prompt = f"""
        Analyze this network packet capture data and provide a comprehensive summary:
        
        {summary_context}
        
        Please provide:
        1. Overview of the network traffic
        2. Key observations about communication patterns
        3. Identified protocols and their usage
        4. Any potential security concerns
        5. Top communicating IPs and their roles
        """
        
        try:
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a network security expert analyzing packet captures."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=1000
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error generating summary: {str(e)}"
    
    def detect_anomalies(self, packet_data: List[Dict], statistics: Dict) -> List[Dict]:
        """Detect suspicious patterns in traffic"""
        anomalies = []
        
        # Check for port scanning
        port_connections = Counter()
        for pkt in packet_data:
            if pkt['dst_port']:
                key = (pkt['src_ip'], pkt['dst_ip'])
                port_connections[key] += 1
        
        for (src, dst), count in port_connections.items():
            if count > 10:  # Multiple ports to same destination
                anomalies.append({
                    'type': 'port_scan',
                    'severity': 'high',
                    'description': f'Potential port scanning from {src} to {dst} ({count} connections)',
                    'source': src,
                    'destination': dst
                })
        
        # Check for unencrypted traffic
        sensitive_ports = [23, 21, 80, 143, 110]  # Telnet, FTP, HTTP, IMAP, POP3
        for pkt in packet_data:
            if pkt['dst_port'] in sensitive_ports:
                anomalies.append({
                    'type': 'unencrypted_traffic',
                    'severity': 'medium',
                    'description': f'Unencrypted communication on port {pkt["dst_port"]}',
                    'protocol': pkt['protocol'],
                    'destination_port': pkt['dst_port']
                })
        
        # Check for DNS anomalies
        dns_queries = [p for p in packet_data if 'dns_query' in p]
        if len(dns_queries) > len(packet_data) * 0.3:
            anomalies.append({
                'type': 'high_dns_activity',
                'severity': 'medium',
                'description': f'Unusual DNS activity detected ({len(dns_queries)} DNS queries)',
                'count': len(dns_queries)
            })
        
        return anomalies
    
    def _prepare_context(self, packet_data: List[Dict], statistics: Dict) -> str:
        """Prepare packet data as context string for AI"""
        
        context = f"""
        Total Packets: {statistics.get('total_packets', 0)}
        Total Data: {statistics.get('total_size', 0)} bytes
        Unique Flows: {statistics.get('flows_count', 0)}
        
        Protocols Used:
        {json.dumps(dict(statistics.get('protocols', {})), indent=2)}
        
        Top Source IPs:
        {json.dumps(dict(sorted(statistics.get('top_ips_src', {}).items(), key=lambda x: x[1], reverse=True)[:5]), indent=2)}
        
        Top Destination IPs:
        {json.dumps(dict(sorted(statistics.get('top_ips_dst', {}).items(), key=lambda x: x[1], reverse=True)[:5]), indent=2)}
        
        Top Ports Used:
        {json.dumps(dict(sorted(statistics.get('top_ports', {}).items(), key=lambda x: x[1], reverse=True)[:5]), indent=2)}
        """
        
        return context
    
    def explain_packet(self, packet: Dict) -> str:
        """Generate explanation for a specific packet"""
        
        prompt = f"""
        Explain this network packet in simple terms:
        
        Source IP: {packet.get('src_ip')}
        Destination IP: {packet.get('dst_ip')}
        Protocol: {packet.get('protocol')}
        Source Port: {packet.get('src_port')}
        Destination Port: {packet.get('dst_port')}
        Packet Size: {packet.get('length')} bytes
        Protocols: {', '.join(packet.get('protocols', []))}
        
        Explain what this packet represents and what it's likely doing.
        """
        
        try:
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=300
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error explaining packet: {str(e)}"
