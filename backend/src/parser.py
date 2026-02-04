from scapy.all import rdpcap, IP, IPv6, TCP, UDP, DNS, DNSQR, Raw
from typing import List, Dict, Any
import json
from collections import defaultdict
from datetime import datetime


class PacketParser:
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.packets = None
        self.packet_data = []
        self.flows = defaultdict(list)
        self.statistics = {}
        
    def parse_file(self) -> bool:
        """Load and parse pcap file"""
        try:
            self.packets = rdpcap(self.file_path)
            print(f"✓ Loaded {len(self.packets)} packets")
            return True
        except Exception as e:
            print(f"✗ Error loading file: {e}")
            return False
    
    def extract_packet_info(self) -> List[Dict[str, Any]]:
        """Extract detailed information from each packet"""
        if not self.packets:
            return []
        
        for idx, packet in enumerate(self.packets):
            pkt_info = {
                'packet_num': idx,
                'timestamp': float(packet.time) if hasattr(packet, 'time') else 0,
                'length': len(packet),
                'protocols': self._get_protocols(packet),
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None,
                'protocol': None,
                'payload': None,
            }
            
            # Extract IP information
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                pkt_info['src_ip'] = ip_layer.src
                pkt_info['dst_ip'] = ip_layer.dst
            elif packet.haslayer(IPv6):
                ipv6_layer = packet[IPv6]
                pkt_info['src_ip'] = ipv6_layer.src
                pkt_info['dst_ip'] = ipv6_layer.dst
            
            # Extract port and protocol information
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                pkt_info['src_port'] = tcp_layer.sport
                pkt_info['dst_port'] = tcp_layer.dport
                pkt_info['protocol'] = 'TCP'
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                pkt_info['src_port'] = udp_layer.sport
                pkt_info['dst_port'] = udp_layer.dport
                pkt_info['protocol'] = 'UDP'
            
            # Handle DNS
            if packet.haslayer(DNS):
                dns_layer = packet[DNS]
                pkt_info['dns_query'] = self._extract_dns_info(dns_layer)
            
            # Extract payload
            if packet.haslayer(Raw):
                raw_data = packet[Raw].load
                pkt_info['payload_size'] = len(raw_data)
                pkt_info['payload_preview'] = str(raw_data[:50])
            
            self._add_flow(pkt_info)
            self.packet_data.append(pkt_info)
        
        return self.packet_data
    
    def _get_protocols(self, packet) -> List[str]:
        """Get list of protocols in packet"""
        protocols = []
        for proto in packet.layers():
            protocols.append(proto.name)
        return protocols
    
    def _extract_dns_info(self, dns_layer) -> Dict:
        """Extract DNS query information"""
        dns_info = {'queries': [], 'answers': []}
        if dns_layer.qd:
            for query in dns_layer.qd:
                if isinstance(query, DNSQR):
                    dns_info['queries'].append(query.qname.decode('utf-8', errors='ignore'))
        return dns_info
    
    def _add_flow(self, pkt_info: Dict):
        """Group packets into flows (conversations)"""
        if pkt_info['src_ip'] and pkt_info['dst_ip']:
            flow_key = tuple(sorted([pkt_info['src_ip'], pkt_info['dst_ip']]))
            self.flows[flow_key].append(pkt_info)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Calculate packet statistics"""
        if not self.packet_data:
            return {}
        
        stats = {
            'total_packets': len(self.packet_data),
            'total_size': sum(p['length'] for p in self.packet_data),
            'flows_count': len(self.flows),
            'protocols': defaultdict(int),
            'top_ips_src': defaultdict(int),
            'top_ips_dst': defaultdict(int),
            'top_ports': defaultdict(int),
        }
        
        for pkt in self.packet_data:
            for proto in pkt['protocols']:
                stats['protocols'][proto] += 1
            if pkt['src_ip']:
                stats['top_ips_src'][pkt['src_ip']] += 1
            if pkt['dst_ip']:
                stats['top_ips_dst'][pkt['dst_ip']] += 1
            if pkt['src_port']:
                stats['top_ports'][pkt['src_port']] += 1
            if pkt['dst_port']:
                stats['top_ports'][pkt['dst_port']] += 1
        
        self.statistics = stats
        return stats
    
    def get_flows(self) -> Dict:
        """Return conversation flows"""
        return dict(self.flows)
