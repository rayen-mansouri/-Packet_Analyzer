from scapy.all import rdpcap, IP, IPv6, TCP, UDP, DNS, DNSQR, Raw, ICMP
from typing import List, Dict, Any
import json
from collections import defaultdict, Counter
from datetime import datetime


class PacketParser:
    """Parse PCAP files and extract comprehensive network information"""

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
            print(f"? Loaded {len(self.packets)} packets")
            return True
        except Exception as e:
            print(f"? Error loading file: {e}")
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
                'payload_size': 0,
                'payload_preview': None,
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
            elif packet.haslayer(ICMP):
                pkt_info['protocol'] = 'ICMP'

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
        """Calculate comprehensive packet statistics"""
        if not self.packet_data:
            return {}

        # Basic counts
        total_packets = len(self.packet_data)
        total_size = sum(p['length'] for p in self.packet_data)
        
        # Protocol breakdown
        protocol_counts = defaultdict(int)
        tcp_count = 0
        udp_count = 0
        icmp_count = 0
        
        for pkt in self.packet_data:
            proto = pkt.get('protocol')
            if proto == 'TCP':
                tcp_count += 1
            elif proto == 'UDP':
                udp_count += 1
            elif proto == 'ICMP':
                icmp_count += 1
            if proto:
                protocol_counts[proto] += 1

        # Layer-based protocol breakdown
        layer_protocols = defaultdict(int)
        for pkt in self.packet_data:
            for proto in pkt['protocols']:
                layer_protocols[proto] += 1

        # Convert to percentages
        protocol_breakdown = {}
        for proto, count in protocol_counts.items():
            percentage = (count / total_packets * 100) if total_packets > 0 else 0
            protocol_breakdown[proto] = {
                'count': count,
                'percentage': round(percentage, 1)
            }

        # IP analysis
        src_ips = Counter()
        dst_ips = Counter()
        unique_ips = set()
        
        for pkt in self.packet_data:
            if pkt['src_ip']:
                src_ips[pkt['src_ip']] += 1
                unique_ips.add(pkt['src_ip'])
            if pkt['dst_ip']:
                dst_ips[pkt['dst_ip']] += 1
                unique_ips.add(pkt['dst_ip'])

        # Port analysis
        ports_used = Counter()
        for pkt in self.packet_data:
            if pkt['dst_port']:
                ports_used[pkt['dst_port']] += 1
            if pkt['src_port']:
                ports_used[pkt['src_port']] += 1

        # Conversation analysis
        dns_queries = sum(1 for p in self.packet_data if p.get('dns_query'))
        
        stats = {
            'total_packets': total_packets,
            'total_size_bytes': total_size,
            'total_size_mb': round(total_size / (1024 * 1024), 2),
            'average_packet_size': round(total_size / total_packets, 2) if total_packets > 0 else 0,
            'flows_count': len(self.flows),
            
            # Protocol information
            'protocol_breakdown': dict(protocol_breakdown),
            'tcp_packets': tcp_count,
            'tcp_percentage': round((tcp_count / total_packets * 100), 1) if total_packets > 0 else 0,
            'udp_packets': udp_count,
            'udp_percentage': round((udp_count / total_packets * 100), 1) if total_packets > 0 else 0,
            'icmp_packets': icmp_count,
            'icmp_percentage': round((icmp_count / total_packets * 100), 1) if total_packets > 0 else 0,
            
            # Layer protocol info
            'layer_protocols': dict(layer_protocols),
            
            # IP information
            'unique_source_ips': len(src_ips),
            'unique_dest_ips': len(dst_ips),
            'unique_ips_total': len(unique_ips),
            'top_ips_src': dict(src_ips.most_common(10)),
            'top_ips_dst': dict(dst_ips.most_common(10)),
            
            # Port information
            'unique_ports': len(ports_used),
            'top_ports': dict(ports_used.most_common(15)),
            
            # Additional metrics
            'dns_queries': dns_queries,
            'largest_packet': max((p['length'] for p in self.packet_data), default=0),
            'smallest_packet': min((p['length'] for p in self.packet_data), default=0),
        }

        self.statistics = stats
        return stats

    def get_flows(self) -> Dict:
        """Return conversation flows"""
        return dict(self.flows)

    def get_network_graph_data(self) -> Dict[str, any]:
        """Generate node and link data for D3 network visualization"""
        from collections import defaultdict
        
        # Track connections between IPs
        connections = defaultdict(lambda: {
            'packets': 0,
            'protocols': Counter(),
            'size': 0
        })
        
        # Track IP statistics
        ip_stats = defaultdict(lambda: {
            'packets_sent': 0,
            'packets_received': 0,
            'protocols': Counter(),
            'total_size': 0
        })
        
        # Build connection graph
        for pkt in self.packet_data:
            src_ip = pkt.get('src_ip')
            dst_ip = pkt.get('dst_ip')
            protocol = pkt.get('protocol', 'OTHER')
            pkt_size = pkt.get('length', 0)
            
            if src_ip and dst_ip:
                # Create bidirectional connection key (alphabetically sorted for consistency)
                conn_key = tuple(sorted([src_ip, dst_ip]))
                connections[conn_key]['packets'] += 1
                connections[conn_key]['protocols'][protocol] += 1
                connections[conn_key]['size'] += pkt_size
                
                # Track IP stats
                ip_stats[src_ip]['packets_sent'] += 1
                ip_stats[src_ip]['protocols'][protocol] += 1
                ip_stats[src_ip]['total_size'] += pkt_size
                
                ip_stats[dst_ip]['packets_received'] += 1
                ip_stats[dst_ip]['protocols'][protocol] += 1
                ip_stats[dst_ip]['total_size'] += pkt_size
        
        # Create nodes for D3
        nodes = []
        node_set = set()
        for ip, stats in ip_stats.items():
            if ip:
                nodes.append({
                    'id': ip,
                    'packets_sent': stats['packets_sent'],
                    'packets_received': stats['packets_received'],
                    'total_packets': stats['packets_sent'] + stats['packets_received'],
                    'protocols': dict(stats['protocols']),
                    'total_size': stats['total_size']
                })
                node_set.add(ip)
        
        # Create links for D3
        links = []
        for (ip1, ip2), conn_data in connections.items():
            links.append({
                'source': ip1,
                'target': ip2,
                'packets': conn_data['packets'],
                'size': conn_data['size'],
                'protocols': dict(conn_data['protocols'])
            })
        
        return {
            'nodes': nodes,
            'links': links
        }

    def get_timeline_data(self) -> Dict[str, any]:
        """Generate timeline data: packet count and protocols over time"""
        from collections import defaultdict
        
        if not self.packet_data:
            return {'timeline': [], 'start_time': 0, 'end_time': 0}
        
        # Get time range
        timestamps = [p.get('timestamp', 0) for p in self.packet_data if p.get('timestamp')]
        if not timestamps:
            return {'timeline': [], 'start_time': 0, 'end_time': 0}
        
        start_time = min(timestamps)
        end_time = max(timestamps)
        
        # If all packets have same timestamp, use 1 second window
        time_range = max(1, end_time - start_time)
        
        # Determine bucket size (1 second buckets, or adjust if capture is very short)
        bucket_size = max(1, time_range / 100)  # Max 100 buckets for readability
        
        # Create time buckets
        timeline_buckets = defaultdict(lambda: {
            'packets': 0,
            'size': 0,
            'protocols': Counter()
        })
        
        # Fill buckets
        for pkt in self.packet_data:
            timestamp = pkt.get('timestamp', 0)
            if timestamp:
                # Calculate bucket index
                bucket_idx = int((timestamp - start_time) / bucket_size)
                timeline_buckets[bucket_idx]['packets'] += 1
                timeline_buckets[bucket_idx]['size'] += pkt.get('length', 0)
                
                protocol = pkt.get('protocol', 'OTHER')
                if protocol:
                    timeline_buckets[bucket_idx]['protocols'][protocol] += 1
        
        # Convert to timeline array
        timeline = []
        for i in range(int(time_range / bucket_size) + 1):
            if i in timeline_buckets:
                bucket = timeline_buckets[i]
                timeline.append({
                    'time': start_time + (i * bucket_size),
                    'timestamp': f"{int(i * bucket_size)}s",
                    'packets': bucket['packets'],
                    'size_kb': round(bucket['size'] / 1024, 2),
                    'protocols': dict(bucket['protocols'])
                })
        
        return {
            'timeline': timeline,
            'start_time': start_time,
            'end_time': end_time,
            'total_duration': round(time_range, 2)
        }
