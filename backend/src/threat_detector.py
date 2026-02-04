from typing import List, Dict, Any
from collections import Counter, defaultdict
import socket
import threading


def resolve_ip_to_domain(ip: str) -> str:
    """Resolve IP to domain name with timeout"""
    try:
        # Use timeout to avoid hanging
        socket.setdefaulttimeout(1)
        domain = socket.gethostbyaddr(ip)[0]
        return domain
    except (socket.herror, socket.timeout, OSError):
        # If resolution fails, return empty string
        return ""
    finally:
        socket.setdefaulttimeout(None)


class ThreatDetector:
    """Enhanced threat detection with pattern recognition"""

    SUSPICIOUS_PORTS = {
        4444: "Remote shell",
        5555: "Reverse shell",
        6666: "IRC botnet",
        8888: "Remote access",
        31337: "Leet backdoor",
        6379: "Redis exploit",
        8080: "Common proxy/backdoor",
        9999: "Arbitrary service",
    }

    # Common C2 server indicators
    C2_INDICATORS = ['beacon', 'command', 'control', 'callback', 'exfil', 'backdoor']

    # DNS exfiltration patterns - unusually long subdomains
    EXFIL_PATTERNS = ['exfil', 'tunnel', 'hidden', 'covert', 'secret']

    def __init__(self):
        self.threats = []
        self.risk_score = 0
        self.threat_details = []

    def _add_threat(self, threat_dict: Dict) -> None:
        """Add threat with domain resolution for source IP"""
        if 'source' in threat_dict:
            domain = resolve_ip_to_domain(threat_dict['source'])
            if domain:
                threat_dict['source_domain'] = domain
        self.threats.append(threat_dict)

    def analyze(self, packet_data: List[Dict], statistics: Dict) -> Dict[str, Any]:
        """Run comprehensive threat analysis"""
        self.threats = []
        self.threat_details = []

        # Run individual checks
        self._check_port_scanning(packet_data)
        self._check_syn_flood(packet_data)
        self._check_brute_force(packet_data)
        self._check_suspicious_ports(packet_data)
        self._check_data_exfiltration(packet_data, statistics)
        self._check_dns_anomalies(packet_data)
        self._check_unusual_traffic_volume(packet_data, statistics)
        self._check_protocol_anomalies(statistics)
        self._calculate_risk_score()

        return {
            'threats': self.threats,
            'risk_score': self.risk_score,
            'severity_count': self._count_by_severity(),
            'threat_summary': self._generate_summary()
        }

    def _check_port_scanning(self, packets: List[Dict]):
        """Detect port scanning attempts"""
        src_dst_ports = defaultdict(set)
        src_dst_times = defaultdict(list)

        for pkt in packets:
            if pkt.get('src_ip') and pkt.get('dst_ip') and pkt.get('dst_port'):
                key = (pkt['src_ip'], pkt['dst_ip'])
                src_dst_ports[key].add(pkt['dst_port'])
                src_dst_times[key].append(pkt.get('timestamp', 0))

        for (src, dst), ports in src_dst_ports.items():
            if len(ports) > 5:
                port_list = sorted(list(ports))[:10]
                self._add_threat({
                    'type': 'port_scan',
                    'severity': 'high',
                    'source': src,
                    'destination': dst,
                    'ports_scanned': len(ports),
                    'sample_ports': port_list,
                    'description': f'Port scanning detected: {src} scanned {len(ports)} ports on {dst}'
                })

    def _check_syn_flood(self, packets: List[Dict]):
        """Detect SYN flood attacks"""
        syn_count = Counter()
        syn_by_dst = defaultdict(list)

        for pkt in packets:
            if pkt.get('src_ip') and pkt.get('protocol') == 'TCP':
                syn_count[pkt['src_ip']] += 1
                syn_by_dst[pkt.get('dst_ip', 'unknown')].append(pkt['src_ip'])

        for src, count in syn_count.items():
            if count > 30:
                self._add_threat({
                    'type': 'syn_flood',
                    'severity': 'critical',
                    'source': src,
                    'packet_count': count,
                    'description': f'Possible SYN flood from {src} ({count} TCP packets detected)'
                })

    def _check_brute_force(self, packets: List[Dict]):
        """Detect brute force attempts"""
        failed_attempts = defaultdict(int)
        service_ports = {22: 'SSH', 3389: 'RDP', 21: 'FTP', 445: 'SMB', 139: 'NetBIOS'}

        for pkt in packets:
            dst_port = pkt.get('dst_port')
            if dst_port in service_ports and pkt.get('src_ip'):
                key = (pkt['src_ip'], dst_port)
                failed_attempts[key] += 1

        for (src, port), count in failed_attempts.items():
            if count > 10:
                port_name = service_ports.get(port, f'Port {port}')
                self._add_threat({
                    'type': 'brute_force',
                    'severity': 'high',
                    'source': src,
                    'target_port': port,
                    'port_service': port_name,
                    'attempt_count': count,
                    'description': f'Brute force on {port_name}: {src} made {count} connection attempts'
                })

    def _check_suspicious_ports(self, packets: List[Dict]):
        """Flag suspicious port usage - deduplicated"""
        seen = set()

        for pkt in packets:
            dst_port = pkt.get('dst_port')
            if dst_port in self.SUSPICIOUS_PORTS:
                key = (pkt.get('src_ip'), pkt.get('dst_ip'), dst_port)
                if key not in seen:
                    seen.add(key)
                    self._add_threat({
                        'type': 'suspicious_port',
                        'severity': 'high',
                        'source': pkt.get('src_ip'),
                        'destination': pkt.get('dst_ip'),
                        'port': dst_port,
                        'port_purpose': self.SUSPICIOUS_PORTS[dst_port],
                        'description': f'Suspicious port {dst_port} ({self.SUSPICIOUS_PORTS[dst_port]}) detected'
                    })

    def _check_data_exfiltration(self, packets: List[Dict], statistics: Dict):
        """Detect potential data exfiltration"""
        outbound_data = Counter()
        outbound_counts = Counter()

        for pkt in packets:
            if pkt.get('src_ip') and pkt.get('payload_size'):
                outbound_data[pkt['src_ip']] += pkt.get('payload_size', 0)
                outbound_counts[pkt['src_ip']] += 1

        for src, total_size in outbound_data.items():
            if total_size > 5 * 1024 * 1024:  # More than 5MB
                pkt_count = outbound_counts[src]
                self._add_threat({
                    'type': 'data_exfiltration',
                    'severity': 'high',
                    'source': src,
                    'data_size_mb': round(total_size / (1024 * 1024), 2),
                    'packet_count': pkt_count,
                    'description': f'High data transfer from {src}: {total_size / (1024*1024):.2f}MB in {pkt_count} packets'
                })

    def _check_dns_anomalies(self, packets: List[Dict]):
        """Detect DNS-based anomalies"""
        dns_packets = [p for p in packets if p.get('dns_query')]
        dns_by_src = defaultdict(int)
        long_queries = []

        for pkt in dns_packets:
            dns_by_src[pkt.get('src_ip', 'unknown')] += 1
            if pkt.get('dns_query'):
                queries = pkt['dns_query'].get('queries', [])
                for q in queries:
                    if len(q) > 50:  # Unusually long DNS query
                        long_queries.append((pkt.get('src_ip'), q))

        # High DNS activity
        if len(dns_packets) > 50:
            self._add_threat({
                'type': 'dns_anomaly',
                'severity': 'medium',
                'packet_count': len(dns_packets),
                'description': f'High DNS activity ({len(dns_packets)} queries) - possible tunneling or reconnaissance'
            })

        # Unusually long DNS queries (exfiltration indicator)
        if long_queries:
            for src, query in long_queries[:3]:  # Report top 3
                self.threats.append({
                    'type': 'dns_exfiltration',
                    'severity': 'medium',
                    'source': src,
                    'query_length': len(query),
                    'description': f'Suspiciously long DNS query ({len(query)} chars) from {src}'
                })

    def _check_unusual_traffic_volume(self, packets: List[Dict], statistics: Dict):
        """Detect unusual traffic volume patterns"""
        if not packets:
            return

        avg_packet_size = statistics.get('average_packet_size', 0)
        total_packets = len(packets)

        # Check for mostly large packets (potential data transfer)
        large_packets = sum(1 for p in packets if p.get('length', 0) > 1000)
        if large_packets > total_packets * 0.8:
            self._add_threat({
                'type': 'unusual_traffic',
                'severity': 'low',
                'large_packet_count': large_packets,
                'percentage': round((large_packets / total_packets) * 100, 1),
                'description': f'Unusually large packets: {large_packets}/{total_packets} packets exceed 1000 bytes'
            })

    def _check_protocol_anomalies(self, statistics: Dict):
        """Detect unusual protocol usage"""
        protocols = statistics.get('protocol_breakdown', {})

        if not protocols:
            return

        # Extract counts from protocol_breakdown (which has {'count': int, 'percentage': float})
        total = sum(p.get('count', 0) if isinstance(p, dict) else p for p in protocols.values())

        # Check for unusual protocol ratios
        for proto, proto_data in protocols.items():
            count = proto_data.get('count', 0) if isinstance(proto_data, dict) else proto_data
            percentage = (count / total) * 100 if total > 0 else 0

            # Warning if ICMP is more than 30%
            if proto == 'ICMP' and percentage > 30:
                self._add_threat({
                    'type': 'protocol_anomaly',
                    'severity': 'medium',
                    'protocol': proto,
                    'percentage': round(percentage, 1),
                    'description': f'Unusual {proto} traffic: {round(percentage, 1)}% of packets'
                })

    def _calculate_risk_score(self):
        """Calculate overall risk score based on threats"""
        severity_weights = {
            'critical': 100,
            'high': 40,
            'medium': 20,
            'low': 5
        }

        self.risk_score = sum(
            severity_weights.get(threat.get('severity'), 0)
            for threat in self.threats
        )

        # Normalize to 0-100
        self.risk_score = min(100, self.risk_score)

    def _count_by_severity(self) -> Dict[str, int]:
        """Count threats by severity level"""
        count = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        for threat in self.threats:
            severity = threat.get('severity', 'low')
            if severity in count:
                count[severity] += 1

        return count

    def _generate_summary(self) -> Dict[str, Any]:
        """Generate human-readable threat summary"""
        summary = {
            'total_threats': len(self.threats),
            'threat_types': Counter(t.get('type') for t in self.threats),
            'critical_found': any(t.get('severity') == 'critical' for t in self.threats),
            'main_concerns': []
        }

        threat_types = Counter(t.get('type') for t in self.threats)
        for threat_type, count in threat_types.most_common(3):
            summary['main_concerns'].append(f"{count}x {threat_type.replace('_', ' ').title()}")

        return summary
