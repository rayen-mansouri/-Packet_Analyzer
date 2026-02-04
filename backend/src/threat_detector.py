from typing import List, Dict, Any
from collections import Counter, defaultdict


class ThreatDetector:
    
    SUSPICIOUS_PORTS = {
        4444: "Remote shell",
        5555: "Reverse shell",
        6666: "IRC botnet",
        8888: "Remote access",
        31337: "Leet backdoor",
        6379: "Redis exploit",
    }
    
    # Common C2 server indicators
    C2_INDICATORS = [
        'beacon',
        'command',
        'control',
        'callback',
        'exfil',
        'backdoor'
    ]
    
    def __init__(self):
        self.threats = []
        self.risk_score = 0
    
    def analyze(self, packet_data: List[Dict], statistics: Dict) -> Dict[str, Any]:
        """Run comprehensive threat analysis"""
        
        self.threats = []
        
        # Run individual checks
        self._check_port_scanning(packet_data)
        self._check_syn_flood(packet_data)
        self._check_brute_force(packet_data)
        self._check_suspicious_ports(packet_data)
        self._check_data_exfiltration(packet_data)
        self._check_dns_tunneling(packet_data)
        self._calculate_risk_score()
        
        return {
            'threats': self.threats,
            'risk_score': self.risk_score,
            'severity_count': self._count_by_severity()
        }
    
    def _check_port_scanning(self, packets: List[Dict]):
        """Detect port scanning attempts"""
        
        src_dst_ports = defaultdict(set)
        
        for pkt in packets:
            if pkt['src_ip'] and pkt['dst_ip'] and pkt['dst_port']:
                key = (pkt['src_ip'], pkt['dst_ip'])
                src_dst_ports[key].add(pkt['dst_port'])
        
        for (src, dst), ports in src_dst_ports.items():
            if len(ports) > 5:  # Multiple ports to same destination
                self.threats.append({
                    'type': 'port_scan',
                    'severity': 'high',
                    'source': src,
                    'destination': dst,
                    'ports_scanned': len(ports),
                    'description': f'Port scanning detected: {src} scanned {len(ports)} ports on {dst}'
                })
    
    def _check_syn_flood(self, packets: List[Dict]):
        """Detect SYN flood attacks"""
        
        syn_count = Counter()
        
        for pkt in packets:
            if pkt['src_ip'] and pkt['protocol'] == 'TCP':
                syn_count[pkt['src_ip']] += 1
        
        for src, count in syn_count.items():
            if count > 50:  # High number of SYN packets from one source
                self.threats.append({
                    'type': 'syn_flood',
                    'severity': 'critical',
                    'source': src,
                    'packet_count': count,
                    'description': f'Possible SYN flood from {src} ({count} packets)'
                })
    
    def _check_brute_force(self, packets: List[Dict]):
        """Detect brute force attempts"""
        
        failed_attempts = defaultdict(int)
        
        for pkt in packets:
            # Check for repeated connection attempts on SSH, RDP, or FTP
            if pkt['dst_port'] in [22, 3389, 21]:  # SSH, RDP, FTP
                if pkt['src_ip']:
                    key = (pkt['src_ip'], pkt['dst_port'])
                    failed_attempts[key] += 1
        
        for (src, port), count in failed_attempts.items():
            if count > 10:
                port_name = {22: 'SSH', 3389: 'RDP', 21: 'FTP'}.get(port)
                self.threats.append({
                    'type': 'brute_force',
                    'severity': 'high',
                    'source': src,
                    'target_port': port,
                    'port_service': port_name,
                    'attempt_count': count,
                    'description': f'Brute force attack on {port_name}: {src} made {count} attempts'
                })
    
    def _check_suspicious_ports(self, packets: List[Dict]):
        """Flag suspicious port usage"""
        
        for pkt in packets:
            if pkt['dst_port'] in self.SUSPICIOUS_PORTS:
                self.threats.append({
                    'type': 'suspicious_port',
                    'severity': 'high',
                    'source': pkt['src_ip'],
                    'destination': pkt['dst_ip'],
                    'port': pkt['dst_port'],
                    'port_purpose': self.SUSPICIOUS_PORTS[pkt['dst_port']],
                    'description': f'Suspicious port {pkt["dst_port"]} ({self.SUSPICIOUS_PORTS[pkt["dst_port"]]}) in use'
                })
    
    def _check_data_exfiltration(self, packets: List[Dict]):
        """Detect potential data exfiltration"""
        
        outbound_data = Counter()
        
        for pkt in packets:
            if pkt['src_ip'] and pkt['payload_size']:
                outbound_data[pkt['src_ip']] += pkt.get('payload_size', 0)
        
        for src, total_size in outbound_data.items():
            if total_size > 10 * 1024 * 1024:  # More than 10MB
                self.threats.append({
                    'type': 'data_exfiltration',
                    'severity': 'high',
                    'source': src,
                    'data_size_mb': total_size / (1024 * 1024),
                    'description': f'Potential data exfiltration from {src} ({total_size / (1024*1024):.2f}MB)'
                })
    
    def _check_dns_tunneling(self, packets: List[Dict]):
        """Detect DNS-based data tunneling"""
        
        dns_packets = [p for p in packets if 'dns_query' in p]
        
        if len(dns_packets) > len(packets) * 0.5:  # More than 50% DNS traffic
            self.threats.append({
                'type': 'dns_tunneling',
                'severity': 'medium',
                'packet_count': len(dns_packets),
                'description': f'High DNS activity ({len(dns_packets)} queries) - possible DNS tunneling'
            })
    
    def _calculate_risk_score(self):
        """Calculate overall risk score"""
        
        severity_weights = {
            'critical': 100,
            'high': 50,
            'medium': 25,
            'low': 10
        }
        
        self.risk_score = sum(
            severity_weights.get(threat['severity'], 0)
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
