from typing import Dict, List, Any
from collections import Counter


class AIAnalyzer:
    """Generate natural language summaries of packet analysis using rule-based AI"""

    def __init__(self):
        pass

    def generate_summary(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive AI-powered summary of the analysis"""
        
        summary = {
            "overview": self._generate_overview(analysis_data),
            "traffic_analysis": self._analyze_traffic_patterns(analysis_data),
            "threat_summary": self._summarize_threats(analysis_data),
            "network_behavior": self._analyze_network_behavior(analysis_data),
            "recommendations": self._generate_recommendations(analysis_data),
            "key_findings": self._extract_key_findings(analysis_data)
        }
        
        return summary

    def _generate_overview(self, data: Dict) -> str:
        """Generate high-level overview"""
        total_packets = data.get('total_packets', 0)
        file_name = data.get('file_name', 'unknown')
        stats = data.get('statistics', {})
        threats = data.get('threats', {})
        risk_score = threats.get('risk_score', 0)
        
        unique_ips = stats.get('unique_ips_total', 0)
        unique_ports = stats.get('unique_ports', 0)
        
        # Determine traffic volume level
        if total_packets > 10000:
            volume = "high volume"
        elif total_packets > 1000:
            volume = "moderate volume"
        else:
            volume = "low volume"
        
        # Risk level
        if risk_score >= 70:
            risk_desc = "⚠️ HIGH RISK - immediate attention required"
        elif risk_score >= 40:
            risk_desc = "⚡ MEDIUM RISK - investigation recommended"
        else:
            risk_desc = "✅ LOW RISK - normal activity"
        
        overview = f"""Analysis of {file_name} reveals {volume} network traffic with {total_packets:,} packets captured. 
The traffic involves {unique_ips} unique IP addresses communicating across {unique_ports} different ports. 
Security assessment indicates {risk_desc} with an overall risk score of {risk_score}/100."""
        
        return overview

    def _analyze_traffic_patterns(self, data: Dict) -> str:
        """Analyze traffic patterns and protocols"""
        stats = data.get('statistics', {})
        protocol_breakdown = stats.get('protocol_breakdown', {})
        
        if not protocol_breakdown:
            return "No protocol information available."
        
        # Get dominant protocol
        protocols_sorted = sorted(
            protocol_breakdown.items(),
            key=lambda x: x[1].get('count', 0) if isinstance(x[1], dict) else x[1],
            reverse=True
        )
        
        dominant_proto = protocols_sorted[0][0] if protocols_sorted else "Unknown"
        dominant_count = protocols_sorted[0][1].get('count', 0) if isinstance(protocols_sorted[0][1], dict) else protocols_sorted[0][1]
        total_packets = data.get('total_packets', 1)
        dominant_pct = (dominant_count / total_packets * 100) if total_packets > 0 else 0
        
        analysis = f"""Traffic is predominantly {dominant_proto} ({dominant_pct:.1f}%), suggesting """
        
        # Protocol-specific insights
        if dominant_proto == 'TCP':
            analysis += "standard client-server communications, web traffic, or file transfers."
        elif dominant_proto == 'UDP':
            analysis += "streaming media, DNS queries, or real-time communications."
        elif dominant_proto == 'ICMP':
            analysis += "network diagnostics, ping operations, or potential reconnaissance activity."
        elif dominant_proto == 'DNS':
            analysis += "heavy domain name resolution activity, which is typical for web browsing."
        else:
            analysis += f"specialized network activity using {dominant_proto} protocol."
        
        # Check for protocol diversity
        if len(protocol_breakdown) > 5:
            analysis += f" The presence of {len(protocol_breakdown)} different protocols indicates diverse network activity."
        
        # DNS queries
        dns_queries = stats.get('dns_queries', 0)
        if dns_queries > 0:
            analysis += f" Observed {dns_queries} DNS queries, indicating active domain name resolution."
        
        return analysis

    def _summarize_threats(self, data: Dict) -> str:
        """Summarize detected threats"""
        threats_data = data.get('threats', {})
        threat_list = threats_data.get('threats', [])
        
        if not threat_list:
            return "✅ No security threats detected. The network traffic appears normal and benign."
        
        # Group by severity
        severity_counts = Counter(t.get('severity', 'unknown') for t in threat_list)
        
        # Group by type
        type_counts = Counter(t.get('type', 'unknown') for t in threat_list)
        
        summary = f"⚠️ Detected {len(threat_list)} potential security threat(s): "
        
        # Severity breakdown
        severity_parts = []
        for severity in ['critical', 'high', 'medium', 'low']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                severity_parts.append(f"{count} {severity}")
        
        if severity_parts:
            summary += ", ".join(severity_parts) + " severity. "
        
        # Top threat types
        top_threats = type_counts.most_common(3)
        if top_threats:
            summary += "Primary concerns include: "
            threat_descriptions = []
            for threat_type, count in top_threats:
                threat_name = threat_type.replace('_', ' ').title()
                threat_descriptions.append(f"{threat_name} ({count})")
            summary += ", ".join(threat_descriptions) + "."
        
        return summary

    def _analyze_network_behavior(self, data: Dict) -> str:
        """Analyze network behavior and patterns"""
        stats = data.get('statistics', {})
        network_graph = data.get('network_graph', {})
        
        nodes = network_graph.get('nodes', [])
        links = network_graph.get('links', [])
        
        avg_packet_size = stats.get('average_packet_size', 0)
        
        analysis = f"Network topology consists of {len(nodes)} active nodes with {len(links)} communication links. "
        
        # Packet size analysis
        if avg_packet_size > 1000:
            analysis += f"Large average packet size ({avg_packet_size:.0f} bytes) suggests file transfers or bulk data movement. "
        elif avg_packet_size < 100:
            analysis += f"Small average packet size ({avg_packet_size:.0f} bytes) indicates control traffic or keep-alive messages. "
        else:
            analysis += f"Average packet size ({avg_packet_size:.0f} bytes) is typical for mixed network traffic. "
        
        # Top communicators
        top_ips_src = stats.get('top_ips_src', {})
        if top_ips_src:
            top_ip = list(top_ips_src.keys())[0]
            top_count = top_ips_src[top_ip]
            total = data.get('total_packets', 1)
            pct = (top_count / total * 100) if total > 0 else 0
            
            if pct > 50:
                analysis += f"Single IP ({top_ip}) dominates traffic with {pct:.1f}% of packets, indicating centralized communication pattern. "
            elif pct > 20:
                analysis += f"Most active IP ({top_ip}) accounts for {pct:.1f}% of traffic. "
        
        # Connection density
        if len(nodes) > 0:
            avg_connections = len(links) / len(nodes)
            if avg_connections > 3:
                analysis += "High connection density suggests mesh-like communication patterns."
            elif avg_connections < 1.5:
                analysis += "Low connection density indicates point-to-point or centralized communication."
        
        return analysis

    def _generate_recommendations(self, data: Dict) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        threats = data.get('threats', {})
        threat_list = threats.get('threats', [])
        risk_score = threats.get('risk_score', 0)
        
        # Risk-based recommendations
        if risk_score >= 70:
            recommendations.append("🚨 URGENT: Immediately investigate all flagged threats and isolate affected systems")
            recommendations.append("🔒 Implement emergency security measures and review access controls")
        elif risk_score >= 40:
            recommendations.append("⚡ Review and investigate medium-risk threats within 24 hours")
            recommendations.append("📊 Increase monitoring frequency for affected systems")
        else:
            recommendations.append("✅ Continue regular security monitoring and maintain current protection levels")
        
        # Threat-specific recommendations
        threat_types = set(t.get('type', '') for t in threat_list)
        
        if 'port_scan' in threat_types:
            recommendations.append("🔍 Port Scan Detected: Review and restrict unnecessary open ports, update firewall rules")
        
        if 'syn_flood' in threat_types:
            recommendations.append("🌊 SYN Flood Detected: Enable SYN cookies, implement rate limiting, consider DDoS protection")
        
        if 'brute_force' in threat_types:
            recommendations.append("🔐 Brute Force Detected: Enforce strong password policies, implement account lockouts, enable MFA")
        
        if 'data_exfiltration' in threat_types:
            recommendations.append("📤 Data Exfiltration Risk: Implement DLP solutions, monitor outbound traffic, review data access policies")
        
        if 'dns_anomaly' in threat_types:
            recommendations.append("🌐 DNS Anomaly Detected: Implement DNS filtering, monitor for tunneling attempts, use secure DNS")
        
        if 'suspicious_port' in threat_types:
            recommendations.append("⚠️ Suspicious Ports: Block known malicious ports, investigate non-standard service usage")
        
        # General security recommendations
        stats = data.get('statistics', {})
        if stats.get('unique_ports', 0) > 100:
            recommendations.append("🔌 High Port Diversity: Conduct port usage audit and close unnecessary services")
        
        # Always include baseline recommendations
        recommendations.extend([
            "📝 Maintain detailed logs of all network activity for forensic analysis",
            "🔄 Regularly update security policies and incident response procedures",
            "👥 Conduct security awareness training for all network users"
        ])
        
        return recommendations

    def _extract_key_findings(self, data: Dict) -> List[str]:
        """Extract key findings from analysis"""
        findings = []
        
        stats = data.get('statistics', {})
        threats = data.get('threats', {})
        threat_list = threats.get('threats', [])
        
        # Traffic volume finding
        total_packets = data.get('total_packets', 0)
        if total_packets > 0:
            findings.append(f"📊 Analyzed {total_packets:,} packets across network infrastructure")
        
        # Protocol finding
        protocol_breakdown = stats.get('protocol_breakdown', {})
        if protocol_breakdown:
            top_protocol = max(protocol_breakdown.items(), 
                             key=lambda x: x[1].get('count', 0) if isinstance(x[1], dict) else x[1])
            findings.append(f"🔵 {top_protocol[0]} is the dominant protocol in traffic")
        
        # Threat finding
        if threat_list:
            critical_threats = [t for t in threat_list if t.get('severity') == 'critical']
            high_threats = [t for t in threat_list if t.get('severity') == 'high']
            
            if critical_threats:
                findings.append(f"🔴 {len(critical_threats)} CRITICAL threat(s) requiring immediate action")
            if high_threats:
                findings.append(f"🟠 {len(high_threats)} HIGH severity threat(s) detected")
        else:
            findings.append("✅ No immediate security threats identified in traffic")
        
        # Network topology finding
        network_graph = data.get('network_graph', {})
        nodes = network_graph.get('nodes', [])
        if len(nodes) > 20:
            findings.append(f"🌐 Complex network with {len(nodes)} active endpoints")
        elif len(nodes) > 0:
            findings.append(f"🌐 Network involves {len(nodes)} communicating hosts")
        
        # DNS activity
        dns_queries = stats.get('dns_queries', 0)
        if dns_queries > 100:
            findings.append(f"🔍 High DNS activity: {dns_queries} domain lookups recorded")
        
        # Average packet size
        avg_size = stats.get('average_packet_size', 0)
        if avg_size > 1200:
            findings.append(f"📦 Large packet sizes ({avg_size:.0f} bytes avg) suggest bulk data transfer")
        elif avg_size < 100:
            findings.append(f"📦 Small packet sizes ({avg_size:.0f} bytes avg) indicate control traffic")
        
        return findings
