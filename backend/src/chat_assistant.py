from typing import Dict, Any


class ChatAssistant:
    """AI chatbot for answering questions about packet analysis"""

    def __init__(self):
        pass

    def process_query(self, message: str, analysis_data: Dict[str, Any]) -> str:
        """Process user query and generate response based on analysis data"""
        
        message_lower = message.lower()
        
        # Greetings and casual conversation
        if any(word in message_lower for word in ['hi', 'hello', 'hey', 'yo', 'sup', 'greetings']):
            return "👋 Hello! I'm your AI packet analysis assistant. I've analyzed your network capture and I'm ready to answer any questions. What would you like to know about the traffic?"
        
        if any(phrase in message_lower for phrase in ['how are you', 'whats up', 'what\'s up', 'whats going on']):
            total_packets = analysis_data.get('total_packets', 0)
            risk_score = analysis_data.get('threats', {}).get('risk_score', 0)
            return f"I'm doing great! I just finished analyzing {total_packets:,} packets from your capture. Risk score is {risk_score}/100. Ask me anything about it!"
        
        if 'thank' in message_lower:
            return "You're welcome! Let me know if you need anything else about your packet analysis."
        
        # Specific IP search
        if any(word in message_lower for word in ['192.', '10.', '172.', '8.8.', '1.1.']) or message_lower.count('.') >= 3:
            return self._search_specific_ip(message, analysis_data)
        
        # Extract key data
        stats = analysis_data.get('statistics', {})
        threats = analysis_data.get('threats', {})
        threat_list = threats.get('threats', [])
        total_packets = analysis_data.get('total_packets', 0)
        risk_score = threats.get('risk_score', 0)
        
        # Risk/threat related queries
        if any(word in message_lower for word in ['risk', 'danger', 'safe', 'secure']):
            return self._answer_risk_query(risk_score, threat_list)
        
        # Threat specific queries
        if any(word in message_lower for word in ['threat', 'attack', 'malicious', 'suspicious']):
            return self._answer_threat_query(threat_list, risk_score)
        
        # Protocol queries
        if any(word in message_lower for word in ['protocol', 'tcp', 'udp', 'icmp', 'dns']):
            return self._answer_protocol_query(stats, total_packets)
        
        # IP related queries
        if any(word in message_lower for word in ['ip', 'address', 'host', 'source', 'destination']):
            return self._answer_ip_query(stats)
        
        # Port queries
        if any(word in message_lower for word in ['port', 'service']):
            return self._answer_port_query(stats)
        
        # Traffic volume queries
        if any(word in message_lower for word in ['traffic', 'volume', 'packets', 'how many', 'size']):
            return self._answer_traffic_query(stats, total_packets)
        
        # DNS queries
        if 'dns' in message_lower or 'domain' in message_lower:
            return self._answer_dns_query(stats)
        
        # Summary/overview queries
        if any(word in message_lower for word in ['summary', 'overview', 'explain', 'what is', 'tell me']):
            return self._answer_summary_query(analysis_data)
        
        # Recommendation queries
        if any(word in message_lower for word in ['recommend', 'should', 'what to do', 'fix', 'solve']):
            return self._answer_recommendation_query(threat_list, risk_score)
        
        # Default response
        return self._default_response(analysis_data)

    def _answer_risk_query(self, risk_score: int, threats: list) -> str:
        """Answer questions about risk level"""
        if risk_score >= 70:
            level = "HIGH RISK ⚠️"
            advice = "Immediate action is required. Multiple serious threats were detected that could compromise network security."
        elif risk_score >= 40:
            level = "MEDIUM RISK ⚡"
            advice = "There are some concerning patterns that should be investigated within 24 hours."
        else:
            level = "LOW RISK ✅"
            advice = "The network traffic appears relatively normal with minimal security concerns."
        
        threat_count = len(threats)
        return f"""Your network has a **{level}** with a risk score of {risk_score}/100.

{advice}

I detected {threat_count} potential threat(s) in the captured traffic. Would you like more details about specific threats?"""

    def _answer_threat_query(self, threats: list, risk_score: int) -> str:
        """Answer questions about threats"""
        if not threats:
            return "✅ Good news! No security threats were detected in this packet capture. The traffic appears benign."
        
        # Group by severity
        critical = [t for t in threats if t.get('severity') == 'critical']
        high = [t for t in threats if t.get('severity') == 'high']
        medium = [t for t in threats if t.get('severity') == 'medium']
        low = [t for t in threats if t.get('severity') == 'low']
        
        response = f"I detected {len(threats)} threat(s):\n\n"
        
        if critical:
            response += f"🔴 **CRITICAL** ({len(critical)}): "
            response += ", ".join([t.get('type', 'unknown').replace('_', ' ').title() for t in critical[:3]])
            response += "\n"
        
        if high:
            response += f"🟠 **HIGH** ({len(high)}): "
            response += ", ".join([t.get('type', 'unknown').replace('_', ' ').title() for t in high[:3]])
            response += "\n"
        
        if medium:
            response += f"🟡 **MEDIUM** ({len(medium)}): "
            response += ", ".join([t.get('type', 'unknown').replace('_', ' ').title() for t in medium[:3]])
            response += "\n"
        
        if low:
            response += f"🟢 **LOW** ({len(low)}): "
            response += ", ".join([t.get('type', 'unknown').replace('_', ' ').title() for t in low[:3]])
        
        response += f"\n\nMost critical concern: **{threats[0].get('type', 'Unknown').replace('_', ' ').title()}**"
        response += f"\n{threats[0].get('description', 'No description available')}"
        
        return response

    def _answer_protocol_query(self, stats: Dict, total_packets: int) -> str:
        """Answer questions about protocols"""
        protocol_breakdown = stats.get('protocol_breakdown', {})
        
        if not protocol_breakdown:
            return "No protocol information is available in this analysis."
        
        response = "**Protocol Distribution:**\n\n"
        
        sorted_protocols = sorted(
            protocol_breakdown.items(),
            key=lambda x: x[1].get('count', 0) if isinstance(x[1], dict) else x[1],
            reverse=True
        )
        
        for proto, data in sorted_protocols[:5]:
            count = data.get('count', 0) if isinstance(data, dict) else data
            pct = (count / total_packets * 100) if total_packets > 0 else 0
            response += f"• **{proto}**: {count:,} packets ({pct:.1f}%)\n"
        
        dominant = sorted_protocols[0][0] if sorted_protocols else "Unknown"
        response += f"\n{dominant} is the dominant protocol, which is "
        
        if dominant == 'TCP':
            response += "typical for web traffic, file transfers, and reliable communications."
        elif dominant == 'UDP':
            response += "common for streaming, gaming, and DNS queries."
        elif dominant == 'ICMP':
            response += "often used for network diagnostics but can also indicate reconnaissance."
        elif dominant == 'DNS':
            response += "normal for internet browsing and domain name resolution."
        else:
            response += "specific to certain types of network applications."
        
        return response

    def _answer_ip_query(self, stats: Dict) -> str:
        """Answer questions about IP addresses"""
        top_src = stats.get('top_ips_src', {})
        top_dst = stats.get('top_ips_dst', {})
        unique_src = stats.get('unique_ips_src', 0)
        unique_dst = stats.get('unique_ips_dst', 0)
        
        response = f"**IP Address Analysis:**\n\n"
        response += f"• {unique_src} unique source IP(s)\n"
        response += f"• {unique_dst} unique destination IP(s)\n\n"
        
        if top_src:
            response += "**Top Talkers (Source IPs):**\n"
            for ip, count in list(top_src.items())[:5]:
                response += f"• {ip}: {count:,} packets\n"
        
        return response

    def _answer_port_query(self, stats: Dict) -> str:
        """Answer questions about ports"""
        top_ports = stats.get('top_ports', {})
        unique_ports = stats.get('unique_ports', 0)
        
        response = f"**Port Analysis:**\n\n"
        response += f"Detected {unique_ports} unique port(s)\n\n"
        
        if top_ports:
            response += "**Most Active Ports:**\n"
            for port, count in list(top_ports.items())[:8]:
                service = self._identify_port_service(int(port))
                response += f"• Port {port} ({service}): {count:,} packets\n"
        
        return response

    def _answer_traffic_query(self, stats: Dict, total_packets: int) -> str:
        """Answer questions about traffic volume"""
        avg_size = stats.get('average_packet_size', 0)
        
        response = f"**Traffic Volume Analysis:**\n\n"
        response += f"• Total Packets: {total_packets:,}\n"
        response += f"• Average Packet Size: {avg_size:.0f} bytes\n\n"
        
        if avg_size > 1000:
            response += "The large packet sizes suggest bulk data transfer or file downloads."
        elif avg_size < 100:
            response += "The small packet sizes indicate control traffic or keep-alive messages."
        else:
            response += "The packet sizes are typical for mixed network traffic."
        
        return response

    def _answer_dns_query(self, stats: Dict) -> str:
        """Answer questions about DNS"""
        dns_queries = stats.get('dns_queries', 0)
        
        if dns_queries == 0:
            return "No DNS queries were detected in this capture."
        
        response = f"**DNS Activity:**\n\n"
        response += f"Detected {dns_queries} DNS quer{'y' if dns_queries == 1 else 'ies'}.\n\n"
        
        if dns_queries > 100:
            response += "This is high DNS activity, which could indicate:\n"
            response += "• Heavy web browsing\n"
            response += "• Multiple applications making network requests\n"
            response += "• Possible DNS tunneling (if excessive)\n"
        else:
            response += "This is normal DNS activity for typical internet usage."
        
        return response

    def _answer_summary_query(self, data: Dict) -> str:
        """Answer summary/overview questions"""
        total_packets = data.get('total_packets', 0)
        stats = data.get('statistics', {})
        threats = data.get('threats', {})
        risk_score = threats.get('risk_score', 0)
        threat_count = len(threats.get('threats', []))
        
        protocol_breakdown = stats.get('protocol_breakdown', {})
        dominant_protocol = "Unknown"
        if protocol_breakdown:
            dominant_protocol = max(
                protocol_breakdown.items(),
                key=lambda x: x[1].get('count', 0) if isinstance(x[1], dict) else x[1]
            )[0]
        
        response = f"**Analysis Summary:**\n\n"
        response += f"📊 Analyzed {total_packets:,} packets\n"
        response += f"🔵 Primary protocol: {dominant_protocol}\n"
        response += f"🌐 {stats.get('unique_ips_total', 0)} unique IP addresses\n"
        response += f"🔌 {stats.get('unique_ports', 0)} unique ports\n"
        response += f"⚠️ {threat_count} threat(s) detected\n"
        response += f"📈 Risk Score: {risk_score}/100\n\n"
        
        if risk_score >= 70:
            response += "⚠️ HIGH RISK - Immediate investigation required!"
        elif risk_score >= 40:
            response += "⚡ MEDIUM RISK - Review recommended"
        else:
            response += "✅ LOW RISK - Traffic appears normal"
        
        return response

    def _answer_recommendation_query(self, threats: list, risk_score: int) -> str:
        """Answer questions about recommendations"""
        if risk_score < 40 and len(threats) == 0:
            return """**Recommendations:**

✅ Your network appears secure. Continue with:
• Regular monitoring of traffic patterns
• Keeping security systems updated
• Maintaining current security policies
• Periodic packet capture analysis"""
        
        response = "**Security Recommendations:**\n\n"
        
        if risk_score >= 70:
            response += "🚨 **URGENT ACTIONS:**\n"
            response += "1. Immediately investigate all flagged threats\n"
            response += "2. Isolate affected systems if necessary\n"
            response += "3. Review and strengthen firewall rules\n"
            response += "4. Contact security team for incident response\n\n"
        
        threat_types = set(t.get('type', '') for t in threats)
        
        if 'port_scan' in threat_types:
            response += "• **Port Scanning**: Close unnecessary ports, update firewall rules\n"
        
        if 'syn_flood' in threat_types:
            response += "• **SYN Flood**: Enable SYN cookies, implement rate limiting\n"
        
        if 'brute_force' in threat_types:
            response += "• **Brute Force**: Enforce strong passwords, enable MFA, implement lockouts\n"
        
        if 'data_exfiltration' in threat_types:
            response += "• **Data Exfiltration**: Review DLP policies, monitor outbound traffic\n"
        
        response += "\n💡 Always maintain updated logs and conduct regular security audits."
        
        return response

    def _default_response(self, data: Dict) -> str:
        """Default response when query intent is unclear"""
        return """I can help you understand your packet analysis! Ask me about:

• **Threats**: "What threats were detected?"
• **Risk**: "How safe is my network?"
• **Protocols**: "What protocols are being used?"
• **IPs**: "Show me the IP addresses"
• **Ports**: "What ports are active?"
• **Traffic**: "How much traffic was captured?"
• **Recommendations**: "What should I do?"

What would you like to know?"""

    def _identify_port_service(self, port: int) -> str:
        """Identify common services by port number"""
        services = {
            20: 'FTP Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
            143: 'IMAP', 443: 'HTTPS', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 8080: 'HTTP Alt', 8443: 'HTTPS Alt'
        }
        return services.get(port, 'Unknown')

    def _search_specific_ip(self, message: str, data: Dict) -> str:
        """Search for a specific IP address in the analysis"""
        import re
        
        # Extract IP address from message
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips_in_message = re.findall(ip_pattern, message)
        
        if not ips_in_message:
            return "I didn't find a valid IP address in your question. Please provide an IP in the format: 192.168.1.1"
        
        search_ip = ips_in_message[0]
        stats = data.get('statistics', {})
        packets = data.get('packets', [])
        
        # Search in top IPs
        top_src = stats.get('top_ips_src', {})
        top_dst = stats.get('top_ips_dst', {})
        
        found_as_src = search_ip in top_src
        found_as_dst = search_ip in top_dst
        
        if not found_as_src and not found_as_dst:
            # Check in all packets (sample)
            found_in_packets = any(
                p.get('src_ip') == search_ip or p.get('dst_ip') == search_ip 
                for p in packets
            )
            
            if found_in_packets:
                return f"✅ Yes, **{search_ip}** appears in the capture, but with low activity (not in top communicators)."
            else:
                return f"❌ No, **{search_ip}** was not found in this packet capture. The IP might not have been active during the capture period."
        
        response = f"✅ Yes, **{search_ip}** is in the capture!\n\n"
        
        if found_as_src:
            count = top_src[search_ip]
            response += f"• As **source**: {count:,} packets sent\n"
        
        if found_as_dst:
            count = top_dst[search_ip]
            response += f"• As **destination**: {count:,} packets received\n"
        
        # Check if it's in threats
        threats = data.get('threats', {}).get('threats', [])
        threat_ips = [t.get('source') for t in threats if t.get('source') == search_ip]
        
        if threat_ips:
            response += f"\n⚠️ **WARNING**: This IP was flagged as a potential threat!"
        
        return response
