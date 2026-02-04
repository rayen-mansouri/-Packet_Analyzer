import os
from typing import Dict, Any, List
import requests
import json
import re


class AIChatbot:
    """AI-powered chatbot using Groq (100% FREE - works when hosted!)"""

    def __init__(self):
        # Initialize Groq configuration (FREE and works everywhere!)
        self.api_key = os.getenv("GROQ_API_KEY", "").strip()
        self.model = os.getenv("GROQ_MODEL", "mixtral-8x7b-32768").strip()
        self.api_url = "https://api.groq.com/openai/v1/chat/completions"
        
        if not self.api_key or self.api_key == "your_groq_key_here":
            print("⚠️ Groq API key not set. Using fallback mode.")
            print("Get your FREE API key at: https://console.groq.com/keys")
            self.client = None
        else:
            print(f"✓ Groq API configured with model: {self.model}")
            self.client = "groq"
        
        self.conversation_history = []
        self.analysis_context = None
        self.context_summary = ""

    def set_analysis_context(self, analysis_data: Dict[str, Any]):
        """Set the packet analysis context for the chatbot"""
        self.analysis_context = analysis_data
        self.conversation_history = []
        
        # Create a comprehensive summary of the analysis for context
        self.context_summary = self._create_context_summary(analysis_data)

    def chat(self, user_message: str) -> str:
        """Process a chat message and return AI response"""
        
        if not self.client:
            return self._fallback_response()
        
        try:
            # Check if user is asking about a specific packet number
            packet_detail_context = ""
            match = re.search(r"\bpacket\s*#?(\d+)\b", user_message, re.IGNORECASE)
            if match and self.analysis_context:
                packet_num = int(match.group(1))
                packets = self.analysis_context.get('packets', [])
                if 1 <= packet_num <= len(packets):
                    packet = packets[packet_num - 1]  # Convert to 0-based index
                    packet_detail_context = f"\n\nREQUESTED PACKET DETAILS (1-based table index):\nPacket #{packet_num}: protocol={packet.get('protocol')}, src_ip={packet.get('src_ip')}, dst_ip={packet.get('dst_ip')}, src_port={packet.get('src_port')}, dst_port={packet.get('dst_port')}, length={packet.get('length')}, info={packet.get('info', 'N/A')}, timestamp={packet.get('timestamp')}"
                    
            # Build context-aware prompt
            system_message = f"""You are a network security analyst. Analyze this packet capture data and answer the user's question.

PACKET DATA SUMMARY:
{self.context_summary[:2000]}{packet_detail_context}

PACKET INDEXING: Packet numbers refer to the table order (1-based) in the Packet Inspector.

Instructions:
- Be concise (2-3 sentences)
- Base answers on the actual data provided
- Focus on security insights"""
            
            # Add user message to history
            self.conversation_history.append({
                "role": "user",
                "content": user_message
            })
            
            # Keep only last 10 messages for context
            messages_to_send = self.conversation_history[-10:]
            
            # Call Groq API
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_message}
                ] + messages_to_send,
                "temperature": 0.7,
                "max_tokens": 500,
                "top_p": 1
            }
            
            response = requests.post(
                self.api_url,
                headers=headers,
                json=payload,
                timeout=30
            )
            
            # Handle different response codes
            if response.status_code == 401:
                return "❌ Groq API key is invalid. Get a new one at https://console.groq.com/keys"
            elif response.status_code == 400:
                error_detail = response.json().get('error', {}).get('message', response.text)
                print(f"[DEBUG] 400 Error: {error_detail}")
                print(f"[DEBUG] Payload: {json.dumps(payload, indent=2)}")
                return f"❌ API Error: 400 - {error_detail[:100]}"
            elif response.status_code == 429:
                return "⚠️ Rate limit hit. Please wait a moment and try again."
            elif response.status_code >= 500:
                return "⚠️ Groq service temporarily unavailable. Try again in a moment."
            elif response.status_code != 200:
                return f"❌ API Error: {response.status_code} - {response.text[:100]}"
            
            # Parse response
            result = response.json()
            
            if "choices" not in result or len(result["choices"]) == 0:
                return "❌ No response from AI. Please try again."
            
            ai_response = result["choices"][0]["message"]["content"]
            
            # Add to history
            self.conversation_history.append({
                "role": "assistant",
                "content": ai_response
            })
            
            return ai_response
            
        except requests.exceptions.Timeout:
            return "⏱️ Request timeout. Groq might be busy. Try again in a moment."
        except requests.exceptions.ConnectionError:
            return "❌ Connection error. Check your internet connection."
        except Exception as e:
            return f"❌ Error: {str(e)[:100]}"

    def _create_context_summary(self, analysis_data: Dict[str, Any]) -> str:
        """Create a DETAILED summary of packet analysis for AI context"""
        
        try:
            summary = ""
            
            # FILE INFO
            file_name = analysis_data.get('file_name', 'Unknown')
            summary += f"FILE: {file_name}\n"
            
            # BASIC STATS
            total_packets = analysis_data.get('total_packets', 0)
            summary += f"TOTAL PACKETS: {total_packets:,}\n"
            
            # STATISTICS (detailed)
            stats = analysis_data.get('statistics', {})
            if stats:
                summary += f"\nSTATISTICS:\n"
                summary += f"- Unique Source IPs: {stats.get('unique_ips_src', 0)}\n"
                summary += f"- Unique Destination IPs: {stats.get('unique_ips_dst', 0)}\n"
                summary += f"- Unique Ports: {stats.get('unique_ports', 0)}\n"
                summary += f"- Average Packet Size: {stats.get('average_packet_size', 0):.0f} bytes\n"
                summary += f"- Total Data Volume: {stats.get('total_bytes', 0):,} bytes\n"
                
                # PROTOCOL BREAKDOWN
                protocol_breakdown = stats.get('protocol_breakdown', {})
                if protocol_breakdown:
                    summary += f"\nPROTOCOL BREAKDOWN:\n"
                    for proto, data in sorted(protocol_breakdown.items(), key=lambda x: x[1].get('count', 0) if isinstance(x[1], dict) else x[1], reverse=True)[:10]:
                        count = data.get('count', 0) if isinstance(data, dict) else data
                        pct = (count / total_packets * 100) if total_packets > 0 else 0
                        summary += f"- {proto}: {count:,} packets ({pct:.1f}%)\n"
                
                # TOP SOURCE IPs
                top_src = stats.get('top_ips_src', {})
                if top_src:
                    summary += f"\nTOP SOURCE IP ADDRESSES:\n"
                    for ip, count in list(top_src.items())[:10]:
                        summary += f"- {ip}: {count:,} packets\n"
                
                # TOP DESTINATION IPs
                top_dst = stats.get('top_ips_dst', {})
                if top_dst:
                    summary += f"\nTOP DESTINATION IP ADDRESSES:\n"
                    for ip, count in list(top_dst.items())[:10]:
                        summary += f"- {ip}: {count:,} packets\n"
                
                # TOP PORTS
                top_ports = stats.get('top_ports', {})
                if top_ports:
                    summary += f"\nTOP PORTS:\n"
                    for port, count in list(top_ports.items())[:10]:
                        summary += f"- Port {port}: {count:,} packets\n"
                
                # DNS QUERIES
                dns_count = stats.get('dns_queries', 0)
                if dns_count > 0:
                    summary += f"\nDNS QUERIES: {dns_count}\n"
            
            # THREATS
            threats = analysis_data.get('threats', {})
            if threats:
                summary += f"\nTHREAT ANALYSIS:\n"
                summary += f"- Risk Score: {threats.get('risk_score', 0)}/100\n"
                
                threat_list = threats.get('threats', [])
                if threat_list:
                    summary += f"- Threats Detected: {len(threat_list)}\n"
                    for i, threat in enumerate(threat_list[:10], 1):
                        threat_type = threat.get('type', 'Unknown')
                        severity = threat.get('severity', 'Unknown')
                        description = threat.get('description', '')
                        source = threat.get('source', '')
                        summary += f"  {i}. [{severity}] {threat_type}: {description}"
                        if source:
                            summary += f" (from {source})"
                        summary += "\n"
            
            return summary.strip()
        
        except Exception as e:
            print(f"Error in context summary: {e}")
            return f"Error: {str(e)}"

    def _fallback_response(self) -> str:
        """Fallback response when API is not available"""
        
        if not self.analysis_context:
            return """👋 Hello! I'm your packet analysis assistant powered by Groq AI.

However, the API key is not configured. To get started:
1. Visit https://console.groq.com/keys
2. Sign up with Google/GitHub (totally free)
3. Copy your API key
4. Add it to backend/.env as: GROQ_API_KEY=your_key_here
5. Restart the backend

Groq is 100% free with unlimited requests! No credit card needed."""
        
        return """I'm currently running in limited mode. Please check your Groq API key configuration."""

    def clear_history(self):
        """Clear conversation history"""
        self.conversation_history = []
