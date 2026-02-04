from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.pdfgen import canvas
from datetime import datetime
import io
from typing import Dict, Any, List


class PDFReportGenerator:
    """Generate professional PDF reports for packet analysis"""

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Create custom styles for the report"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#00d4ff'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))

        # Section header
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#00ff88'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))

        # Threat title
        self.styles.add(ParagraphStyle(
            name='ThreatTitle',
            parent=self.styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#ff4444'),
            spaceAfter=6,
            fontName='Helvetica-Bold'
        ))

        # Info text
        self.styles.add(ParagraphStyle(
            name='InfoText',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#333333'),
            spaceAfter=6
        ))

    def generate_report(self, analysis_data: Dict[str, Any]) -> io.BytesIO:
        """Generate comprehensive PDF report"""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter,
                                rightMargin=72, leftMargin=72,
                                topMargin=72, bottomMargin=18)

        # Container for the 'Flowable' objects
        elements = []

        # Add content sections
        elements.extend(self._create_cover_page(analysis_data))
        elements.append(PageBreak())
        
        elements.extend(self._create_executive_summary(analysis_data))
        elements.append(Spacer(1, 0.2 * inch))
        
        elements.extend(self._create_statistics_section(analysis_data))
        elements.append(Spacer(1, 0.2 * inch))
        
        elements.extend(self._create_threat_section(analysis_data))
        elements.append(Spacer(1, 0.2 * inch))
        
        elements.extend(self._create_network_section(analysis_data))
        elements.append(Spacer(1, 0.2 * inch))
        
        elements.extend(self._create_recommendations(analysis_data))

        # Build PDF
        doc.build(elements)
        buffer.seek(0)
        return buffer

    def _create_cover_page(self, data: Dict) -> List:
        """Create cover page"""
        elements = []
        
        # Title
        elements.append(Spacer(1, 2 * inch))
        title = Paragraph("📊 Packet Analysis Report", self.styles['CustomTitle'])
        elements.append(title)
        elements.append(Spacer(1, 0.5 * inch))

        # File info
        file_name = data.get('file_name', 'Unknown')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        info_data = [
            ['File Name:', file_name],
            ['Analysis Date:', timestamp],
            ['Total Packets:', str(data.get('total_packets', 0))],
            ['Risk Score:', f"{data.get('threats', {}).get('risk_score', 0)}/100"]
        ]
        
        info_table = Table(info_data, colWidths=[2*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#00d4ff')),
            ('TEXTCOLOR', (1, 0), (1, -1), colors.HexColor('#333333')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ]))
        
        elements.append(info_table)
        return elements

    def _create_executive_summary(self, data: Dict) -> List:
        """Create executive summary section"""
        elements = []
        
        elements.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        
        threats = data.get('threats', {})
        risk_score = threats.get('risk_score', 0)
        threat_count = len(threats.get('threats', []))
        total_packets = data.get('total_packets', 0)
        
        # Risk assessment
        if risk_score >= 70:
            risk_level = "HIGH RISK"
            risk_color = colors.HexColor('#ff4444')
        elif risk_score >= 40:
            risk_level = "MEDIUM RISK"
            risk_color = colors.HexColor('#ffaa00')
        else:
            risk_level = "LOW RISK"
            risk_color = colors.HexColor('#00ff88')
        
        summary_text = f"""
        <para>
        This report analyzes <b>{total_packets}</b> packets captured from the network traffic.
        The analysis detected <b>{threat_count}</b> potential threats with an overall risk score of <b>{risk_score}/100</b>.
        <br/><br/>
        <font color="{risk_color.hexval()}"><b>Risk Assessment: {risk_level}</b></font>
        </para>
        """
        
        elements.append(Paragraph(summary_text, self.styles['InfoText']))
        
        return elements

    def _create_statistics_section(self, data: Dict) -> List:
        """Create network statistics section"""
        elements = []
        
        elements.append(Paragraph("Network Statistics", self.styles['SectionHeader']))
        
        stats = data.get('statistics', {})
        
        # Protocol breakdown
        protocol_breakdown = stats.get('protocol_breakdown', {})
        if protocol_breakdown:
            elements.append(Paragraph("<b>Protocol Distribution:</b>", self.styles['InfoText']))
            
            protocol_data = [['Protocol', 'Packets', 'Percentage']]
            total_packets = data.get('total_packets', 1)
            
            for proto, proto_data in protocol_breakdown.items():
                count = proto_data.get('count', 0) if isinstance(proto_data, dict) else proto_data
                percentage = (count / total_packets * 100) if total_packets > 0 else 0
                protocol_data.append([proto, str(count), f"{percentage:.1f}%"])
            
            protocol_table = Table(protocol_data, colWidths=[2*inch, 1.5*inch, 1.5*inch])
            protocol_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00d4ff')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            elements.append(protocol_table)
            elements.append(Spacer(1, 0.2 * inch))
        
        # Key metrics
        metrics_data = [
            ['Metric', 'Value'],
            ['Unique Source IPs', str(stats.get('unique_ips_src', 0))],
            ['Unique Dest IPs', str(stats.get('unique_ips_dst', 0))],
            ['Unique Ports', str(stats.get('unique_ports', 0))],
            ['DNS Queries', str(stats.get('dns_queries', 0))],
            ['Average Packet Size', f"{stats.get('average_packet_size', 0):.0f} bytes"]
        ]
        
        metrics_table = Table(metrics_data, colWidths=[3*inch, 2*inch])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00ff88')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(metrics_table)
        
        return elements

    def _create_threat_section(self, data: Dict) -> List:
        """Create threats section"""
        elements = []
        
        elements.append(Paragraph("Security Threats", self.styles['SectionHeader']))
        
        threats = data.get('threats', {})
        threat_list = threats.get('threats', [])
        
        if not threat_list:
            elements.append(Paragraph("✅ No threats detected", self.styles['InfoText']))
            return elements
        
        # Group threats by severity
        severity_groups = {'critical': [], 'high': [], 'medium': [], 'low': []}
        for threat in threat_list:
            severity = threat.get('severity', 'low')
            severity_groups.get(severity, severity_groups['low']).append(threat)
        
        # Display threats by severity
        for severity in ['critical', 'high', 'medium', 'low']:
            threats_in_group = severity_groups[severity]
            if not threats_in_group:
                continue
            
            severity_color = {
                'critical': '#ff0000',
                'high': '#ff4444',
                'medium': '#ffaa00',
                'low': '#00ff88'
            }.get(severity, '#666666')
            
            elements.append(Paragraph(
                f'<font color="{severity_color}"><b>{severity.upper()} Severity ({len(threats_in_group)})</b></font>',
                self.styles['InfoText']
            ))
            
            for threat in threats_in_group:
                threat_type = threat.get('type', 'Unknown')
                description = threat.get('description', 'No description')
                source = threat.get('source', 'N/A')
                source_domain = threat.get('source_domain', '')
                
                threat_text = f"""
                <b>• {threat_type.replace('_', ' ').title()}</b><br/>
                {description}<br/>
                """
                
                if source != 'N/A':
                    threat_text += f"Source: {source}"
                    if source_domain:
                        threat_text += f" ({source_domain})"
                    threat_text += "<br/>"
                
                elements.append(Paragraph(threat_text, self.styles['InfoText']))
                elements.append(Spacer(1, 0.1 * inch))
        
        return elements

    def _create_network_section(self, data: Dict) -> List:
        """Create network topology section"""
        elements = []
        
        elements.append(Paragraph("Network Topology", self.styles['SectionHeader']))
        
        network_graph = data.get('network_graph', {})
        nodes = network_graph.get('nodes', [])
        links = network_graph.get('links', [])
        
        summary_text = f"""
        The network analysis identified <b>{len(nodes)}</b> unique IP addresses 
        with <b>{len(links)}</b> connections between them.
        """
        elements.append(Paragraph(summary_text, self.styles['InfoText']))
        
        # Top communicating IPs
        stats = data.get('statistics', {})
        top_ips_src = stats.get('top_ips_src', {})
        
        if top_ips_src:
            elements.append(Paragraph("<b>Top Source IPs:</b>", self.styles['InfoText']))
            
            ip_data = [['IP Address', 'Packet Count']]
            for ip, count in list(top_ips_src.items())[:10]:
                ip_data.append([ip, str(count)])
            
            ip_table = Table(ip_data, colWidths=[3*inch, 2*inch])
            ip_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00d4ff')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            elements.append(ip_table)
        
        return elements

    def _create_recommendations(self, data: Dict) -> List:
        """Create security recommendations"""
        elements = []
        
        elements.append(Paragraph("Security Recommendations", self.styles['SectionHeader']))
        
        threats = data.get('threats', {})
        risk_score = threats.get('risk_score', 0)
        threat_list = threats.get('threats', [])
        
        recommendations = []
        
        # General recommendations based on risk
        if risk_score >= 70:
            recommendations.append("⚠️ IMMEDIATE ACTION REQUIRED: High risk detected. Review all threats immediately.")
            recommendations.append("🔒 Consider isolating affected systems from the network.")
        elif risk_score >= 40:
            recommendations.append("⚡ Medium risk detected. Investigate suspicious activities.")
        else:
            recommendations.append("✅ Low risk detected. Continue monitoring network activity.")
        
        # Specific recommendations based on threat types
        threat_types = set(t.get('type', '') for t in threat_list)
        
        if 'port_scan' in threat_types:
            recommendations.append("🔍 Port scanning detected. Review firewall rules and close unnecessary ports.")
        
        if 'syn_flood' in threat_types:
            recommendations.append("🛡️ SYN flood detected. Implement rate limiting and SYN cookies.")
        
        if 'brute_force' in threat_types:
            recommendations.append("🔐 Brute force attempts detected. Implement account lockout policies and 2FA.")
        
        if 'data_exfiltration' in threat_types:
            recommendations.append("📤 Large data transfers detected. Review DLP policies and monitor outbound traffic.")
        
        if 'dns_anomaly' in threat_types:
            recommendations.append("🌐 DNS anomalies detected. Implement DNS filtering and monitor for tunneling.")
        
        # Always add general recommendations
        recommendations.extend([
            "📊 Regularly monitor network traffic for anomalies.",
            "🔄 Keep all systems and security software up to date.",
            "📝 Maintain detailed logs of all network activity.",
            "👥 Train staff on security best practices."
        ])
        
        for rec in recommendations:
            elements.append(Paragraph(f"• {rec}", self.styles['InfoText']))
            elements.append(Spacer(1, 0.05 * inch))
        
        return elements
