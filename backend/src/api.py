from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import os
import tempfile
from pathlib import Path

from parser import PacketParser
from analyzer import PacketAnalyzer
from threat_detector import ThreatDetector
from visualizer import NetworkVisualizer

app = FastAPI(
    title="PacketAnalyzer API",
    description="AI-powered Wireshark packet analysis",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class AnalysisRequest(BaseModel):
    include_ai_summary: bool = True
    include_threats: bool = True
    include_visualizations: bool = True


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "online",
        "service": "PacketAnalyzer API",
        "version": "1.0.0"
    }


@app.post("/api/analyze")
async def analyze_pcap(file: UploadFile = File(...), request: Optional[AnalysisRequest] = None):
    """
    Upload and analyze a Wireshark pcap file
    """
    
    if request is None:
        request = AnalysisRequest()
    
    # Validate file
    if not file.filename.endswith(('.pcap', '.pcapng')):
        raise HTTPException(status_code=400, detail="File must be .pcap or .pcapng")
    
    try:
        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp_file:
            content = await file.read()
            tmp_file.write(content)
            tmp_path = tmp_file.name
        
        # Parse packets
        parser = PacketParser(tmp_path)
        if not parser.parse_file():
            raise HTTPException(status_code=400, detail="Failed to parse pcap file")
        
        # Extract packet information
        packets = parser.extract_packet_info()
        statistics = parser.get_statistics()
        flows = parser.get_flows()
        
        result = {
            "file_name": file.filename,
            "packets": packets[:100],  # Return first 100 packets
            "total_packets": len(packets),
            "statistics": dict(statistics),
            "flows_count": len(flows),
            "sample_flows": dict(list(flows.items())[:10])
        }
        
        # Generate AI summary if requested
        if request.include_ai_summary:
            analyzer = PacketAnalyzer()
            summary = analyzer.generate_summary(packets, statistics)
            result["ai_summary"] = summary
        
        # Detect threats if requested
        if request.include_threats:
            detector = ThreatDetector()
            threats = detector.analyze(packets, statistics)
            result["threats"] = threats
        
        # Generate visualizations if requested
        if request.include_visualizations:
            visualizer = NetworkVisualizer()
            result["visualizations"] = {
                "ip_graph": visualizer.create_ip_relationship_graph(packets),
                "protocol_graph": visualizer.create_protocol_flow_graph(packets),
                "timeline": visualizer.create_traffic_timeline(packets),
                "ports": visualizer.create_port_usage_graph(packets)
            }
        
        # Cleanup
        os.unlink(tmp_path)
        
        return JSONResponse(result)
    
    except Exception as e:
        # Cleanup on error
        if 'tmp_path' in locals():
            try:
                os.unlink(tmp_path)
            except:
                pass
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")


@app.get("/api/packet/{packet_num}")
async def get_packet_details(packet_num: int):
    """
    Get detailed explanation of a specific packet
    (Requires packet data to be stored in session)
    """
    
    return {
        "message": "Endpoint for packet details",
        "packet_num": packet_num,
        "status": "not_implemented"
    }


@app.get("/api/export/{analysis_id}")
async def export_report(analysis_id: str):
    """
    Export analysis report as PDF
    """
    
    return {
        "message": "Export functionality",
        "analysis_id": analysis_id,
        "status": "not_implemented"
    }


@app.get("/api/threat-intelligence/{ip}")
async def get_threat_intel(ip: str):
    """
    Get threat intelligence for an IP address
    """
    
    return {
        "ip": ip,
        "threat_info": "not_implemented",
        "message": "Requires integration with threat intel API"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
