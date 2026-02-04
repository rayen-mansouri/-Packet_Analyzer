import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import os
import tempfile

from src.parser import PacketParser
from src.analyzer import PacketAnalyzer
from src.threat_detector import ThreatDetector
from src.visualizer import NetworkVisualizer

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

class AnalysisRequest(BaseModel):
    include_ai_summary: bool = False
    include_threats: bool = True
    include_visualizations: bool = True


@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "PacketAnalyzer API",
        "version": "1.0.0"
    }


@app.post("/api/analyze")
async def analyze_pcap(file: UploadFile = File(...), request: Optional[AnalysisRequest] = None):
    
    if request is None:
        request = AnalysisRequest()
    
    if not file.filename.endswith(('.pcap', '.pcapng')):
        raise HTTPException(status_code=400, detail="File must be .pcap or .pcapng")
    
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp_file:
            content = await file.read()
            tmp_file.write(content)
            tmp_path = tmp_file.name
        
        parser = PacketParser(tmp_path)
        if not parser.parse_file():
            raise HTTPException(status_code=400, detail="Failed to parse pcap file")
        
        try:
            packets = parser.extract_packet_info()
            statistics = parser.get_statistics()
            flows = parser.get_flows()
        except Exception as e:
            print(f"Error extracting packets: {e}")
            raise HTTPException(status_code=400, detail=f"Error parsing packets: {str(e)}")
        
        result = {
            "file_name": file.filename,
            "packets": packets[:100] if packets else [],
            "total_packets": len(packets) if packets else 0,
            "statistics": dict(statistics) if statistics else {},
            "flows_count": len(flows) if flows else 0,
            "sample_flows": dict(list(flows.items())[:10]) if flows else {}
        }
        
        if request.include_threats:
            try:
                detector = ThreatDetector()
                threats = detector.analyze(packets if packets else [], statistics if statistics else {})
                result["threats"] = threats
            except Exception as e:
                print(f"Error detecting threats: {e}")
                result["threats"] = {"threats": [], "risk_score": 0, "severity_count": {}}
        
        if request.include_ai_summary:
            try:
                analyzer = PacketAnalyzer()
                summary = analyzer.generate_summary(packets if packets else [], statistics if statistics else {})
                result["ai_summary"] = summary
            except Exception as e:
                print(f"Error generating summary: {e}")
                result["ai_summary"] = "AI summary not available"
        
        if request.include_visualizations:
            try:
                visualizer = NetworkVisualizer()
                result["visualizations"] = {
                    "ip_graph": visualizer.create_ip_relationship_graph(packets if packets else []),
                    "protocol_graph": visualizer.create_protocol_flow_graph(packets if packets else []),
                    "timeline": visualizer.create_traffic_timeline(packets if packets else []),
                    "ports": visualizer.create_port_usage_graph(packets if packets else [])
                }
            except Exception as e:
                print(f"Error creating visualizations: {e}")
                result["visualizations"] = {}
        
        if tmp_path:
            os.unlink(tmp_path)
        
        return JSONResponse(result)
    
    except Exception as e:
        print(f"Upload error: {e}")
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except:
                pass
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")


@app.get("/api/packet/{packet_num}")
async def get_packet_details(packet_num: int):
    return {
        "message": "Endpoint for packet details",
        "packet_num": packet_num,
        "status": "not_implemented"
    }


@app.get("/api/export/{analysis_id}")
async def export_report(analysis_id: str):
    return {
        "message": "Export functionality",
        "analysis_id": analysis_id,
        "status": "not_implemented"
    }


@app.get("/api/threat-intelligence/{ip}")
async def get_threat_intel(ip: str):
    return {
        "ip": ip,
        "threat_info": "not_implemented",
        "message": "Requires integration with threat intel API"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001, reload=False)
