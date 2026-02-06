import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import os
import tempfile
import json
from collections import Counter, defaultdict
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from src.parser import PacketParser
from src.analyzer import PacketAnalyzer
from src.threat_detector import ThreatDetector
from src.visualizer import NetworkVisualizer
from src.pdf_generator import PDFReportGenerator
from src.ai_analyzer import AIAnalyzer
from src.ai_chatbot import AIChatbot

app = FastAPI(
    title="PacketAnalyzer API",
    description="AI-powered Wireshark packet analysis",
    version="1.0.0"
)

# Get allowed origins from environment variable or use defaults
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalysisRequest(BaseModel):
    include_ai_summary: bool = True
    include_threats: bool = True
    include_visualizations: bool = True


class ChatRequest(BaseModel):
    message: str
    analysis_data: dict


def make_serializable(obj):
    """Recursively convert non-JSON-serializable objects to serializable types"""
    if obj is None:
        return None
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, (int, float)):
        return obj
    if isinstance(obj, str):
        return obj
    if isinstance(obj, (Counter, defaultdict)):
        return {str(k): make_serializable(v) for k, v in dict(obj).items()}
    if isinstance(obj, dict):
        return {str(k): make_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [make_serializable(item) for item in obj]
    if isinstance(obj, set):
        return sorted([make_serializable(item) for item in obj], key=str)
    return str(obj)


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
        
        print(f"Parsing file: {tmp_path}")
        parser = PacketParser(tmp_path)
        if not parser.parse_file():
            raise HTTPException(status_code=400, detail="Failed to parse pcap file")
        
        try:
            packets = parser.extract_packet_info()
            print(f"? Extracted {len(packets)} packets")
            statistics = parser.get_statistics()
            print(f"? Got statistics")
            flows = parser.get_flows()
            print(f"? Got flows: {len(flows)}")
            network_graph = parser.get_network_graph_data()
            print(f"? Got network graph: {len(network_graph['nodes'])} nodes, {len(network_graph['links'])} links")
            timeline_data = parser.get_timeline_data()
            print(f"? Got timeline: {len(timeline_data['timeline'])} time buckets")
        except Exception as e:
            print(f"Error extracting packets: {e}")
            import traceback
            traceback.print_exc()
            raise HTTPException(status_code=400, detail=f"Error parsing packets: {str(e)}")
        
        print("Building result...")
        result = {
            "file_name": file.filename,
            "packets": make_serializable(packets[:100] if packets else []),
            "total_packets": len(packets) if packets else 0,
            "statistics": make_serializable(statistics if statistics else {}),
            "flows_count": len(flows) if flows else 0,
            "sample_flows": make_serializable(dict(list(flows.items())[:10]) if flows else {}),
            "network_graph": make_serializable(network_graph if 'network_graph' in locals() else {"nodes": [], "links": []}),
            "timeline": make_serializable(timeline_data if 'timeline_data' in locals() else {"timeline": [], "start_time": 0, "end_time": 0, "total_duration": 0})
        }

        if request.include_threats:
            try:
                print("Analyzing threats...")
                detector = ThreatDetector()
                threats = detector.analyze(packets if packets else [], statistics if statistics else {})
                print(f"? Got threats: {len(threats.get('threats', []))} detected")
                result["threats"] = make_serializable(threats)
            except Exception as e:
                print(f"Error detecting threats: {e}")
                import traceback
                traceback.print_exc()
                result["threats"] = {"threats": [], "risk_score": 0, "severity_count": {}}
        
        if request.include_ai_summary:
            try:
                print("Generating AI summary...")
                ai_analyzer = AIAnalyzer()
                # Pass the complete analysis data to AI
                ai_input = {
                    'total_packets': len(packets) if packets else 0,
                    'file_name': file.filename,
                    'statistics': statistics if statistics else {},
                    'threats': result.get('threats', {}),
                    'network_graph': network_graph if 'network_graph' in locals() else {}
                }
                ai_summary = ai_analyzer.generate_summary(ai_input)
                result["ai_summary"] = ai_summary
                print("✓ AI summary generated")
            except Exception as e:
                print(f"Error generating AI summary: {e}")
                import traceback
                traceback.print_exc()
                result["ai_summary"] = {"error": "AI summary generation failed"}
        
        if request.include_visualizations:
            try:
                print("Creating visualizations...")
                visualizer = NetworkVisualizer()
                result["visualizations"] = make_serializable({
                    "ip_graph": visualizer.create_ip_relationship_graph(packets if packets else []),
                    "protocol_graph": visualizer.create_protocol_flow_graph(packets if packets else []),
                    "timeline": visualizer.create_traffic_timeline(packets if packets else []),
                    "ports": visualizer.create_port_usage_graph(packets if packets else [])
                })
            except Exception as e:
                print(f"Error creating visualizations: {e}")
                result["visualizations"] = {}

        if tmp_path:
            os.unlink(tmp_path)

        print("Serializing final result...")
        final_result = make_serializable(result)
        print("? Result serialized successfully")
        
        return JSONResponse(final_result)

    except HTTPException:
        raise
    except Exception as e:
        print(f"Upload error: {e}")
        import traceback
        traceback.print_exc()
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


@app.post("/api/export-pdf")
async def export_pdf(analysis_data: dict):
    """Generate and download PDF report from analysis data"""
    try:
        print("Generating PDF report...")
        pdf_generator = PDFReportGenerator()
        pdf_buffer = pdf_generator.generate_report(analysis_data)
        
        filename = f"packet_analysis_{analysis_data.get('file_name', 'report')}.pdf".replace('.pcap', '').replace('.pcapng', '')
        
        return StreamingResponse(
            pdf_buffer,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
    except Exception as e:
        print(f"Error generating PDF: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error generating PDF: {str(e)}")


@app.post("/api/chat")
async def chat(request: ChatRequest):
    """Handle chatbot queries about analysis data"""
    try:
        message = request.message
        analysis_data = request.analysis_data
        
        if not message:
            raise HTTPException(status_code=400, detail="Message is required")
        
        print(f"Chat query: {message}")
        
        # Create AI chatbot instance
        chatbot = AIChatbot()
        
        # Set the analysis context if provided
        if analysis_data:
            chatbot.set_analysis_context(analysis_data)
        
        # Get AI response
        response = chatbot.chat(message)
        
        return {"response": response}
    except Exception as e:
        print(f"Error processing chat: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Chat error: {str(e)}")


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
