# Quick Start Guide for PacketAnalyzer

## Installation & Setup

### Prerequisites
- Python 3.9+ (for backend)
- Node.js 16+ (for frontend)
- A Wireshark capture file (.pcap or .pcapng)

### Backend Setup

1. Navigate to backend folder:
```bash
cd backend
```

2. Create virtual environment:
```bash
python -m venv venv
venv\Scripts\activate  # On Windows
# or
source venv/bin/activate  # On macOS/Linux
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure environment variables:
```bash
copy .env.example .env
# Edit .env and add your OpenAI API key
```

5. Run the server:
```bash
python src/api.py
```

The API will be available at `http://localhost:8000`

### Frontend Setup

1. Navigate to frontend folder:
```bash
cd frontend
```

2. Install dependencies:
```bash
npm install
```

3. Start development server:
```bash
npm run dev
```

The frontend will be available at `http://localhost:5173`

## Usage

1. Open the frontend in your browser
2. Upload a .pcap or .pcapng file
3. The system will:
   - Parse all packets
   - Detect threats and anomalies
   - Generate AI insights
   - Create visual graphs
   - Calculate risk scores
4. Review the detailed analysis report
5. Export results if needed

## File Structure

```
PacketAnalyzer/
├── backend/
│   ├── src/
│   │   ├── api.py              # Main FastAPI server
│   │   ├── parser.py           # Packet parsing
│   │   ├── analyzer.py         # AI analysis
│   │   ├── threat_detector.py  # Security detection
│   │   └── visualizer.py       # Graph generation
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── FileUpload.jsx
│   │   │   ├── AnalysisResults.jsx
│   │   │   └── Dashboard.jsx
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
└── README.md
```

## API Endpoints

### POST /api/analyze
Upload and analyze a Wireshark file

**Request:**
- Form data with file (.pcap or .pcapng)

**Response:**
```json
{
  "file_name": "capture.pcap",
  "total_packets": 1000,
  "packets": [...],
  "statistics": {...},
  "threats": {...},
  "visualizations": {...},
  "ai_summary": "..."
}
```

### GET /
Health check

## Features Implemented

✅ Packet Parsing (Scapy)
✅ Threat Detection (Port scan, SYN flood, brute force)
✅ Statistics & Analytics
✅ Network Visualization (Graph data)
✅ AI-powered Insights (LLM integration ready)
✅ React Frontend with Tailwind CSS
✅ File Upload & Processing

## Next Steps

1. **Integrate OpenAI API** - Add API key for AI summaries
2. **Add Real Graphs** - Implement D3.js/Plotly visualizations
3. **Geolocation Mapping** - Add GeoIP2 integration
4. **Export Reports** - PDF/JSON export functionality
5. **Database** - Store analysis history (SQLite/PostgreSQL)
6. **Authentication** - User login system
7. **Batch Processing** - Multiple file uploads
8. **Advanced Filtering** - Search and filter packets
9. **Threat Intelligence** - VirusTotal/AbuseIPDB integration
10. **Performance Optimization** - Cache large captures

## Troubleshooting

### "Failed to parse pcap file"
- Ensure file is valid Wireshark capture
- Check file extension (.pcap or .pcapng)

### CORS errors
- Backend CORS is configured for all origins (*)
- Update frontend proxy in vite.config.js if needed

### Missing OpenAI response
- Add OPENAI_API_KEY to .env
- Check API key validity

## Support

For issues or feature requests, check the detailed documentation or create an issue in the repo.
