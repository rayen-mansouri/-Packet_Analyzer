# PacketAnalyzer - AI-Powered Wireshark File Analysis

Analyze and visualize network traffic from Wireshark captures with AI-powered insights.

## Features

### Core Analysis
- **Packet Decomposition**: Parse and analyze packet structure
- **Protocol Breakdown**: Categorize by HTTP, DNS, TLS, TCP, UDP, etc.
- **IP Relationship Mapping**: Visual graphs showing communication patterns
- **Timeline Visualization**: Traffic patterns over time

### Security & Threat Detection
- **Suspicious Pattern Detection**: Port scanning, SYN floods, brute force attempts
- **Unencrypted Traffic Alerts**: Identify sensitive data in cleartext
- **Malware C2 Detection**: Flag potential command & control communications
- **Credential Exposure**: Detect exposed credentials/API keys

### Analytics & Reporting
- **Traffic Statistics**: Top talkers, protocol distribution, data transferred
- **Geolocation Mapping**: IP geolocation with threat intelligence
- **Export Reports**: Generate security analysis reports
- **Comparison Mode**: Compare multiple pcap files

## Project Structure

```
PacketAnalyzer/
├── frontend/          # React + Vite UI
│   ├── src/
│   │   ├── pages/
│   │   ├── components/
│   │   └── App.jsx
│   └── package.json
├── backend/           # Python FastAPI server
│   ├── src/
│   │   ├── parser.py        # Packet parsing logic
│   │   ├── analyzer.py      # AI-powered analysis
│   │   ├── threat_detector.py
│   │   ├── visualizer.py    # Graph generation
│   │   └── api.py           # FastAPI endpoints
│   └── requirements.txt
└── README.md
```

## Tech Stack

**Frontend**:
- React 18
- Vite
- TailwindCSS
- D3.js / Plotly (graphs & visualizations)
- Axios (API calls)

**Backend**:
- Python 3.9+
- FastAPI
- Scapy / PyShark (packet parsing)
- NetworkX (graph analysis)
- OpenAI API (AI insights)
- GeoIP2 (geolocation)

## Getting Started

### Backend Setup
```bash
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python src/api.py
```

### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

## Usage

1. Upload a `.pcap` or `.pcapng` file
2. The app parses packets and extracts metadata
3. AI model generates security insights & anomalies
4. Visual graphs show IP relationships & protocols
5. Export detailed reports

## Next Steps
- [ ] Backend packet parser setup
- [ ] AI integration for insights
- [ ] Graph visualization engine
- [ ] Frontend upload & display UI
- [ ] Threat detection module
