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
- **AI-Powered Chatbot**: Ask questions about your packet capture using GPT
- **PDF Export**: Generate professional security analysis reports
- **AI Summaries**: Natural language summaries of network activity
- **Timeline Visualization**: Interactive traffic patterns over time with protocol breakdown
- **Network Graph**: Visual representation of IP relationships with threat highlighting
- **Packet Inspector**: Detailed packet-by-packet analysis with enhanced metadata
- **Enhanced Protocol Filtering**: Color-coded protocol selection with visual indicators

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
- Scapy (packet parsing)
- OpenAI GPT-4o-mini (AI chatbot & insights)
- Reportlab (PDF generation)
- Matplotlib (visualizations)

## Getting Started

### Backend Setup
```bash
cd backend
pip install -r requirements.txt

# Set up your OpenAI API key (for AI chatbot)
copy .env.example .env
# Edit .env and add your OpenAI API key

python main.py
```

### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

## AI Chatbot

The PacketAnalyzer includes a **real AI chatbot** powered by OpenAI's GPT models that can:
- Analyze your packet captures contextually
- Answer questions about IPs, protocols, threats
- Explain security issues in simple terms
- Search for specific patterns or data
- Provide security recommendations

See [CHATBOT_SETUP.md](CHATBOT_SETUP.md) for detailed setup instructions.

## Usage

1. **Upload** a `.pcap` or `.pcapng` file
2. **Analyze**: View statistics, threats, network graph, and timeline
3. **Chat**: Ask the AI chatbot questions about your capture
4. **Export**: Download a professional PDF report
5. **Explore**: Interact with visualizations and dive into details

## Recent Improvements (v2.1)

🎨 **UI/UX Enhancements**:
- Added separate "Contact" tab in sidebar navigation
- Improved risk assessment with informative notes about IP flagging
- Color-coded protocol filter dropdown (TCP, UDP, ICMP, ARP, etc.)
- Removed duplicate Protocol Distribution chart from Graphs tab
- Enhanced packet detail view with comprehensive metadata

📦 **Packet Inspector Updates**:
- Human-readable timestamps alongside Unix format
- Detailed network layer information (ports, TTL, packet sizes)
- Enhanced TCP/UDP protocol details (sequence numbers, flags, checksums)
- Better organized packet information sections
- Service name resolution for common ports

⚠️ **Risk Assessment**:
- Added informative note explaining IP risk scoring
- Improved visual styling for risk indicators
- Better clarity on threat detection sensitivity

## Status

✅ **Completed Features**:
- Packet parsing and analysis
- Threat detection with visual indicators
- Interactive network graph visualization
- Timeline visualization with protocol breakdown
- PDF report export
- AI-powered summaries
- **Real AI chatbot with GPT integration**
- Enhanced packet inspector with detailed metadata
- Color-coded protocol filtering

🔄 **In Progress**:
- GeoIP mapping
- Performance optimizations for large PCAP files

⏹️ **Planned**:
- Comparison mode for multiple captures
- Enhanced threat intelligence feeds
- Real-time packet capture
