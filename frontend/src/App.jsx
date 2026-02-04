import React, { useState } from 'react'
import './App.css'

export default function App() {
  const [file, setFile] = useState(null)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  const handleUpload = async (e) => {
    e.preventDefault()
    if (!file) return
    
    setLoading(true)
    setError(null)
    
    try {
      const formData = new FormData()
      formData.append('file', file)
      
      const response = await fetch('http://localhost:8001/api/analyze?include_threats=true&include_ai_summary=false&include_visualizations=true', {
        method: 'POST',
        body: formData
      })
      
      if (!response.ok) {
        const errText = await response.text()
        throw new Error(`Upload failed: ${response.status} - ${errText}`)
      }
      const data = await response.json()
      setResult(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  if (result) {
    return (
      <div className="container">
        <header>
          <h1>📡 PacketAnalyzer Results</h1>
          <button onClick={() => setResult(null)} className="btn-secondary">
            ← New Analysis
          </button>
        </header>
        
        <main>
          <div className="result-header">
            <h2>{result.file_name}</h2>
            <div className="stats-grid">
              <div className="stat">
                <p>Packets</p>
                <span>{result.total_packets}</span>
              </div>
              <div className="stat">
                <p>Flows</p>
                <span>{result.flows_count}</span>
              </div>
              <div className="stat">
                <p>Size</p>
                <span>{(result.statistics.total_size / 1024 / 1024).toFixed(2)} MB</span>
              </div>
              <div className="stat">
                <p>Risk</p>
                <span className={result.threats?.risk_score > 70 ? 'danger' : result.threats?.risk_score > 40 ? 'warning' : 'safe'}>
                  {result.threats?.risk_score || 0}/100
                </span>
              </div>
            </div>
          </div>

          {result.threats?.threats?.length > 0 && (
            <div className="section">
              <h3>⚠️ Threats Detected ({result.threats.threats.length})</h3>
              {result.threats.threats.slice(0, 5).map((t, i) => (
                <div key={i} className={`threat threat-${t.severity}`}>
                  <strong>{t.type}</strong>
                  <p>{t.description}</p>
                </div>
              ))}
            </div>
          )}

          {Object.keys(result.statistics.protocols || {}).length > 0 && (
            <div className="section">
              <h3>📊 Protocols</h3>
              <ul>
                {Object.entries(result.statistics.protocols)
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 10)
                  .map(([p, c]) => (
                    <li key={p}>{p}: <strong>{c}</strong></li>
                  ))}
              </ul>
            </div>
          )}

          {result.ai_summary && (
            <div className="section">
              <h3>🤖 AI Analysis</h3>
              <p>{result.ai_summary}</p>
            </div>
          )}
        </main>
      </div>
    )
  }

  return (
    <div className="container">
      <header>
        <h1>📡 PacketAnalyzer</h1>
        <p>AI-powered Wireshark packet analysis</p>
      </header>

      <main>
        <form onSubmit={handleUpload} className="upload-section">
          <div className="upload-box">
            <h2>Upload Wireshark File</h2>
            <input
              type="file"
              accept=".pcap,.pcapng"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
              disabled={loading}
            />
            {file && <p className="file-name">Selected: {file.name}</p>}
            <button 
              type="submit" 
              disabled={!file || loading}
              className="btn-primary"
            >
              {loading ? 'Analyzing...' : 'Analyze File'}
            </button>
          </div>
        </form>

        {error && <div className="error">{error}</div>}

        <div className="features">
          <h3>Features</h3>
          <ul>
            <li>🔍 Packet decomposition & analysis</li>
            <li>🛡️ Threat detection (port scans, floods, etc)</li>
            <li>📊 Network statistics & flows</li>
            <li>🔗 IP relationship graphs</li>
          </ul>
        </div>
      </main>
    </div>
  )
}
