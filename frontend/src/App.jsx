import React, { useState, useRef, useEffect } from "react";
import axios from "axios";
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from "recharts";
import NetworkGraph from "./components/NetworkGraph";
import Timeline from "./components/Timeline";
import PacketInspector from "./components/PacketInspector";
import "./App.css";

export default function App() {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [theme, setTheme] = useState("dark");
  const [sidebarTab, setSidebarTab] = useState("documentation");
  const [chatMessages, setChatMessages] = useState([]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const [activeTab, setActiveTab] = useState("overview");
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [isDragOver, setIsDragOver] = useState(false);
  const chatMessagesEndRef = useRef(null);
  
  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    chatMessagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [chatMessages, chatLoading]);

  useEffect(() => {
    document.body.classList.toggle("theme-light", theme === "light");
  }, [theme]);

  const handleFileSelect = (e) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      const validExtensions = [".pcap", ".pcapng"];
      const fileExt = "." + selectedFile.name.split(".").pop().toLowerCase();
      if (validExtensions.includes(fileExt)) {
        setFile(selectedFile);
        setError(null);
      } else {
        setError("❌ Invalid file. Please select .pcap or .pcapng");
        setFile(null);
      }
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    setIsDragOver(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragOver(false);
    const droppedFile = e.dataTransfer.files?.[0];
    if (droppedFile) {
      const validExtensions = [".pcap", ".pcapng"];
      const fileExt = "." + droppedFile.name.split(".").pop().toLowerCase();
      if (validExtensions.includes(fileExt)) {
        setFile(droppedFile);
        setError(null);
      } else {
        setError("❌ Invalid file. Please select .pcap or .pcapng");
        setFile(null);
      }
    }
  };

  const handleAnalyze = async () => {
    if (!file) {
      setError("Please select a file");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const response = await axios.post("http://localhost:8000/api/analyze", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setResults(response.data);
    } catch (err) {
      setError(`Error: ${err.response?.data?.detail || err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleExportPDF = async () => {
    if (!results) {
      setError("No analysis results to export");
      return;
    }
    
    try {
      console.log("Exporting PDF...");
      const response = await axios.post(
        "http://localhost:8000/api/export-pdf",
        results,
        { 
          responseType: 'blob',
          headers: {
            'Content-Type': 'application/json'
          }
        }
      );
      
      console.log("PDF received", response);
      
      // Create download link
      const blob = new Blob([response.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      const filename = `packet_analysis_${results.file_name.replace('.pcap', '').replace('.pcapng', '')}.pdf`;
      link.setAttribute('download', filename);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      
      console.log("PDF downloaded successfully");
    } catch (err) {
      console.error("Export error:", err);
      setError(`Export failed: ${err.response?.data?.message || err.message}`);
    }
  };

  const handleClearChat = () => {
    setChatMessages([]);
  };

  const handleCopyMessage = (content) => {
    navigator.clipboard.writeText(content);
  };

  const handleChatSend = async () => {
    if (!chatInput.trim() || chatLoading) return;

    const userMessage = chatInput.trim();
    const timestamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    
    setChatMessages(prev => [...prev, { 
      role: 'user', 
      content: userMessage,
      timestamp 
    }]);
    setChatInput('');
    setChatLoading(true);
    
    try {
      const response = await axios.post(
        "http://localhost:8000/api/chat",
        {
          message: userMessage,
          analysis_data: results
        }
      );
      
      setChatMessages(prev => [...prev, { 
        role: 'assistant', 
        content: response.data.response,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      }]);
    } catch (err) {
      const errorMsg = err.response?.data?.detail || err.message || 'Unknown error';
      setChatMessages(prev => [...prev, { 
        role: 'assistant', 
        content: `❌ Sorry, I encountered an error: ${errorMsg}\n\nPlease make sure:\n• Your OpenAI API key is set in backend/.env\n• The backend server is running\n• You have uploaded a packet capture file`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        isError: true
      }]);
    } finally {
      setChatLoading(false);
    }
  };

  const handleReset = () => {
    setFile(null);
    setResults(null);
    setError(null);
  };

  return (
    <div className="app">
      <div className="header">
        <div className="header-left">
          <button className="sidebar-toggle" onClick={() => setSidebarOpen(!sidebarOpen)}>
            {sidebarOpen ? '✖' : '☰'}
          </button>
          <h1>🔍 PacketAnalyzer</h1>
        </div>
        <div className="header-right">
          <p className="credits">Made by Rayen Mansouri</p>
        </div>
      </div>

      <div 
        className="main-container"
        style={{ gridTemplateColumns: !results && sidebarOpen ? '200px 1fr' : !results && !sidebarOpen ? '0 1fr' : (sidebarOpen ? '200px 1fr 400px' : '0 1fr 400px') }}
      >

        <div className={`sidebar ${sidebarOpen ? 'open' : 'closed'}`}>
          <div className="sidebar-menu">
            <div 
              className={`menu-item ${sidebarTab === "documentation" ? "active" : ""}`}
              onClick={() => setSidebarTab("documentation")}
            >
              <span className="menu-icon">📚</span>
              <span className="menu-label">Documentation</span>
            </div>
            <div 
              className={`menu-item ${sidebarTab === "contact" ? "active" : ""}`}
              onClick={() => setSidebarTab("contact")}
            >
              <span className="menu-icon">📞</span>
              <span className="menu-label">Contact</span>
            </div>
            <div 
              className={`menu-item ${sidebarTab === "settings" ? "active" : ""}`}
              onClick={() => setSidebarTab("settings")}
            >
              <span className="menu-icon">⚙️</span>
              <span className="menu-label">Settings</span>
            </div>
          </div>

          <div className="sidebar-content">
            {sidebarTab === "settings" && (
              <div className="content-section">
                <h3>Preferences</h3>
                <div className="setting-item">
                  <span>Theme</span>
                  <button
                    className="toggle-btn"
                    onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
                  >
                    {theme === "dark" ? "🌙 Dark" : "☀️ Light"}
                  </button>
                </div>
              </div>
            )}

            {sidebarTab === "documentation" && (
              <>
                <div className="content-section">
                  <h3>📚 Documentation</h3>
                  <div className="doc-item">📤 Upload .pcap/.pcapng files to analyze network traffic</div>
                  <div className="doc-item">📊 Use tabs to explore Overview, Graphs, Timeline, Packets</div>
                  <div className="doc-item">🔍 Click a packet row to view detailed protocol information</div>
                  <div className="doc-item">💬 Ask the AI about any packet number for instant analysis</div>
                  <div className="doc-item">⚠️ Review threats and risk scores in the Overview tab</div>
                  <div className="doc-item">📈 Visualize network topology and protocol distribution in Graphs</div>
                </div>

                <div className="content-section">
                  <h3>🔗 Helpful Resources</h3>
                  <a className="resource-link" href="https://www.wireshark.org/docs/" target="_blank" rel="noreferrer">📖 Wireshark Official Docs</a>
                  <a className="resource-link" href="https://www.iana.org/assignments/service-names-port-numbers/" target="_blank" rel="noreferrer">🌐 IANA Port Numbers</a>
                  <a className="resource-link" href="https://www.rfc-editor.org/" target="_blank" rel="noreferrer">📚 RFC Editor</a>
                  <a className="resource-link" href="https://owasp.org/" target="_blank" rel="noreferrer">🔒 OWASP Security</a>
                  <a className="resource-link" href="https://en.wikipedia.org/wiki/Transmission_Control_Protocol" target="_blank" rel="noreferrer">📡 TCP/IP Protocols</a>
                  <a className="resource-link" href="https://en.wikipedia.org/wiki/OSI_model" target="_blank" rel="noreferrer">🏗️ OSI Model Guide</a>
                </div>
              </>
            )}

            {sidebarTab === "contact" && (
              <div className="content-section">
                <h3>📞 Contact</h3>
                <div className="contact-info">
                  <div className="contact-item">👤 Rayen Mansouri</div>
                  <div className="contact-item email">📧 mouhamedrayen.mansouri@esprit.tn</div>
                </div>
              </div>
            )}
          </div>
        </div>

        <div className="content">
          {!results ? (
            <div className="upload-card">
              <h2>📁 Upload PCAP File</h2>
              <p className="upload-hint">Select .pcap or .pcapng for analysis</p>

              <div
                className={`upload-area ${isDragOver ? 'drag-over' : ''}`}
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
              >
                <div className="upload-content">
                  <div className="upload-icon">📤</div>
                  <p className="upload-text">Drag and drop here</p>
                  <p className="upload-or">or</p>
                  <label className="upload-button">
                    Browse Files
                    <input
                      type="file"
                      accept=".pcap,.pcapng"
                      onChange={handleFileSelect}
                      style={{ display: "none" }}
                    />
                  </label>
                </div>
              </div>

              {file && (
                <div className="file-selected">
                  <span>✓ {file.name}</span>
                  <span className="file-size">({(file.size / 1024 / 1024).toFixed(2)} MB)</span>
                </div>
              )}

              {error && <div className="error-message">{error}</div>}

              <button
                className="analyze-button"
                onClick={handleAnalyze}
                disabled={!file || loading}
              >
                {loading ? "⏳ Analyzing..." : "🚀 Analyze"}
              </button>
            </div>
          ) : (
            <div className="results-view">
              {/* Tabs Navigation */}
              <div className="tabs-nav">
                <button
                  className={`tab-btn ${activeTab === 'overview' ? 'active' : ''}`}
                  onClick={() => setActiveTab('overview')}
                >
                  📊 Overview
                </button>
                <button
                  className={`tab-btn ${activeTab === 'graphs' ? 'active' : ''}`}
                  onClick={() => setActiveTab('graphs')}
                >
                  📈 Graphs
                </button>
                <button
                  className={`tab-btn ${activeTab === 'timeline' ? 'active' : ''}`}
                  onClick={() => setActiveTab('timeline')}
                >
                  ⏱️ Timeline
                </button>
                <button
                  className={`tab-btn ${activeTab === 'packets' ? 'active' : ''}`}
                  onClick={() => setActiveTab('packets')}
                >
                  📦 Packets
                </button>
                <button
                  className={`tab-btn ${activeTab === 'export' ? 'active' : ''}`}
                  onClick={() => setActiveTab('export')}
                >
                  📄 Export
                </button>
              </div>

              {/* Overview Tab */}
              {activeTab === 'overview' && (
                <div className="tab-content">
              {/* Top row: File info + Threat summary */}
              <div className="results-grid top-section">
                <div className="card info-card">
                  <h3>📄 File Info</h3>
                  <div className="card-content">
                    <div className="info-row">
                      <span className="label">File:</span>
                      <span className="value">{results.file_name}</span>
                    </div>
                    <div className="info-row">
                      <span className="label">Total Packets:</span>
                      <span className="value metric-large">{results.total_packets}</span>
                    </div>
                    <div className="info-row">
                      <span className="label">Flows:</span>
                      <span className="value metric-large">{results.flows_count}</span>
                    </div>
                  </div>
                </div>

                {results.threats && (
                  <div className="card threat-summary-card">
                    <h3>⚠️ Risk Assessment</h3>
                    <div className="threat-summary-content">
                      <div className="risk-score-display">
                        <div className="risk-circle">{results.threats.risk_score}</div>
                        <span className="risk-label">Risk Score</span>
                      </div>
                      <div className="threat-count-display">
                        <div className="threat-number">{results.threats.threats?.length || 0}</div>
                        <span className="threat-label-text">Threats Detected</span>
                      </div>
                      {results.threats.threat_summary?.top_concerns && (
                        <div className="top-concerns">
                          <h4>Main Concerns:</h4>
                          {results.threats.threat_summary.top_concerns.map((concern, idx) => (
                            <div key={idx} className="concern-item">• {concern}</div>
                          ))}
                        </div>
                      )}
                      <div className="risk-note">
                        <small>ℹ️ Note: Your own IP may be flagged as high risk if many packets are sent from it.</small>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Protocol Distribution */}
              {results.statistics?.protocol_breakdown && (
                <div className="card protocol-card-large">
                  <h3>📊 Protocol Distribution</h3>
                  <div className="card-content">
                    <ResponsiveContainer width="100%" height={300}>
                      <PieChart>
                        <Pie
                          data={Object.entries(results.statistics.protocol_breakdown).map(([name, data]) => ({
                            name,
                            value: data.percentage,
                          }))}
                          cx="50%"
                          cy="50%"
                          labelLine={false}
                          label={({ name, value }) => `${name} ${value.toFixed(1)}%`}
                          outerRadius={100}
                          fill="#8884d8"
                          dataKey="value"
                        >
                          <Cell fill="#00d4ff" />
                          <Cell fill="#00ff88" />
                          <Cell fill="#ffaa00" />
                          <Cell fill="#ff4444" />
                          <Cell fill="#8855ff" />
                        </Pie>
                        <Tooltip formatter={(value) => `${value.toFixed(1)}%`} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              )}

              {/* Metrics grid - 5 columns */}
              <div className="metrics-grid">
                <div className="metric-card">
                  <div className="metric-icon">💾</div>
                  <div className="metric-label-title">File Size</div>
                  <div className="metric-large-value">{results.statistics?.total_size_mb?.toFixed(2)}</div>
                  <div className="metric-unit">MB</div>
                </div>
                <div className="metric-card">
                  <div className="metric-icon">📏</div>
                  <div className="metric-label-title">Avg Packet</div>
                  <div className="metric-large-value">{results.statistics?.average_packet_size?.toFixed(0)}</div>
                  <div className="metric-unit">bytes</div>
                </div>
                <div className="metric-card">
                  <div className="metric-icon">🌐</div>
                  <div className="metric-label-title">Unique IPs</div>
                  <div className="metric-large-value">{results.statistics?.unique_ips_total}</div>
                  <div className="metric-unit">hosts</div>
                </div>
                <div className="metric-card">
                  <div className="metric-icon">🔌</div>
                  <div className="metric-label-title">Unique Ports</div>
                  <div className="metric-large-value">{results.statistics?.unique_ports}</div>
                  <div className="metric-unit">ports</div>
                </div>
                <div className="metric-card">
                  <div className="metric-icon">🔍</div>
                  <div className="metric-label-title">DNS Queries</div>
                  <div className="metric-large-value">{results.statistics?.dns_queries}</div>
                  <div className="metric-unit">queries</div>
                </div>
              </div>

              {results.statistics?.top_ips_src && (
                <div className="results-grid">
                  <div className="card ip-card">
                    <h3>🔼 Top Source IPs</h3>
                    <div className="card-content ip-list">
                      {Object.entries(results.statistics.top_ips_src)
                        .slice(0, 8)
                        .map(([ip, count]) => (
                          <div key={ip} className="ip-row">
                            <span className="ip-address">{ip}</span>
                            <span className="ip-count">{count}</span>
                          </div>
                        ))}
                    </div>
                  </div>

                  {results.statistics?.top_ips_dst && (
                    <div className="card ip-card">
                      <h3>🔽 Top Dest IPs</h3>
                      <div className="card-content ip-list">
                        {Object.entries(results.statistics.top_ips_dst)
                          .slice(0, 8)
                          .map(([ip, count]) => (
                            <div key={ip} className="ip-row">
                              <span className="ip-address">{ip}</span>
                              <span className="ip-count">{count}</span>
                            </div>
                          ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {results.statistics?.top_ports && (
                <div className="card ports-card">
                  <h3>🔌 Top Ports</h3>
                  <div className="ports-grid">
                    {Object.entries(results.statistics.top_ports)
                      .slice(0, 12)
                      .map(([port, count]) => (
                        <div key={port} className="port-item">
                          <div className="port-number">{port}</div>
                          <div className="port-count">{count}</div>
                        </div>
                      ))}
                  </div>
                </div>
              )}

              {results.threats && (
                <div className="card threat-card">
                  <h3>⚠️ Threats</h3>
                  <div className="threat-info">
                    <div className="threat-stat">
                      <span className="threat-label">Risk</span>
                      <span className="threat-value">{results.threats.risk_score}/100</span>
                    </div>
                    <div className="threat-stat">
                      <span className="threat-label">Detected</span>
                      <span className="threat-value">{results.threats.threats?.length || 0}</span>
                    </div>
                  </div>

                  {results.threats.threat_summary?.top_concerns && (
                    <div className="threat-summary">
                      <h4>🎯 Main Concerns</h4>
                      {results.threats.threat_summary.top_concerns.map((concern, idx) => (
                        <div key={idx} className="concern">{concern}</div>
                      ))}
                    </div>
                  )}

                  {results.threats.threats?.length > 0 && (
                    <div className="threats-list">
                      {results.threats.threats.map((threat, idx) => (
                        <div key={idx} className={`threat-item severity-${threat.severity}`}>
                          <div className="threat-type">{threat.type}</div>
                          <div className="threat-description">{threat.description}</div>
                          {threat.source && (
                            <div className="threat-detail">
                              Source: {threat.source}
                              {threat.source_domain && <span className="domain-badge">{threat.source_domain}</span>}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                  <div className="threat-note">
                    <span className="note-icon">💡</span>
                    <span className="note-text"><strong>Note:</strong> Your own IP may be flagged as a threat if it has many packets sent. This is normal behavior and not a security concern.</span>
                  </div>
                </div>
              )}
                </div>
              )}

              {/* Graphs Tab */}
              {activeTab === 'graphs' && (
                <div className="tab-content">
                  {results.network_graph && (
                    <div className="card">
                      <h3>🌐 Network Graph - IP Relationships</h3>
                      <NetworkGraph 
                        data={results.network_graph}
                        threatIPs={results.threats?.threats?.map(t => t.source).filter(Boolean) || []}
                      />
                    </div>
                  )}
                </div>
              )}

              {/* Timeline Tab */}
              {activeTab === 'timeline' && (
                <div className="tab-content">
                  {results.timeline && (
                    <Timeline 
                      timelineData={results.timeline}
                      threats={results.threats?.threats || []}
                    />
                  )}
                </div>
              )}

              {/* Packets Tab */}
              {activeTab === 'packets' && (
                <div className="tab-content">
                  {results.packets && results.packets.length > 0 && (
                    <PacketInspector packets={results.packets} />
                  )}
                </div>
              )}

              {/* Export Tab */}
              {activeTab === 'export' && (
                <div className="tab-content">
                  {/* AI Summary Section */}
                  {results.ai_summary && (
                    <div className="card ai-summary-card">
                      <h3>🤖 AI Analysis Summary</h3>
                      <div className="ai-summary-content">
                        <div className="summary-section">
                          <h4>📋 Overview</h4>
                          <p>{results.ai_summary.overview}</p>
                        </div>
                        
                        <div className="summary-section">
                          <h4>📊 Traffic Analysis</h4>
                          <p>{results.ai_summary.traffic_analysis}</p>
                        </div>
                        
                        <div className="summary-section">
                          <h4>🎯 Threat Summary</h4>
                          <p>{results.ai_summary.threat_summary}</p>
                        </div>
                        
                        <div className="summary-section">
                          <h4>🌐 Network Behavior</h4>
                          <p>{results.ai_summary.network_behavior}</p>
                        </div>
                        
                        {results.ai_summary.key_findings && results.ai_summary.key_findings.length > 0 && (
                          <div className="summary-section">
                            <h4>🔑 Key Findings</h4>
                            <ul className="findings-list">
                              {results.ai_summary.key_findings.map((finding, idx) => (
                                <li key={idx}>{finding}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                        
                        {results.ai_summary.recommendations && results.ai_summary.recommendations.length > 0 && (
                          <div className="summary-section">
                            <h4>💡 Recommendations</h4>
                            <ul className="recommendations-list">
                              {results.ai_summary.recommendations.map((rec, idx) => (
                                <li key={idx}>{rec}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  <div className="action-buttons">
                    <button className="export-button" onClick={handleExportPDF}>
                      📄 Export PDF Report
                    </button>
                    <button className="reset-button" onClick={handleReset}>
                      ↻ Analyze Another File
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        <div className="right-panel">
          {results && (
            <div className="panel-card chatbot-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <div>
                  <h3 style={{ marginBottom: '4px' }}>💬 AI Assistant</h3>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.75rem', color: '#888' }}>
                    <span style={{ 
                      display: 'inline-flex', 
                      alignItems: 'center', 
                      gap: '4px',
                      background: 'rgba(0, 255, 136, 0.1)',
                      padding: '3px 8px',
                      borderRadius: '12px',
                      border: '1px solid rgba(0, 255, 136, 0.3)'
                    }}>
                      <span style={{ 
                        width: '6px', 
                        height: '6px', 
                        background: '#00ff88', 
                        borderRadius: '50%',
                        animation: 'pulse 2s infinite'
                      }}></span>
                      Powered by Groq AI
                    </span>
                    <span style={{ color: '#666' }}>•</span>
                    <span>Real-time analysis</span>
                  </div>
                </div>
                {chatMessages.length > 0 && (
                  <button 
                    onClick={handleClearChat}
                    style={{
                      padding: '6px 12px',
                      background: 'rgba(255,255,255,0.05)',
                      border: '1px solid rgba(255,255,255,0.1)',
                      borderRadius: '6px',
                      color: '#888',
                      cursor: 'pointer',
                      fontSize: '0.75rem',
                      transition: 'all 0.2s'
                    }}
                    onMouseEnter={(e) => {
                      e.target.style.background = 'rgba(255, 68, 68, 0.1)';
                      e.target.style.borderColor = 'rgba(255, 68, 68, 0.3)';
                      e.target.style.color = '#ff4444';
                    }}
                    onMouseLeave={(e) => {
                      e.target.style.background = 'rgba(255,255,255,0.05)';
                      e.target.style.borderColor = 'rgba(255,255,255,0.1)';
                      e.target.style.color = '#888';
                    }}
                  >
                    🗑️ Clear
                  </button>
                )}
              </div>
              <div className="chat-container">
                <div className="chat-messages">
                  {chatMessages.length === 0 && (
                    <div className="chat-welcome">
                      <p style={{ fontSize: '16px', marginBottom: '16px' }}>👋 <strong>Hi! I'm your AI network security analyst.</strong></p>
                      <p style={{ fontSize: '13px', color: '#888', marginBottom: '20px' }}>
                        I've analyzed your packet capture and can help you understand what's happening in your network. Ask me anything!
                      </p>
                      <div className="chat-suggestions">
                        <button onClick={() => setChatInput("What are the biggest security risks I should be worried about?")}>
                          🔐 Security Risks
                        </button>
                        <button onClick={() => setChatInput("Explain the network traffic patterns in simple terms")}>
                          📊 Traffic Patterns
                        </button>
                        <button onClick={() => setChatInput("What protocols are being used and what do they do?")}>
                          🌐 Protocol Analysis
                        </button>
                        <button onClick={() => setChatInput("Are there any suspicious IPs or unusual behavior?")}>
                          ⚠️ Suspicious Activity
                        </button>
                        <button onClick={() => setChatInput("Give me a quick summary of what's happening in this capture")}>
                          ⚡ Quick Summary
                        </button>
                      </div>
                    </div>
                  )}
                  {chatMessages.map((msg, idx) => (
                    <div key={idx} className={`chat-message ${msg.role} ${msg.isError ? 'error' : ''}`}>
                      <div className="message-header">
                        <div className="message-icon">
                          {msg.role === 'user' ? '👤' : msg.isError ? '⚠️' : '🤖'}
                        </div>
                        <div className="message-meta">
                          <span className="message-role">{msg.role === 'user' ? 'You' : 'AI Assistant'}</span>
                          <span className="message-time">{msg.timestamp}</span>
                        </div>
                        <button 
                          className="copy-btn"
                          onClick={() => handleCopyMessage(msg.content)}
                          title="Copy message"
                        >
                          📋
                        </button>
                      </div>
                      <div className="message-content">
                        {msg.content.split('\n').map((line, i) => (
                          <span key={i}>
                            {line}
                            {i < msg.content.split('\n').length - 1 && <br />}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                  {chatLoading && (
                    <div className="chat-message assistant typing-message">
                      <div className="message-header">
                        <div className="message-icon">🤖</div>
                        <div className="message-meta">
                          <span className="message-role">AI Assistant</span>
                        </div>
                      </div>
                      <div className="message-content typing">
                        <span className="typing-dot"></span>
                        <span className="typing-dot"></span>
                        <span className="typing-dot"></span>
                        <span style={{ marginLeft: '8px' }}>Analyzing...</span>
                      </div>
                    </div>
                  )}
                  <div ref={chatMessagesEndRef} />
                </div>
                <div className="chat-input-container">
                  <textarea
                    className="chat-input"
                    placeholder="Ask me anything about your packet capture... (Press Enter to send, Shift+Enter for new line)"
                    value={chatInput}
                    onChange={(e) => setChatInput(e.target.value)}
                    onKeyDown={(e) => {
                      e.stopPropagation();
                      if (e.key === 'Enter' && !e.shiftKey) {
                        e.preventDefault();
                        handleChatSend();
                      }
                    }}
                    disabled={chatLoading}
                    rows={2}
                    style={{ resize: 'vertical', minHeight: '50px', maxHeight: '150px' }}
                  />
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <span style={{ fontSize: '0.7rem', color: '#666', flex: 1 }}>
                      {chatInput.length > 0 && `${chatInput.length} chars`}
                    </span>
                    <button 
                      className="chat-send-btn" 
                      onClick={handleChatSend}
                      disabled={chatLoading || !chatInput.trim()}
                      title="Send message"
                    >
                      {chatLoading ? '⏳' : '➤'}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
      <footer className="app-footer">
        <p>mouhamedrayen.mansouri@esprit.tn</p>
      </footer>
    </div>
  );
}
