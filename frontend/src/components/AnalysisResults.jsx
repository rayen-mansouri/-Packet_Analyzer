import React, { useState } from 'react'
import { FiChevronDown } from 'react-icons/fi'

function AnalysisResults({ data }) {
  const [expandedSections, setExpandedSections] = useState({
    summary: true,
    threats: true,
    statistics: true,
    packets: false,
    graphs: true
  })

  const toggleSection = (section) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }))
  }

  const Section = ({ title, section, children }) => (
    <div className="bg-slate-800 rounded-lg border border-slate-700 overflow-hidden">
      <button
        onClick={() => toggleSection(section)}
        className="w-full px-6 py-4 flex items-center justify-between hover:bg-slate-700/50 transition text-white font-semibold"
      >
        <span>{title}</span>
        <FiChevronDown
          className={`w-5 h-5 transition transform ${
            expandedSections[section] ? 'rotate-180' : ''
          }`}
        />
      </button>
      {expandedSections[section] && (
        <div className="px-6 py-4 border-t border-slate-700 text-slate-300">
          {children}
        </div>
      )}
    </div>
  )

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-blue-900 to-slate-900 rounded-lg p-6 border border-blue-700">
        <h2 className="text-3xl font-bold text-white mb-2">{data.file_name}</h2>
        <div className="grid grid-cols-4 gap-4">
          <div>
            <p className="text-slate-400 text-sm">Total Packets</p>
            <p className="text-2xl font-bold text-blue-400">{data.total_packets}</p>
          </div>
          <div>
            <p className="text-slate-400 text-sm">Unique Flows</p>
            <p className="text-2xl font-bold text-blue-400">{data.flows_count}</p>
          </div>
          <div>
            <p className="text-slate-400 text-sm">Total Size</p>
            <p className="text-2xl font-bold text-blue-400">
              {(data.statistics.total_size / (1024 * 1024)).toFixed(2)} MB
            </p>
          </div>
          <div>
            <p className="text-slate-400 text-sm">Risk Level</p>
            <p className={`text-2xl font-bold ${
              data.threats?.risk_score > 70 ? 'text-red-400' :
              data.threats?.risk_score > 40 ? 'text-yellow-400' :
              'text-green-400'
            }`}>
              {data.threats?.risk_score || 0}/100
            </p>
          </div>
        </div>
      </div>

      {/* AI Summary */}
      {data.ai_summary && (
        <Section title="🤖 AI Analysis Summary" section="summary">
          <p className="text-slate-300 leading-relaxed whitespace-pre-wrap">
            {data.ai_summary}
          </p>
        </Section>
      )}

      {/* Threats */}
      {data.threats && (
        <Section title="⚠️ Security Threats" section="threats">
          {data.threats.threats.length === 0 ? (
            <p className="text-green-400">No threats detected ✓</p>
          ) : (
            <div className="space-y-3">
              {data.threats.threats.slice(0, 10).map((threat, idx) => (
                <div
                  key={idx}
                  className={`p-4 rounded border-l-4 ${
                    threat.severity === 'critical'
                      ? 'bg-red-900/20 border-red-500'
                      : threat.severity === 'high'
                      ? 'bg-orange-900/20 border-orange-500'
                      : 'bg-yellow-900/20 border-yellow-500'
                  }`}
                >
                  <div className="flex justify-between items-start mb-2">
                    <p className="font-semibold text-white capitalize">
                      {threat.type.replace('_', ' ')}
                    </p>
                    <span className={`text-xs font-bold uppercase px-2 py-1 rounded ${
                      threat.severity === 'critical'
                        ? 'bg-red-500 text-white'
                        : threat.severity === 'high'
                        ? 'bg-orange-500 text-white'
                        : 'bg-yellow-500 text-white'
                    }`}>
                      {threat.severity}
                    </span>
                  </div>
                  <p className="text-sm text-slate-300">{threat.description}</p>
                </div>
              ))}
            </div>
          )}
        </Section>
      )}

      {/* Statistics */}
      <Section title="📊 Network Statistics" section="statistics">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <h3 className="font-semibold text-white mb-3">Protocols</h3>
            <div className="space-y-2">
              {Object.entries(data.statistics.protocols)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 8)
                .map(([protocol, count]) => (
                  <div key={protocol} className="flex justify-between text-sm">
                    <span className="text-slate-400">{protocol}</span>
                    <span className="text-blue-400 font-semibold">{count}</span>
                  </div>
                ))}
            </div>
          </div>
          <div>
            <h3 className="font-semibold text-white mb-3">Top Source IPs</h3>
            <div className="space-y-2">
              {Object.entries(data.statistics.top_ips_src)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 5)
                .map(([ip, count]) => (
                  <div key={ip} className="flex justify-between text-sm">
                    <span className="text-slate-400 font-mono text-xs">{ip}</span>
                    <span className="text-green-400 font-semibold">{count}</span>
                  </div>
                ))}
            </div>
          </div>
        </div>
      </Section>

      {/* Packets Sample */}
      <Section title="📦 Packet Sample" section="packets">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-600">
                <th className="text-left px-4 py-2 text-slate-400">#</th>
                <th className="text-left px-4 py-2 text-slate-400">Source IP</th>
                <th className="text-left px-4 py-2 text-slate-400">Dest IP</th>
                <th className="text-left px-4 py-2 text-slate-400">Protocol</th>
                <th className="text-left px-4 py-2 text-slate-400">Size</th>
              </tr>
            </thead>
            <tbody>
              {data.packets.slice(0, 20).map((pkt, idx) => (
                <tr key={idx} className="border-b border-slate-700 hover:bg-slate-700/30">
                  <td className="px-4 py-2 text-slate-400">{idx + 1}</td>
                  <td className="px-4 py-2 text-slate-300 font-mono text-xs">{pkt.src_ip || '-'}</td>
                  <td className="px-4 py-2 text-slate-300 font-mono text-xs">{pkt.dst_ip || '-'}</td>
                  <td className="px-4 py-2">
                    <span className="bg-blue-900/50 text-blue-300 px-2 py-1 rounded text-xs">
                      {pkt.protocol || 'Other'}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-slate-400">{pkt.length} B</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      {/* Visualizations */}
      {data.visualizations && (
        <Section title="📈 Network Visualizations" section="graphs">
          <p className="text-slate-400 mb-4">
            Visualization graphs will be rendered here with D3.js/Plotly integration
          </p>
          <div className="grid grid-cols-2 gap-4 text-center">
            <div className="bg-slate-700/50 rounded p-8">
              <p className="text-slate-400">IP Relationship Graph</p>
              <p className="text-sm text-slate-500">({data.visualizations.ip_graph.nodes.length} nodes)</p>
            </div>
            <div className="bg-slate-700/50 rounded p-8">
              <p className="text-slate-400">Protocol Flow</p>
              <p className="text-sm text-slate-500">({data.visualizations.protocol_graph.nodes.length} protocols)</p>
            </div>
            <div className="bg-slate-700/50 rounded p-8">
              <p className="text-slate-400">Traffic Timeline</p>
              <p className="text-sm text-slate-500">{data.visualizations.timeline.total_packets} packets</p>
            </div>
            <div className="bg-slate-700/50 rounded p-8">
              <p className="text-slate-400">Port Usage</p>
              <p className="text-sm text-slate-500">{data.visualizations.ports.ports.length} ports</p>
            </div>
          </div>
        </Section>
      )}
    </div>
  )
}

export default AnalysisResults
