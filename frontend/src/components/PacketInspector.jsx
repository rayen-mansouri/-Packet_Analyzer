import React, { useState, useMemo } from 'react';
import './PacketInspector.css';

const PacketInspector = ({ packets = [] }) => {
  const [selectedPacket, setSelectedPacket] = useState(packets.length > 0 ? packets[0] : null);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterProtocol, setFilterProtocol] = useState('all');

  // Auto-select first packet when packets change
  React.useEffect(() => {
    if (packets.length > 0 && !selectedPacket) {
      setSelectedPacket(packets[0]);
    }
  }, [packets, selectedPacket]);

  const protocols = useMemo(() => {
    const uniqueProtocols = [...new Set(packets.map(p => p.protocol))];
    return ['all', ...uniqueProtocols.sort()];
  }, [packets]);

  const filteredPackets = useMemo(() => {
    return packets.filter(packet => {
      const matchesProtocol = filterProtocol === 'all' || packet.protocol === filterProtocol;
      const matchesSearch = !searchTerm ||
        packet.src_ip?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        packet.dst_ip?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        packet.protocol?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        String(packet.src_port).includes(searchTerm) ||
        String(packet.dst_port).includes(searchTerm);
      return matchesProtocol && matchesSearch;
    });
  }, [packets, searchTerm, filterProtocol]);

  const getServiceName = (port) => {
    const services = {
      20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
      25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
      80: 'HTTP', 110: 'POP3', 123: 'NTP', 143: 'IMAP',
      443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 3389: 'RDP',
      5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-Alt',
      27017: 'MongoDB'
    };
    return services[port] || port;
  };

  const describeTCPFlags = (flags) => {
    if (!flags) return '';
    const descriptions = [];
    if (flags.includes('S')) descriptions.push('SYN');
    if (flags.includes('A')) descriptions.push('ACK');
    if (flags.includes('F')) descriptions.push('FIN');
    if (flags.includes('R')) descriptions.push('RST');
    if (flags.includes('P')) descriptions.push('PSH');
    if (flags.includes('U')) descriptions.push('URG');
    return descriptions.join(', ');
  };

  const Section = ({ title, children }) => (
    <div className="detail-section">
      <h4>{title}</h4>
      <div className="section-content">{children}</div>
    </div>
  );

  return (
    <div className="packet-inspector">
      <div className="inspector-header">
        <h3>📦 Packet Inspector</h3>
        <div className="inspector-controls">
          <input
            type="text"
            className="search-input"
            placeholder="Search IP, port, protocol..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
          <select
            className="protocol-filter"
            value={filterProtocol}
            onChange={(e) => setFilterProtocol(e.target.value)}
            style={{
              color: filterProtocol === 'all' ? '#e0e0e0' : 
                     filterProtocol === 'TCP' ? '#00d4ff' : 
                     filterProtocol === 'UDP' ? '#00ff88' : 
                     filterProtocol === 'ICMP' ? '#ffaa00' : 
                     filterProtocol === 'ARP' ? '#ff4444' : '#8855ff'
            }}
          >
            {protocols.map(proto => (
              <option 
                key={proto} 
                value={proto}
                style={{
                  color: proto === 'all' ? '#333' : 
                         proto === 'TCP' ? '#0099cc' : 
                         proto === 'UDP' ? '#00aa66' : 
                         proto === 'ICMP' ? '#cc8800' : 
                         proto === 'ARP' ? '#cc3333' : '#6633cc',
                  backgroundColor: '#fff'
                }}
              >
                {proto === 'all' ? 'All Protocols' : proto}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="inspector-content">
        <div className="packet-list">
          <div className="packet-table-header">
            <span className="col-num">#</span>
            <span className="col-src">Source IP</span>
            <span className="col-dst">Dest IP</span>
            <span className="col-proto">Protocol</span>
          </div>
          <div className="packet-table-body">
            {filteredPackets.length === 0 ? (
              <div className="no-packets">No packets match your filters</div>
            ) : (
              filteredPackets.map((packet, index) => (
                <div
                  key={index}
                  className={`packet-row ${selectedPacket === packet ? 'selected' : ''}`}
                  onClick={() => setSelectedPacket(packet)}
                >
                  <span className="col-num">{index + 1}</span>
                  <span className="col-src">{packet.src_ip}</span>
                  <span className="col-dst">{packet.dst_ip}</span>
                  <span className={`col-proto protocol-${packet.protocol}`}>
                    {packet.protocol}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="packet-details">
          {selectedPacket ? (
            <>
              <div className="details-header">
                <h4>Packet #{filteredPackets.indexOf(selectedPacket) + 1} - Detailed Analysis</h4>
              </div>

              <Section title="📋 Overview">
                <div className="detail-row">
                  <span className="label">Packet Number:</span>
                  <span className="value">#{filteredPackets.indexOf(selectedPacket) + 1}</span>
                </div>
                <div className="detail-row">
                  <span className="label">Length:</span>
                  <span className="value">{selectedPacket.length} bytes</span>
                </div>
                <div className="detail-row">
                  <span className="label">Protocol:</span>
                  <span className="value protocol-badge">{selectedPacket.protocol}</span>
                </div>
                <div className="detail-row">
                  <span className="label">Timestamp:</span>
                  <span className="value">{selectedPacket.timestamp}</span>
                </div>
                {selectedPacket.timestamp && (
                  <div className="detail-row">
                    <span className="label">Human Time:</span>
                    <span className="value">{new Date(parseFloat(selectedPacket.timestamp) * 1000).toLocaleString()}</span>
                  </div>
                )}
                <div className="detail-row">
                  <span className="label">Info:</span>
                  <span className="value">{selectedPacket.info || 'N/A'}</span>
                </div>
              </Section>

              <Section title="🌐 Network Layer">
                <div className="detail-row">
                  <span className="label">Source IP:</span>
                  <span className="value ip-address">{selectedPacket.src_ip}</span>
                </div>
                {selectedPacket.src_port && (
                  <div className="detail-row">
                    <span className="label">Source Port:</span>
                    <span className="value">{selectedPacket.src_port} ({getServiceName(selectedPacket.src_port)})</span>
                  </div>
                )}
                <div className="detail-row">
                  <span className="label">Destination IP:</span>
                  <span className="value ip-address">{selectedPacket.dst_ip}</span>
                </div>
                {selectedPacket.dst_port && (
                  <div className="detail-row">
                    <span className="label">Destination Port:</span>
                    <span className="value">{selectedPacket.dst_port} ({getServiceName(selectedPacket.dst_port)})</span>
                  </div>
                )}
                {selectedPacket.ttl && (
                  <div className="detail-row">
                    <span className="label">TTL (Time to Live):</span>
                    <span className="value">{selectedPacket.ttl} hops</span>
                  </div>
                )}
                {selectedPacket.length && (
                  <div className="detail-row">
                    <span className="label">Packet Size:</span>
                    <span className="value">{selectedPacket.length < 1024 ? `${selectedPacket.length} bytes` : `${(selectedPacket.length / 1024).toFixed(2)} KB`}</span>
                  </div>
                )}
              </Section>

              {selectedPacket.protocol === "TCP" && (selectedPacket.seq || selectedPacket.ack || selectedPacket.flags) && (
                <Section title="🔌 TCP Details">
                  {selectedPacket.seq && (
                    <div className="detail-row">
                      <span className="label">Sequence Number:</span>
                      <span className="value">{selectedPacket.seq}</span>
                    </div>
                  )}
                  {selectedPacket.ack && (
                    <div className="detail-row">
                      <span className="label">Acknowledgment Number:</span>
                      <span className="value">{selectedPacket.ack}</span>
                    </div>
                  )}
                  {selectedPacket.flags && (
                    <div className="detail-row">
                      <span className="label">TCP Flags:</span>
                      <span className="value flags-value">
                        {selectedPacket.flags} ({describeTCPFlags(selectedPacket.flags)})
                      </span>
                    </div>
                  )}
                  {selectedPacket.window && (
                    <div className="detail-row">
                      <span className="label">Window Size:</span>
                      <span className="value">{selectedPacket.window} bytes</span>
                    </div>
                  )}
                </Section>
              )}

              {selectedPacket.protocol === "UDP" && selectedPacket.length && (
                <Section title="📡 UDP Details">
                  <div className="detail-row">
                    <span className="label">UDP Length:</span>
                    <span className="value">{selectedPacket.length} bytes</span>
                  </div>
                  <div className="detail-row">
                    <span className="label">Checksum:</span>
                    <span className="value">{selectedPacket.checksum || 'N/A'}</span>
                  </div>
                </Section>
              )}

              {selectedPacket.http_info && (
                <Section title="🌍 HTTP Details">
                  {selectedPacket.http_info.method && (
                    <div className="detail-row">
                      <span className="label">Method:</span>
                      <span className="value http-method">{selectedPacket.http_info.method}</span>
                    </div>
                  )}
                  {selectedPacket.http_info.host && (
                    <div className="detail-row">
                      <span className="label">Host:</span>
                      <span className="value">{selectedPacket.http_info.host}</span>
                    </div>
                  )}
                  {selectedPacket.http_info.uri && (
                    <div className="detail-row">
                      <span className="label">URI:</span>
                      <span className="value uri-value">{selectedPacket.http_info.uri}</span>
                    </div>
                  )}
                  {selectedPacket.http_info.user_agent && (
                    <div className="detail-row">
                      <span className="label">User Agent:</span>
                      <span className="value small-text">{selectedPacket.http_info.user_agent}</span>
                    </div>
                  )}
                </Section>
              )}

              {selectedPacket.dns_info && (
                <Section title="🔍 DNS Details">
                  {selectedPacket.dns_info.query && (
                    <div className="detail-row">
                      <span className="label">Query:</span>
                      <span className="value">{selectedPacket.dns_info.query}</span>
                    </div>
                  )}
                  {selectedPacket.dns_info.response && (
                    <div className="detail-row">
                      <span className="label">Response:</span>
                      <span className="value">{selectedPacket.dns_info.response}</span>
                    </div>
                  )}
                </Section>
              )}
            </>
          ) : (
            <div className="no-selection">
              <div className="no-selection-icon">📦</div>
              <p>Select a packet to view details</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default PacketInspector;
