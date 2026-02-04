import React, { useMemo } from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import './Timeline.css';

const PROTOCOL_COLORS = {
  TCP: '#00d4ff',
  UDP: '#00ff88',
  ICMP: '#ffaa00',
  DNS: '#ff4444',
  HTTP: '#00d4ff',
  HTTPS: '#00ff88',
  SSH: '#ffaa00',
  FTP: '#ff4444',
  SMTP: '#00d4ff',
  POP3: '#00ff88',
  IMAP: '#ffaa00',
  TELNET: '#ff4444',
  ARP: '#00d4ff',
  Other: '#888888',
};

export default function Timeline({ timelineData, threats = [] }) {
  const chartData = useMemo(() => {
    if (!timelineData || !timelineData.timeline) return [];

    return timelineData.timeline.map((bucket) => {
      const item = {
        time: bucket.timestamp || `${bucket.time.toFixed(1)}s`,
        timestamp: bucket.timestamp,
        packets: bucket.packets || 0,
      };

      // Add protocol breakdown
      if (bucket.protocols) {
        Object.entries(bucket.protocols).forEach(([protocol, count]) => {
          item[protocol] = count || 0;
        });
      }

      return item;
    });
  }, [timelineData]);

  const protocols = useMemo(() => {
    const protocolSet = new Set();
    chartData.forEach((item) => {
      Object.keys(item).forEach((key) => {
        if (
          key !== 'time' &&
          key !== 'timestamp' &&
          key !== 'packets' &&
          typeof item[key] === 'number' &&
          item[key] > 0
        ) {
          protocolSet.add(key);
        }
      });
    });
    return Array.from(protocolSet);
  }, [chartData]);

  const threatTimestamps = useMemo(() => {
    return threats
      .filter((threat) => threat.timestamp)
      .map((threat) => ({
        timestamp: threat.timestamp,
        severity: threat.severity,
      }));
  }, [threats]);

  if (!chartData || chartData.length === 0) {
    return (
      <div className="timeline-container">
        <div className="timeline-placeholder">
          📊 No timeline data available
        </div>
      </div>
    );
  }

  return (
    <div className="timeline-container">
      <div className="timeline-header">
        <h3>📊 Traffic Timeline</h3>
        <p className="timeline-subtitle">
          {timelineData.total_duration.toFixed(2)}s duration • {chartData.length} time buckets
        </p>
      </div>

      <ResponsiveContainer width="100%" height={400}>
        <AreaChart
          data={chartData}
          margin={{ top: 10, right: 30, left: 0, bottom: 30 }}
          className="timeline-chart"
        >
          <defs>
            {protocols.map((protocol) => (
              <linearGradient
                key={`gradient-${protocol}`}
                id={`gradient-${protocol}`}
                x1="0"
                y1="0"
                x2="0"
                y2="1"
              >
                <stop
                  offset="5%"
                  stopColor={PROTOCOL_COLORS[protocol] || PROTOCOL_COLORS.Other}
                  stopOpacity={0.8}
                />
                <stop
                  offset="95%"
                  stopColor={PROTOCOL_COLORS[protocol] || PROTOCOL_COLORS.Other}
                  stopOpacity={0.1}
                />
              </linearGradient>
            ))}
          </defs>

          <CartesianGrid strokeDasharray="3 3" stroke="#333" />
          <XAxis
            dataKey="time"
            stroke="#666"
            tick={{ fontSize: 12 }}
            angle={-45}
            textAnchor="end"
            height={70}
          />
          <YAxis stroke="#666" tick={{ fontSize: 12 }} label={{ value: 'Packets', angle: -90, position: 'insideLeft' }} />

          <Tooltip
            contentStyle={{
              backgroundColor: '#1a1a2e',
              border: '2px solid #00d4ff',
              borderRadius: '8px',
              padding: '12px',
            }}
            cursor={{ fill: 'rgba(0, 212, 255, 0.1)' }}
            formatter={(value, name) => [value, name]}
            labelStyle={{ color: '#00d4ff' }}
          />

          <Legend
            wrapperStyle={{ paddingTop: '20px' }}
            iconType="line"
            tick={{ fontSize: 12 }}
            height={30}
          />

          {protocols.map((protocol) => (
            <Area
              key={protocol}
              type="monotone"
              dataKey={protocol}
              stackId="protocols"
              stroke={PROTOCOL_COLORS[protocol] || PROTOCOL_COLORS.Other}
              fill={`url(#gradient-${protocol})`}
              fillOpacity={1}
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>

      {threatTimestamps.length > 0 && (
        <div className="threat-markers">
          <h4>🎯 Threat Timeline</h4>
          <div className="threats-list">
            {threatTimestamps.map((threat, idx) => (
              <div key={idx} className={`threat-marker threat-${threat.severity}`}>
                <span className="threat-time">{threat.timestamp.toFixed(2)}s</span>
                <span className="threat-severity">{threat.severity}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="timeline-info">
        <div className="info-item">
          <span className="info-label">Start Time:</span>
          <span className="info-value">{timelineData.start_time.toFixed(2)}s</span>
        </div>
        <div className="info-item">
          <span className="info-label">End Time:</span>
          <span className="info-value">{timelineData.end_time.toFixed(2)}s</span>
        </div>
        <div className="info-item">
          <span className="info-label">Duration:</span>
          <span className="info-value">{timelineData.total_duration.toFixed(2)}s</span>
        </div>
        <div className="info-item">
          <span className="info-label">Buckets:</span>
          <span className="info-value">{chartData.length}</span>
        </div>
      </div>
    </div>
  );
}
