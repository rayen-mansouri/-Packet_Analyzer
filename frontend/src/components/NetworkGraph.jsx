import React, { useEffect, useRef, useState } from "react";
import * as d3 from "d3";
import "./NetworkGraph.css";

export default function NetworkGraph({ data, threatIPs = [] }) {
  const svgRef = useRef(null);
  const containerRef = useRef(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [hoveredNode, setHoveredNode] = useState(null);
  const [stats, setStats] = useState({ nodes: 0, links: 0, maxPackets: 0 });
  const zoomInitializedRef = useRef(false);
  const simulationRef = useRef(null);

  useEffect(() => {
    if (!data || !data.nodes || !data.links || !svgRef.current) return;

    // Get actual dimensions
    const container = containerRef.current;
    const width = container?.clientWidth || 1000;
    const height = container?.clientHeight || 600;

    // Clear previous svg
    d3.select(svgRef.current).selectAll("*").remove();
    zoomInitializedRef.current = false; // Reset zoom flag on new data

    const svg = d3.select(svgRef.current).attr("width", width).attr("height", height);

    // Create defs for gradients and markers
    const defs = svg.append("defs");
    
    // Arrow markers for directed edges
    defs
      .append("marker")
      .attr("id", "arrowhead")
      .attr("markerWidth", 10)
      .attr("markerHeight", 10)
      .attr("refX", 20)
      .attr("refY", 3)
      .attr("orient", "auto")
      .append("polygon")
      .attr("points", "0 0, 10 3, 0 6")
      .attr("fill", "rgba(0, 212, 255, 0.5)");

    defs
      .append("marker")
      .attr("id", "arrowhead-threat")
      .attr("markerWidth", 10)
      .attr("markerHeight", 10)
      .attr("refX", 20)
      .attr("refY", 3)
      .attr("orient", "auto")
      .append("polygon")
      .attr("points", "0 0, 10 3, 0 6")
      .attr("fill", "rgba(255, 68, 68, 0.7)");

    // Create main group for zoom/pan
    const g = svg.append("g");

    // Add zoom behavior
    const zoom = d3.zoom().on("zoom", (event) => {
      g.attr("transform", event.transform);
    });
    svg.call(zoom);

    // Prepare data - use more nodes if available, max 50
    const allNodes = data.nodes.sort((a, b) => b.total_packets - a.total_packets);
    const displayNodes = allNodes.slice(0, Math.min(50, Math.max(10, allNodes.length)));
    const nodeIds = new Set(displayNodes.map((n) => n.id));
    const displayLinks = data.links.filter((l) => nodeIds.has(l.source) && nodeIds.has(l.target));

    // Calculate max packets for scaling
    const maxPackets = Math.max(...displayNodes.map((n) => n.total_packets), 1);

    setStats({
      nodes: displayNodes.length,
      links: displayLinks.length,
      maxPackets,
    });

    // Node radius scale function
    const nodeRadiusScale = d3
      .scaleSqrt()
      .domain([0, maxPackets])
      .range([12, 60]);

    // Link width scale
    const linkWidthScale = d3
      .scaleSqrt()
      .domain([0, Math.max(...displayLinks.map((l) => l.packets), 1)])
      .range([1, 8]);

    // Force simulation
    const simulation = d3
      .forceSimulation(displayNodes)
      .force(
        "link",
        d3
          .forceLink(displayLinks)
          .id((d) => d.id)
          .distance((d) => {
            // Closer nodes when there are fewer IPs
            const nodeCount = displayNodes.length;
            const baseDist = nodeCount < 10 ? 80 : nodeCount < 20 ? 120 : 150;
            return Math.max(baseDist, baseDist - d.packets / 5);
          })
          .strength(0.08)
      )
      .force(
        "charge",
        d3.forceManyBody().strength((d) => {
          // Less repulsion when fewer nodes
          const nodeCount = displayNodes.length;
          return nodeCount < 10 ? -400 : nodeCount < 20 ? -600 : -1000;
        }).distanceMax(800)
      )
      .force("center", d3.forceCenter(width / 2, height / 2).strength(0.15))
      .force(
        "collision",
        d3
          .forceCollide()
          .radius((d) => nodeRadiusScale(d.total_packets) + 25)
          .strength(0.8)
      );

    // Create links
    const link = g
      .append("g")
      .selectAll("line")
      .data(displayLinks)
      .enter()
      .append("line")
      .attr("stroke", (d) => {
        const isThreat = threatIPs.includes(d.source) || threatIPs.includes(d.target);
        return isThreat ? "rgba(255, 68, 68, 0.6)" : "rgba(0, 212, 255, 0.4)";
      })
      .attr("stroke-width", (d) => linkWidthScale(d.packets))
      .attr("opacity", 0.7)
      .attr("class", "network-link")
      .attr("marker-end", (d) => {
        const isThreat = threatIPs.includes(d.source) || threatIPs.includes(d.target);
        return isThreat ? "url(#arrowhead-threat)" : "url(#arrowhead)";
      });

    // Create node groups
    const node = g
      .append("g")
      .selectAll("g")
      .data(displayNodes)
      .enter()
      .append("g")
      .attr("class", "network-node")
      .call(
        d3
          .drag()
          .on("start", dragStarted)
          .on("drag", dragged)
          .on("end", dragEnded)
      );

    // Add circles
    node
      .append("circle")
      .attr("r", (d) => nodeRadiusScale(d.total_packets))
      .attr("fill", (d) => {
        if (threatIPs.includes(d.id)) return "#ff5555";
        if (selectedNode === d.id) return "#00ff88";
        if (hoveredNode === d.id) return "#ffaa00";
        return "#00d4ff";
      })
      .attr("stroke", (d) => {
        if (threatIPs.includes(d.id)) return "#ff8888";
        return "#ffffff";
      })
      .attr("stroke-width", (d) => {
        if (selectedNode === d.id || hoveredNode === d.id) return 3;
        if (threatIPs.includes(d.id)) return 2.5;
        return 2;
      })
      .on("mouseover", (event, d) => {
        setHoveredNode(d.id);
      })
      .on("mouseout", () => {
        setHoveredNode(null);
      })
      .on("click", (event, d) => {
        event.stopPropagation();
        setSelectedNode(selectedNode === d.id ? null : d.id);
      });

    // Add labels with background
    node
      .append("rect")
      .attr("x", (d) => {
        const text = d.id.split(".").slice(-2).join(".");
        return -(text.length * 3);
      })
      .attr("y", -10)
      .attr("width", (d) => {
        const text = d.id.split(".").slice(-2).join(".");
        return text.length * 6;
      })
      .attr("height", 14)
      .attr("fill", "rgba(0, 0, 0, 0.7)")
      .attr("rx", 3)
      .attr("opacity", (d) => (hoveredNode === d.id || selectedNode === d.id ? 1 : 0.6));

    node
      .append("text")
      .attr("text-anchor", "middle")
      .attr("dy", ".3em")
      .attr("font-size", (d) => {
        const radius = nodeRadiusScale(d.total_packets);
        return Math.max(9, radius / 3);
      })
      .attr("font-weight", "bold")
      .attr("fill", "#ffffff")
      .attr("pointer-events", "none")
      .text((d) => d.id.split(".").slice(-2).join("."));

    // Add packet count labels below nodes
    node
      .append("text")
      .attr("text-anchor", "middle")
      .attr("dy", (d) => nodeRadiusScale(d.total_packets) + 18)
      .attr("font-size", "10px")
      .attr("fill", "#00ff88")
      .attr("font-weight", "600")
      .attr("pointer-events", "none")
      .attr("opacity", (d) => (hoveredNode === d.id || selectedNode === d.id ? 1 : 0.7))
      .text((d) => `${d.total_packets}📦`);

    // Tooltips
    const tooltip = d3
      .select("body")
      .append("div")
      .attr("class", "network-tooltip")
      .style("opacity", 0);

    node.on("mouseover", (event, d) => {
      tooltip
        .transition()
        .duration(200)
        .style("opacity", 0.95);
      tooltip
        .html(
          `<div style="font-weight: bold; color: #00d4ff; margin-bottom: 8px;">${d.id}</div>` +
            `<div style="margin-bottom: 4px;">📦 Total: <strong>${d.total_packets}</strong></div>` +
            `<div style="margin-bottom: 4px;">📤 Sent: <strong>${d.packets_sent}</strong></div>` +
            `<div style="margin-bottom: 4px;">📥 Received: <strong>${d.packets_received}</strong></div>` +
            `<div style="margin-bottom: 4px;">💾 Size: <strong>${(d.total_size / 1024).toFixed(1)} KB</strong></div>` +
            `<div style="border-top: 1px solid rgba(0, 212, 255, 0.3); padding-top: 6px; margin-top: 6px;">` +
            Object.entries(d.protocols)
              .map(([p, c]) => `<div>${p}: <strong>${c}</strong></div>`)
              .join("") +
            `</div>`
        )
        .style("left", event.pageX + 10 + "px")
        .style("top", event.pageY - 28 + "px");
      setHoveredNode(d.id);
    });

    node.on("mouseout", () => {
      tooltip.transition().duration(500).style("opacity", 0);
      setHoveredNode(null);
    });

    svg.on("click", () => {
      setSelectedNode(null);
    });

    // Update positions on tick
    simulation.on("tick", () => {
      link
        .attr("x1", (d) => d.source.x)
        .attr("y1", (d) => d.source.y)
        .attr("x2", (d) => d.target.x)
        .attr("y2", (d) => d.target.y);

      node.attr("transform", (d) => `translate(${d.x},${d.y})`);
    });

    // Initial zoom fit - only once per data load
    if (!zoomInitializedRef.current) {
      setTimeout(() => {
        const bounds = g.node().getBBox();
        const fullWidth = bounds.width + 100;
        const fullHeight = bounds.height + 100;
        const midX = bounds.x + bounds.width / 2;
        const midY = bounds.y + bounds.height / 2;

        const scale = Math.min(width / fullWidth, height / fullHeight) * 0.9;
        const translate = [width / 2 - scale * midX, height / 2 - scale * midY];

        svg
          .transition()
          .duration(750)
          .call(zoom.transform, d3.zoomIdentity.translate(translate[0], translate[1]).scale(scale));
        
        zoomInitializedRef.current = true;
      }, 100);
    }

    // Drag functions
    function dragStarted(event, d) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
    }

    function dragged(event, d) {
      d.fx = event.x;
      d.fy = event.y;
    }

    function dragEnded(event, d) {
      if (!event.active) simulation.alphaTarget(0);
      d.fx = null;
      d.fy = null;
    }

    return () => {
      tooltip.remove();
      simulation.stop();
    };
  }, [data, threatIPs]); // FIXED: Only depend on data and threatIPs, NOT hoveredNode or selectedNode!

  // FIXED: Separate effect just for styling updates when hovering/selecting
  useEffect(() => {
    if (!svgRef.current) return;

    d3.select(svgRef.current)
      .selectAll(".network-node circle")
      .attr("fill", (d) => {
        if (threatIPs.includes(d.id)) return "#ff5555";
        if (selectedNode === d.id) return "#00ff88";
        if (hoveredNode === d.id) return "#ffaa00";
        return "#00d4ff";
      })
      .attr("stroke-width", (d) => {
        if (selectedNode === d.id || hoveredNode === d.id) return 3;
        if (threatIPs.includes(d.id)) return 2.5;
        return 2;
      });

    d3.select(svgRef.current)
      .selectAll(".network-node rect")
      .attr("opacity", (d) => (hoveredNode === d.id || selectedNode === d.id ? 1 : 0.6));

  }, [selectedNode, hoveredNode, threatIPs]);

  const selectedNodeData = selectedNode && data?.nodes?.find((n) => n.id === selectedNode);

  return (
    <div className="network-graph-container">
      <div className="network-header">
        <div className="network-stats">
          <span className="stat-item">🔵 {stats.nodes} IPs</span>
          <span className="stat-item">🔗 {stats.links} Connections</span>
          <span className="stat-item">📊 Max: {stats.maxPackets} packets</span>
        </div>
        <div className="network-legend">
          <span className="legend-item"><span className="legend-dot" style={{ background: "#00d4ff" }}></span> Normal</span>
          <span className="legend-item"><span className="legend-dot" style={{ background: "#ff5555" }}></span> Threat</span>
          <span className="legend-item">⭕ Size = Traffic</span>
        </div>
      </div>
      <div ref={containerRef} className="network-graph-wrapper">
        <svg ref={svgRef} className="network-graph"></svg>
      </div>
      {selectedNodeData && (
        <div className="network-node-info">
          <button className="close-btn" onClick={() => setSelectedNode(null)}>✕</button>
          <h4>IP Details</h4>
          <p className="ip-address">{selectedNodeData.id}</p>
          <div className="ip-details">
            <div className="detail-row">
              <span>Total Packets:</span>
              <strong>{selectedNodeData.total_packets}</strong>
            </div>
            <div className="detail-row">
              <span>Sent:</span>
              <strong>{selectedNodeData.packets_sent}</strong>
            </div>
            <div className="detail-row">
              <span>Received:</span>
              <strong>{selectedNodeData.packets_received}</strong>
            </div>
            <div className="detail-row">
              <span>Data Size:</span>
              <strong>{(selectedNodeData.total_size / 1024).toFixed(2)} KB</strong>
            </div>
            <div className="detail-row">
              <span>Avg Packet Size:</span>
              <strong>
                {(selectedNodeData.total_size / Math.max(selectedNodeData.total_packets, 1)).toFixed(0)} b
              </strong>
            </div>
            <div className="protocols-section">
              <h5>Protocols</h5>
              {Object.entries(selectedNodeData.protocols).map(([proto, count]) => (
                <div key={proto} className="protocol-line">
                  {proto}: <strong>{count}</strong>
                </div>
              ))}
            </div>
            {threatIPs.includes(selectedNodeData.id) && (
              <div className="threat-indicator">⚠️ THREAT IP</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

