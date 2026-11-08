import React, { useState, useEffect } from "react";
import CountUp from "react-countup";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { API_BASE } from "./apiConfig";

const COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#38bdf8",
};

function CustomTooltip({ active, payload, label }) {
  if (active && payload && payload.length) {
    return (
      <div className="custom-tooltip">
        <p className="label">{label}</p>
        {payload.map((entry, index) => (
          <p key={index} className="item" style={{ color: entry.color }}>
            {entry.name}: {entry.value}
          </p>
        ))}
      </div>
    );
  }
  return null;
}

export default function SOCOverview() {
  const [liveData, setLiveData] = useState(null);
  const [feed, setFeed] = useState([]);
  const [anomalies, setAnomalies] = useState([]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [dashRes, feedRes, anomRes] = await Promise.all([
          fetch(`${API_BASE}/api/dashboard/live`),
          fetch(`${API_BASE}/api/threats/feed`),
          fetch(`${API_BASE}/api/ai/anomalies`)
        ]);
        
        const dashData = await dashRes.json();
        const feedData = await feedRes.json();
        const anomData = await anomRes.json();
        
        setLiveData(dashData);
        setFeed(feedData.events.slice(0, 10)); // Top 10 recent
        setAnomalies(anomData.anomalies.slice(0, 3)); // Top 3 anomalies
      } catch (error) {
        console.error("Error fetching live data:", error);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 10000); // Refresh every 10s
    return () => clearInterval(interval);
  }, []);

  if (!liveData) {
    return (
      <div className="loading-overlay" style={{ position: "relative", height: "100%", background: "transparent" }}>
        <div className="loading-spinner"></div>
      </div>
    );
  }


  return (
    <div className="animate-fade-in">
      <div className="page-header">
        <div>
          <h1 className="page-title">SOC Overview</h1>
          <div className="page-subtitle">Real-time network security operations and metrics</div>
        </div>
      </div>

      <div className="stats-grid delay-1">
        <div className={`stat-card ${liveData.threatLevel}`}>
          <div className="stat-header">
            <span className="stat-title">Active Threats</span>
            <span className="stat-icon">⚠️</span>
          </div>
          <div className={`stat-value ${liveData.threatLevel}`}>
            <CountUp end={liveData.activeThreats} duration={2} preserveValue={true} />
          </div>
          <div className="stat-footer">Live active malicious events</div>
        </div>

        <div className="stat-card safe">
          <div className="stat-header">
            <span className="stat-title">Devices Online</span>
            <span className="stat-icon">🔌</span>
          </div>
          <div className="stat-value safe">
            <CountUp end={liveData.devicesOnline} duration={2} preserveValue={true} />
            <span style={{ fontSize: "1rem", color: "var(--text-muted)", marginLeft: "4px" }}>/ {liveData.totalDevices}</span>
          </div>
          <div className="stat-footer">Connected IoT endpoints</div>
        </div>

        <div className="stat-card high">
          <div className="stat-header">
            <span className="stat-title">AI Anomalies</span>
            <span className="stat-icon">🧠</span>
          </div>
          <div className="stat-value high">
            <CountUp end={liveData.anomalies} duration={2} preserveValue={true} />
          </div>
          <div className="stat-footer">Unusual patterns detected</div>
        </div>

        <div className="stat-card info">
          <div className="stat-header">
            <span className="stat-title">Network Bandwidth</span>
            <span className="stat-icon">📈</span>
          </div>
          <div className="stat-value info">
            <CountUp end={liveData.bandwidth} duration={2} decimals={1} preserveValue={true} />
            <span style={{ fontSize: "1rem", color: "var(--text-muted)", marginLeft: "4px" }}>Mbps</span>
          </div>
          <div className="stat-footer">Current throughput</div>
        </div>
      </div>

      <div className="charts-grid delay-2">
        <div className="chart-card full-width">
          <div className="chart-header">
            <div className="chart-title">Threat vs Normal Traffic (24h)</div>
          </div>
          <div style={{ height: 300 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={liveData.trend}>
                <defs>
                  <linearGradient id="colorThreat" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={COLORS.critical} stopOpacity={0.8}/>
                    <stop offset="95%" stopColor={COLORS.critical} stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorNormal" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={COLORS.low} stopOpacity={0.8}/>
                    <stop offset="95%" stopColor={COLORS.low} stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="hour" />
                <YAxis />
                <Tooltip content={<CustomTooltip />} />
                <Area type="monotone" dataKey="threats" stroke={COLORS.critical} fillOpacity={1} fill="url(#colorThreat)" name="Threats" />
                <Area type="monotone" dataKey="normal" stroke={COLORS.low} fillOpacity={1} fill="url(#colorNormal)" name="Normal" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="chart-card delay-3">
          <div className="chart-header">
            <div className="chart-title">Live Threat Feed</div>
            <span className="topbar-badge badge-critical" style={{ fontSize: "0.6rem" }}>Live</span>
          </div>
          <div className="feed-list matrix-bg" style={{ padding: "10px" }}>
            {feed.map((event, i) => (
              <div className="feed-item premium-card" key={event.id} style={{ animationDelay: `${i * 0.1}s` }}>
                <div className={`device-status ${event.severity === 'critical' ? 'warning' : 'online'}`} style={{ 
                  background: COLORS[event.severity], 
                  boxShadow: `0 0 8px ${COLORS[event.severity]}` 
                }}></div>
                <div className="feed-content">
                  <div className="feed-title">{event.attackType}</div>
                  <div className="feed-meta">
                    <span>Target: {event.targetDevice}</span>
                    <span>Src: {event.sourceIP}</span>
                  </div>
                </div>
                <div className="feed-time">
                  {event.timestamp.split('T')[1].replace('Z', '')}
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="chart-card delay-4">
          <div className="chart-header">
            <div className="chart-title">AI Anomalies Detected</div>
          </div>
          <div className="feed-list">
            {anomalies.map((anom, i) => (
              <div className="anomaly-card" key={anom.id} style={{ marginBottom: "8px" }}>
                <div className="anomaly-header">
                  <div className="anomaly-title">{anom.device}</div>
                  <div className="anomaly-score">{(anom.score * 100).toFixed(1)}% Score</div>
                </div>
                <div className="anomaly-desc">{anom.description}</div>
                <div className="anomaly-meta">
                  <span>Metric: {anom.metric}</span>
                  <span style={{ marginLeft: "auto" }}>{anom.timestamp.split('T')[1].replace('Z', '')}</span>
                </div>
              </div>
            ))}
            {anomalies.length === 0 && <div className="feed-item">No active anomalies</div>}
          </div>
        </div>

        <div className="chart-card full-width delay-5">
          <div className="chart-header">
            <div className="chart-title">Top Attacking IPs</div>
          </div>
          <div className="data-table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Source IP</th>
                  <th>Country</th>
                  <th>Attacks Count</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {liveData.topIPs.map((ip, index) => (
                  <tr key={index}>
                    <td style={{ fontFamily: "var(--font-mono)", color: "var(--accent-cyan)" }}>{ip.ip}</td>
                    <td>{ip.country}</td>
                    <td>{ip.attacks}</td>
                    <td>
                      <span className={`topbar-badge badge-${ip.severity}`} style={{ display: "inline-block", padding: "2px 8px" }}>
                        {ip.severity}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
