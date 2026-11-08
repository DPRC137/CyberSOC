import React, { useState, useEffect } from "react";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from "recharts";
import { API_BASE } from "./apiConfig";

const COLORS = ["#3b82f6", "#8b5cf6", "#ec4899", "#22d3ee", "#34d399", "#fbbf24"];

function CustomTooltip({ active, payload }) {
  if (active && payload && payload.length) {
    return (
      <div className="custom-tooltip">
        <p className="label">{payload[0].name}</p>
        <p className="item">{payload[0].value} Devices</p>
      </div>
    );
  }
  return null;
}

export default function DeviceManager() {
  const [deviceData, setDeviceData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("all");

  useEffect(() => {
    const fetchDevices = async () => {
      try {
        const res = await fetch(`${API_BASE}/api/devices`);
        const data = await res.json();
        setDeviceData(data);
        setLoading(false);
      } catch (error) {
        console.error("Error fetching devices:", error);
        setLoading(false);
      }
    };

    fetchDevices();
    const interval = setInterval(fetchDevices, 30000); // refresh every 30s
    return () => clearInterval(interval);
  }, []);

  if (loading || !deviceData) {
    return (
      <div className="loading-overlay" style={{ position: "relative", height: "100%", background: "transparent" }}>
        <div className="loading-spinner"></div>
      </div>
    );
  }

  const { devices, summary, typeChart } = deviceData;

  const filteredDevices = devices.filter(d => {
    if (filter === "all") return true;
    if (filter === "online") return d.status === "online";
    if (filter === "offline") return d.status === "offline";
    if (filter === "warning") return d.status === "warning";
    if (filter === "atRisk") return d.riskScore > 60;
    return true;
  });

  return (
    <div className="animate-fade-in">
      <div className="page-header">
        <div>
          <h1 className="page-title">IoT Device Management</h1>
          <div className="page-subtitle">Monitor and manage connected endpoints in the network</div>
        </div>
        <div style={{ display: "flex", gap: "10px" }}>
          <button className={`btn ${filter === 'all' ? '' : 'btn-outline'}`} onClick={() => setFilter('all')}>All ({summary.total})</button>
          <button className={`btn ${filter === 'online' ? '' : 'btn-outline'}`} onClick={() => setFilter('online')} style={{ borderColor: "var(--severity-low)", color: filter === 'online' ? "white" : "var(--severity-low)" }}>Online</button>
          <button className={`btn ${filter === 'warning' ? '' : 'btn-outline'}`} onClick={() => setFilter('warning')} style={{ borderColor: "var(--severity-medium)", color: filter === 'warning' ? "white" : "var(--severity-medium)" }}>Warning</button>
          <button className={`btn ${filter === 'offline' ? '' : 'btn-outline'}`} onClick={() => setFilter('offline')} style={{ borderColor: "var(--text-muted)", color: filter === 'offline' ? "white" : "var(--text-muted)" }}>Offline</button>
          <button className={`btn ${filter === 'atRisk' ? '' : 'btn-outline'}`} onClick={() => setFilter('atRisk')} style={{ borderColor: "var(--severity-critical)", color: filter === 'atRisk' ? "white" : "var(--severity-critical)" }}>At Risk</button>
        </div>
      </div>

      <div className="charts-grid delay-1" style={{ gridTemplateColumns: "1fr 2fr", marginBottom: "var(--space-xl)" }}>
        <div className="chart-card">
          <div className="chart-header">
            <div className="chart-title">Device Types</div>
          </div>
          <div style={{ height: 250 }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={typeChart}
                  cx="50%" cy="50%"
                  innerRadius={60} outerRadius={90}
                  paddingAngle={5}
                  dataKey="value"
                  stroke="none"
                >
                  {typeChart.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="chart-card">
          <div className="chart-header">
            <div className="chart-title">Network Status Summary</div>
          </div>
          <div className="stats-grid" style={{ marginBottom: 0, height: "100%", alignContent: "center" }}>
             <div className="stat-card" style={{ background: "rgba(34, 197, 94, 0.05)", borderColor: "rgba(34, 197, 94, 0.2)" }}>
               <div className="stat-title">Healthy</div>
               <div className="stat-value safe">{summary.online - summary.warning}</div>
             </div>
             <div className="stat-card" style={{ background: "rgba(234, 179, 8, 0.05)", borderColor: "rgba(234, 179, 8, 0.2)" }}>
               <div className="stat-title">Warnings</div>
               <div className="stat-value" style={{ color: "var(--severity-medium)" }}>{summary.warning}</div>
             </div>
             <div className="stat-card" style={{ background: "rgba(239, 68, 68, 0.05)", borderColor: "rgba(239, 68, 68, 0.2)" }}>
               <div className="stat-title">High Risk</div>
               <div className="stat-value critical">{summary.atRisk}</div>
             </div>
             <div className="stat-card" style={{ background: "rgba(148, 163, 184, 0.05)", borderColor: "rgba(148, 163, 184, 0.2)" }}>
               <div className="stat-title">Offline</div>
               <div className="stat-value" style={{ color: "var(--text-muted)" }}>{summary.offline}</div>
             </div>
          </div>
        </div>
      </div>

      <h2 style={{ fontSize: "1.2rem", marginBottom: "var(--space-md)", color: "var(--text-primary)" }}>
        Endpoint Inventory {filter !== 'all' ? `(Filtered: ${filter})` : ''}
      </h2>

      <div className="device-grid delay-2">
        {filteredDevices.map(dev => (
          <div className="device-card" key={dev.id}>
            <div className="device-header">
              <div className="device-icon-name">
                <div className="device-icon">{dev.icon}</div>
                <div>
                  <div className="device-name">{dev.name}</div>
                  <div className="device-type">{dev.type}</div>
                </div>
              </div>
              <div className={`device-status ${dev.status}`} title={dev.status}></div>
            </div>
            
            <div style={{ marginTop: "var(--space-sm)", marginBottom: "var(--space-sm)" }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.8rem", marginBottom: "4px" }}>
                <span style={{ color: "var(--text-muted)" }}>Risk Score</span>
                <span style={{ 
                  color: dev.riskScore > 80 ? "var(--severity-critical)" : dev.riskScore > 60 ? "var(--severity-high)" : dev.riskScore > 30 ? "var(--severity-medium)" : "var(--severity-low)",
                  fontWeight: "bold"
                }}>{dev.riskScore}%</span>
              </div>
              <div style={{ width: "100%", height: "4px", background: "rgba(255,255,255,0.1)", borderRadius: "2px" }}>
                <div style={{ 
                  width: `${dev.riskScore}%`, 
                  height: "100%", 
                  borderRadius: "2px",
                  background: dev.riskScore > 80 ? "var(--severity-critical)" : dev.riskScore > 60 ? "var(--severity-high)" : dev.riskScore > 30 ? "var(--severity-medium)" : "var(--severity-low)"
                }}></div>
              </div>
            </div>

            <div className="device-details">
              <span>{dev.ip}</span>
              <span>{dev.mac}</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "4px" }}>
              <span>FW: {dev.firmware}</span>
              <span>Seen: {dev.lastSeen.split('T')[1].replace('Z','')}</span>
            </div>
          </div>
        ))}
      </div>
      
      {filteredDevices.length === 0 && (
        <div style={{ textAlign: "center", padding: "var(--space-3xl)", color: "var(--text-muted)" }}>
          No devices found matching the current filter.
        </div>
      )}
    </div>
  );
}
