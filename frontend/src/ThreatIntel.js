import React, { useState, useEffect } from "react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { API_BASE } from "./apiConfig";

const COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

function CustomTooltip({ active, payload, label }) {
  if (active && payload && payload.length) {
    return (
      <div className="custom-tooltip">
        <p className="label">{label}</p>
        <p className="item" style={{ color: payload[0].color || payload[0].fill }}>
          {payload[0].name}: {payload[0].value}
        </p>
      </div>
    );
  }
  return null;
}

export default function ThreatIntel() {
  const [geoData, setGeoData] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchGeo = async () => {
      try {
        const res = await fetch(`${API_BASE}/api/geo/threats`);
        const data = await res.json();
        setGeoData(data.sources);
        setLoading(false);
      } catch (error) {
        console.error("Error fetching geo threats:", error);
        setLoading(false);
      }
    };

    fetchGeo();
    const interval = setInterval(fetchGeo, 15000); // refresh every 15s
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="loading-overlay" style={{ position: "relative", height: "100%", background: "transparent" }}>
        <div className="loading-spinner"></div>
      </div>
    );
  }

  // Generate data for top countries chart
  const chartData = geoData.slice(0, 10).map(d => ({
    name: d.country,
    attacks: d.attacks,
    severity: d.severity
  }));

  // Simple SVG World Map projection points (simulated lat/lng to x/y for demo)
  // Real app would use d3-geo or similar
  const getMapCoords = (lat, lng) => {
    // Very rough equirectangular projection for SVG viewBox 0 0 800 400
    const x = (lng + 180) * (800 / 360);
    const y = (90 - lat) * (400 / 180);
    return { x, y };
  };

  return (
    <div className="animate-fade-in">
      <div className="page-header">
        <div>
          <h1 className="page-title">Global Threat Intelligence</h1>
          <div className="page-subtitle">Real-time geographical origin of detected malicious activity</div>
        </div>
      </div>

      <div className="chart-card full-width delay-1" style={{ marginBottom: "var(--space-xl)", padding: 0, overflow: "hidden" }}>
        <div className="chart-header" style={{ padding: "var(--space-lg) var(--space-lg) 0" }}>
          <div className="chart-title">Live Threat Map</div>
        </div>
        
        {/* Simple inline SVG Map with Radar Animation */}
        <div className="radar-container" style={{ position: "relative", width: "100%", height: "400px", background: "var(--bg-primary)", overflow: "hidden" }}>
          {/* 3D Perspective Grid */}
          <div style={{
            position: "absolute", bottom: "-50%", left: "-50%", width: "200%", height: "200%",
            background: "linear-gradient(transparent 65%, rgba(6, 182, 212, 0.2) 66%, transparent 67%), linear-gradient(90deg, transparent 65%, rgba(6, 182, 212, 0.2) 66%, transparent 67%)",
            backgroundSize: "60px 60px",
            transform: "perspective(500px) rotateX(60deg)",
            transformOrigin: "center center",
            zIndex: 0
          }}></div>
          
          <div className="radar-sweep" style={{ zIndex: 1 }}></div>

          {/* Render threat markers */}
          {geoData.map((point, idx) => {
            const coords = getMapCoords(point.lat, point.lng);
            return (
              <div
                key={idx}
                style={{
                  position: "absolute",
                  left: `${(coords.x / 800) * 100}%`,
                  top: `${(coords.y / 400) * 100}%`,
                  transform: "translate(-50%, -50%)",
                }}
                title={`${point.country}: ${point.attacks} attacks`}
              >
                <div style={{
                  width: point.attacks > 30 ? "16px" : "10px",
                  height: point.attacks > 30 ? "16px" : "10px",
                  backgroundColor: COLORS[point.severity],
                  borderRadius: "50%",
                  boxShadow: `0 0 15px ${COLORS[point.severity]}`
                }}></div>
                {/* Pulse effect */}
                <div style={{
                  position: "absolute",
                  top: "50%", left: "50%",
                  width: "100%", height: "100%",
                  backgroundColor: COLORS[point.severity],
                  borderRadius: "50%",
                  transform: "translate(-50%, -50%)",
                  animation: "pulseRing 2s infinite",
                  animationDelay: `${idx * 0.2}s`
                }}></div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="charts-grid delay-2">
        <div className="chart-card">
          <div className="chart-header">
            <div className="chart-title">Top Attack Origins</div>
          </div>
          <div style={{ height: 300 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} layout="vertical" margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" horizontal={false} />
                <XAxis type="number" />
                <YAxis dataKey="name" type="category" width={80} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="attacks" radius={[0, 4, 4, 0]}>
                  {chartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[entry.severity]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="chart-card">
          <div className="chart-header">
            <div className="chart-title">Geographical Threat Feed</div>
          </div>
          <div className="data-table-container" style={{ maxHeight: "300px", overflowY: "auto" }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Country</th>
                  <th>Primary Attack Vector</th>
                  <th>Event Count</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {geoData.map((d, i) => (
                  <tr key={i}>
                    <td><strong>{d.country}</strong></td>
                    <td style={{ color: "var(--text-secondary)" }}>{d.topAttack}</td>
                    <td style={{ fontFamily: "var(--font-mono)" }}>{d.attacks}</td>
                    <td>
                      <span className={`topbar-badge badge-${d.severity}`} style={{ display: "inline-block", padding: "2px 8px" }}>
                        {d.severity}
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
