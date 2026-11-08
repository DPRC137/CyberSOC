import React, { useState, useEffect } from "react";
import { API_BASE } from "./apiConfig";

export default function AlertCenter() {
  const [alertsData, setAlertsData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState("all");

  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        const res = await fetch(`${API_BASE}/api/alerts`);
        const data = await res.json();
        setAlertsData(data);
        setLoading(false);
      } catch (error) {
        console.error("Error fetching alerts:", error);
        setLoading(false);
      }
    };

    fetchAlerts();
    const interval = setInterval(fetchAlerts, 20000); // refresh every 20s
    return () => clearInterval(interval);
  }, []);

  if (loading || !alertsData) {
    return (
      <div className="loading-overlay" style={{ position: "relative", height: "100%", background: "transparent" }}>
        <div className="loading-spinner"></div>
      </div>
    );
  }

  const { alerts, summary, total } = alertsData;

  const filteredAlerts = alerts.filter(a => {
    if (filterSeverity === "all") return true;
    return a.severity === filterSeverity;
  });

  const handleAction = async (id, action) => {
    try {
      const res = await fetch(`${API_BASE}/api/alerts/${id}/status`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: action })
      });
      const result = await res.json();
      if (result.success) {
        // Update local state to reflect change immediately
        setAlertsData(prev => ({
          ...prev,
          alerts: prev.alerts.map(a => a.id === id ? { ...a, status: action } : a)
        }));
      } else {
        alert("Failed to update status: " + result.error);
      }
    } catch (err) {
      console.error("Error updating status:", err);
      alert("Failed to update status due to network error.");
    }
  };

  return (
    <div className="animate-fade-in">
      <div className="page-header">
        <div>
          <h1 className="page-title">Alert Center</h1>
          <div className="page-subtitle">Manage and investigate Bayesian-Markov hybrid security alerts</div>
        </div>
      </div>

      <div className="stats-grid delay-1">
        <div className="stat-card critical" style={{ cursor: "pointer" }} onClick={() => setFilterSeverity(filterSeverity === 'critical' ? 'all' : 'critical')}>
          <div className="stat-header">
            <span className="stat-title">Critical</span>
          </div>
          <div className="stat-value critical">{summary.critical || 0}</div>
          <div className="stat-footer">Requires immediate action</div>
        </div>
        
        <div className="stat-card high" style={{ cursor: "pointer" }} onClick={() => setFilterSeverity(filterSeverity === 'high' ? 'all' : 'high')}>
          <div className="stat-header">
            <span className="stat-title">High</span>
          </div>
          <div className="stat-value high">{summary.high || 0}</div>
          <div className="stat-footer">Elevated risk events</div>
        </div>
        
        <div className="stat-card medium" style={{ cursor: "pointer" }} onClick={() => setFilterSeverity(filterSeverity === 'medium' ? 'all' : 'medium')}>
          <div className="stat-header">
            <span className="stat-title">Medium</span>
          </div>
          <div className="stat-value" style={{ color: "var(--severity-medium)" }}>{summary.medium || 0}</div>
          <div className="stat-footer">Warning indicators</div>
        </div>
        
        <div className="stat-card low" style={{ cursor: "pointer" }} onClick={() => setFilterSeverity(filterSeverity === 'low' ? 'all' : 'low')}>
          <div className="stat-header">
            <span className="stat-title">Low</span>
          </div>
          <div className="stat-value safe">{summary.low || 0}</div>
          <div className="stat-footer">Informational events</div>
        </div>
      </div>

      <div className="chart-card full-width delay-2">
        <div className="chart-header">
          <div className="chart-title">
            Recent Alerts {filterSeverity !== 'all' ? `(Filtered: ${filterSeverity})` : `(${total} Total)`}
          </div>
          {filterSeverity !== 'all' && (
            <button className="btn btn-outline" style={{ padding: "4px 12px", fontSize: "0.8rem" }} onClick={() => setFilterSeverity('all')}>
              Clear Filter
            </button>
          )}
        </div>
        
        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Severity</th>
                <th>Alert ID</th>
                <th>Source IP</th>
                <th>Target Device</th>
                <th>Attack Type</th>
                <th>Risk Metrics</th>
                <th>Description</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.map(alert => {
                const sIp = alert.source_ip || alert.sourceIP || "0.0.0.0";
                const atk = alert.attack_type || alert.attackType || "Anomaly";
                const hybridRisk = alert.hybrid_risk != null ? (alert.hybrid_risk * 100).toFixed(0) + "%" : null;
                const bayesProb = alert.bayesian_prob != null ? (alert.bayesian_prob * 100).toFixed(0) + "%" : null;

                return (
                  <tr key={alert.id} style={{ 
                    backgroundColor: alert.severity === 'critical' ? 'rgba(239, 68, 68, 0.05)' : 'transparent',
                    borderLeft: `2px solid var(--severity-${alert.severity})`
                  }}>
                    <td style={{ whiteSpace: "nowrap" }}>
                      {alert.timestamp ? (alert.timestamp.includes('T') ? alert.timestamp.split('T')[1].replace('Z','') : alert.timestamp) : "--:--:--"}
                    </td>
                    <td>
                      <span className={`topbar-badge badge-${alert.severity} ${alert.severity === 'critical' ? 'glitch-text' : ''}`} style={{ display: "inline-block", padding: "2px 8px", fontSize: "0.7rem" }}>
                        {alert.severity}
                      </span>
                    </td>
                    <td style={{ fontFamily: "var(--font-mono)", fontSize: "0.75rem", color: "var(--text-muted)" }}>{alert.id}</td>
                    <td style={{ fontFamily: "var(--font-mono)", color: "var(--accent-cyan)" }}>{sIp}</td>
                    <td>{alert.device}</td>
                    <td style={{ fontWeight: "500", color: "var(--text-primary)" }}>{atk}</td>
                    <td>
                      {hybridRisk ? (
                        <div style={{ display: "flex", gap: "4px", fontSize: "0.72rem" }}>
                          <span style={{ color: "var(--accent-cyan)", background: "rgba(34,211,238,0.1)", padding: "1px 5px", borderRadius: "3px" }} title="Hybrid Risk">
                            ⚡ {hybridRisk}
                          </span>
                          {bayesProb && (
                            <span style={{ color: "var(--accent-purple)", background: "rgba(167,139,250,0.1)", padding: "1px 5px", borderRadius: "3px" }} title="Bayesian Probability">
                              P(B): {bayesProb}
                            </span>
                          )}
                        </div>
                      ) : (
                        <span style={{ color: "var(--text-muted)", fontSize: "0.75rem" }}>—</span>
                      )}
                    </td>
                    <td style={{ fontSize: "0.8rem", maxWidth: "250px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={alert.description}>
                      {alert.description}
                    </td>
                    <td>
                      <span style={{ 
                        padding: "2px 6px", 
                        borderRadius: "4px", 
                        fontSize: "0.75rem",
                        background: alert.status === 'new' ? 'rgba(59, 130, 246, 0.2)' : 'rgba(255,255,255,0.1)',
                        color: alert.status === 'new' ? 'var(--accent-blue)' : 'var(--text-secondary)'
                      }}>
                        {alert.status}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: "flex", gap: "8px" }}>
                        <button className="btn btn-outline" style={{ padding: "2px 8px", fontSize: "0.7rem" }} onClick={() => handleAction(alert.id, 'investigating')}>Investigate</button>
                        <button className="btn btn-outline" style={{ padding: "2px 8px", fontSize: "0.7rem", borderColor: "rgba(34, 197, 94, 0.3)", color: "var(--severity-low)" }} onClick={() => handleAction(alert.id, 'resolved')}>Resolve</button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          
          {filteredAlerts.length === 0 && (
            <div style={{ textAlign: "center", padding: "var(--space-2xl)", color: "var(--text-muted)" }}>
              No alerts found for the selected severity.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
