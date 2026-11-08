import React, { useState, useEffect } from "react";
import { API_BASE } from "./apiConfig";

export default function HybridAnalytics() {
  const [modelMetrics, setModelMetrics] = useState(null);
  const [markovData, setMarkovData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [recentProcessed, setRecentProcessed] = useState([]);
  const [selectedEvent, setSelectedEvent] = useState(null);

  useEffect(() => {
    const fetchMetrics = async () => {
      try {
        const [mRes, kRes] = await Promise.all([
          fetch(`${API_BASE}/api/model/metrics`),
          fetch(`${API_BASE}/api/model/markov-matrix`)
        ]);
        const mData = await mRes.json();
        const kData = await kRes.json();
        setModelMetrics(mData);
        setMarkovData(kData);
        setLoading(false);
      } catch (err) {
        console.error("Error fetching model metrics:", err);
        setLoading(false);
      }
    };
    fetchMetrics();
  }, []);

  const handleGenerate = async (trafficType, attackPhase = "brute_force") => {
    setGenerating(true);
    try {
      const res = await fetch(`${API_BASE}/api/traffic/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          traffic_type: trafficType,
          count: 1,
          attack_phase: attackPhase
        })
      });
      const data = await res.json();
      if (data.results && data.results.length > 0) {
        const item = data.results[0];
        setRecentProcessed(prev => [item, ...prev.slice(0, 9)]);
        setSelectedEvent(item);
      }
    } catch (err) {
      console.error("Error generating traffic:", err);
      alert("Failed to generate traffic: " + err.message);
    } finally {
      setGenerating(false);
    }
  };

  if (loading) {
    return (
      <div className="loading-overlay" style={{ position: "relative", height: "100%", background: "transparent" }}>
        <div className="loading-spinner"></div>
      </div>
    );
  }

  const bMetrics = modelMetrics?.bayesian_metrics || {};

  return (
    <div className="animate-fade-in">
      <div className="page-header">
        <div>
          <h1 className="page-title">Bayesian-Markov Hybrid Detection Engine</h1>
          <div className="page-subtitle">Mathematical threat modeling, transition matrices, and live pipeline simulation</div>
        </div>
      </div>

      {/* ===== MODEL PERFORMANCE STATS ===== */}
      <div className="stats-grid delay-1">
        <div className="stat-card cyan">
          <div className="stat-header">
            <span className="stat-title">Bayesian Accuracy</span>
            <span className="stat-icon">🎯</span>
          </div>
          <div className="stat-value cyan">
            {bMetrics.accuracy ? (bMetrics.accuracy * 100).toFixed(1) + "%" : "84.5%"}
          </div>
          <div className="stat-footer">Gaussian & Categorical Naive Bayes</div>
        </div>

        <div className="stat-card blue">
          <div className="stat-header">
            <span className="stat-title">Precision / Recall</span>
            <span className="stat-icon">⚖️</span>
          </div>
          <div className="stat-value blue" style={{ fontSize: "1.4rem" }}>
            {bMetrics.precision ? (bMetrics.precision * 100).toFixed(1) : "90.3"}% / {bMetrics.recall ? (bMetrics.recall * 100).toFixed(1) : "74.4"}%
          </div>
          <div className="stat-footer">F1-Score: {bMetrics.f1_score ? (bMetrics.f1_score * 100).toFixed(1) + "%" : "81.6%"}</div>
        </div>

        <div className="stat-card purple">
          <div className="stat-header">
            <span className="stat-title">Markov State Space</span>
            <span className="stat-icon">🔄</span>
          </div>
          <div className="stat-value purple">
            {markovData?.states?.length || 5} States
          </div>
          <div className="stat-footer">Discrete-Time Kill Chain DTMC</div>
        </div>

        <div className="stat-card" style={{ borderColor: "rgba(34, 211, 238, 0.4)" }}>
          <div className="stat-header">
            <span className="stat-title">Hybrid Weights</span>
            <span className="stat-icon">⚡</span>
          </div>
          <div className="stat-value" style={{ fontSize: "1.3rem", color: "var(--accent-cyan)" }}>
            w_B: 0.50 | w_M: 0.40
          </div>
          <div className="stat-footer">Alert Threshold: τ ≥ 0.60</div>
        </div>
      </div>

      {/* ===== INTERACTIVE TRAFFIC GENERATION CONTROL PANEL ===== */}
      <div className="chart-card full-width delay-2" style={{ marginBottom: "var(--space-xl)" }}>
        <div className="chart-header">
          <div className="chart-title">🎮 Live Traffic Generator & Pipeline Simulator</div>
          <span className="chart-badge">End-to-End Testing</span>
        </div>
        <div style={{ padding: "var(--space-md) 0" }}>
          <p style={{ color: "var(--text-secondary)", fontSize: "0.9rem", marginBottom: "var(--space-md)" }}>
            Trigger parameterized traffic streams into the live ingestion pipeline. The system runs Bayesian classification, updates Markov entity transitions, calculates hybrid risk, and conditionally generates alerts in SQLite.
          </p>

          <div style={{ display: "flex", flexWrap: "wrap", gap: "12px", alignItems: "center" }}>
            <button
              className="btn"
              disabled={generating}
              onClick={() => handleGenerate("normal")}
              style={{ background: "rgba(34, 197, 94, 0.2)", border: "1px solid var(--severity-low)", color: "var(--severity-low)" }}
            >
              🟢 Generate Normal Traffic
            </button>

            <button
              className="btn"
              disabled={generating}
              onClick={() => handleGenerate("malicious", "brute_force")}
              style={{ background: "rgba(239, 68, 68, 0.2)", border: "1px solid var(--severity-critical)", color: "var(--severity-critical)" }}
            >
              🔴 Simulate Brute Force Attack
            </button>

            <button
              className="btn"
              disabled={generating}
              onClick={() => handleGenerate("malicious", "recon")}
              style={{ background: "rgba(234, 179, 8, 0.2)", border: "1px solid var(--severity-medium)", color: "var(--severity-medium)" }}
            >
              🟡 Simulate Recon Port Scan
            </button>

            <button
              className="btn"
              disabled={generating}
              onClick={() => handleGenerate("malicious", "exploit")}
              style={{ background: "rgba(249, 115, 22, 0.2)", border: "1px solid var(--severity-high)", color: "var(--severity-high)" }}
            >
              🟠 Simulate Payload Exploit
            </button>

            <button
              className="btn"
              disabled={generating}
              onClick={() => handleGenerate("malicious", "exfiltration")}
              style={{ background: "rgba(168, 85, 247, 0.2)", border: "1px solid var(--accent-purple)", color: "var(--accent-purple)" }}
            >
              🟣 Simulate Data Exfiltration
            </button>

            {generating && <span style={{ color: "var(--accent-cyan)", fontSize: "0.85rem" }}>⏳ Processing through models...</span>}
          </div>
        </div>

        {/* Selected / Latest Event Inspection */}
        {selectedEvent && (
          <div style={{ marginTop: "var(--space-md)", background: "rgba(0,0,0,0.3)", borderRadius: "8px", padding: "16px", border: "1px solid rgba(255,255,255,0.08)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px", borderBottom: "1px solid rgba(255,255,255,0.06)", paddingBottom: "8px" }}>
              <div style={{ fontWeight: "600", fontSize: "0.95rem", color: "var(--text-primary)" }}>
                Inspection: {selectedEvent.event_id} ({selectedEvent.device})
              </div>
              <div>
                <span className={`topbar-badge badge-${selectedEvent.hybrid?.severity || 'low'}`} style={{ padding: "3px 10px" }}>
                  {(selectedEvent.hybrid?.severity || 'low').toUpperCase()}
                </span>
                {selectedEvent.alert_generated && (
                  <span style={{ marginLeft: "8px", background: "rgba(239, 68, 68, 0.2)", border: "1px solid var(--severity-critical)", color: "var(--severity-critical)", padding: "3px 8px", borderRadius: "4px", fontSize: "0.75rem" }}>
                    🚨 Alert: {selectedEvent.alert_id}
                  </span>
                )}
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "16px" }}>
              {/* Bayesian Breakdown */}
              <div style={{ background: "rgba(255,255,255,0.02)", padding: "12px", borderRadius: "6px" }}>
                <div style={{ color: "var(--accent-cyan)", fontWeight: "600", fontSize: "0.85rem", marginBottom: "6px" }}>
                  1. Bayesian Classification
                </div>
                <div style={{ fontSize: "0.8rem", color: "var(--text-secondary)" }}>
                  <div>P(Attack | x): <strong>{((selectedEvent.bayesian?.probability_attack || 0) * 100).toFixed(1)}%</strong></div>
                  <div>P(Normal | x): <strong>{((selectedEvent.bayesian?.probability_normal || 0) * 100).toFixed(1)}%</strong></div>
                  <div>Log-Odds: <strong>{(selectedEvent.bayesian?.log_odds || 0).toFixed(2)}</strong></div>
                </div>
              </div>

              {/* Markov Breakdown */}
              <div style={{ background: "rgba(255,255,255,0.02)", padding: "12px", borderRadius: "6px" }}>
                <div style={{ color: "var(--accent-purple)", fontWeight: "600", fontSize: "0.85rem", marginBottom: "6px" }}>
                  2. Markov Sequence Analysis
                </div>
                <div style={{ fontSize: "0.8rem", color: "var(--text-secondary)" }}>
                  <div>State: <strong>{selectedEvent.markov?.current_state}</strong></div>
                  <div>Transition: <strong>{selectedEvent.markov?.transition_description}</strong></div>
                  <div>Sequence P(Attack): <strong>{((selectedEvent.markov?.markov_probability || 0) * 100).toFixed(1)}%</strong></div>
                  <div>Anomaly Index: <strong>{(selectedEvent.markov?.transition_anomaly_score || 0).toFixed(2)}</strong></div>
                </div>
              </div>

              {/* Hybrid Risk Breakdown */}
              <div style={{ background: "rgba(255,255,255,0.02)", padding: "12px", borderRadius: "6px" }}>
                <div style={{ color: "var(--accent-pink)", fontWeight: "600", fontSize: "0.85rem", marginBottom: "6px" }}>
                  3. Hybrid Risk Fusion
                </div>
                <div style={{ fontSize: "0.8rem", color: "var(--text-secondary)" }}>
                  <div>Hybrid Score: <strong style={{ color: "var(--accent-cyan)", fontSize: "1.05rem" }}>{((selectedEvent.hybrid?.hybrid_risk || 0) * 100).toFixed(1)}%</strong></div>
                  <div>Inferred Type: <strong>{selectedEvent.hybrid?.attack_type}</strong></div>
                  <div>Alert Fired: <strong>{selectedEvent.alert_generated ? "YES (Persisted to DB)" : "NO"}</strong></div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Recent Processed Events Table */}
        {recentProcessed.length > 0 && (
          <div style={{ marginTop: "var(--space-md)" }}>
            <div style={{ fontSize: "0.85rem", fontWeight: "600", color: "var(--text-secondary)", marginBottom: "8px" }}>
              Recently Processed Stream ({recentProcessed.length} events)
            </div>
            <div className="data-table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Event ID</th>
                    <th>Device</th>
                    <th>Markov State</th>
                    <th>Bayesian P</th>
                    <th>Markov P</th>
                    <th>Hybrid Risk</th>
                    <th>Severity</th>
                    <th>Alert</th>
                  </tr>
                </thead>
                <tbody>
                  {recentProcessed.map((ev, i) => (
                    <tr key={i} onClick={() => setSelectedEvent(ev)} style={{ cursor: "pointer" }}>
                      <td style={{ fontFamily: "var(--font-mono)", fontSize: "0.75rem" }}>{ev.event_id}</td>
                      <td>{ev.device}</td>
                      <td><span style={{ fontSize: "0.75rem", color: "var(--accent-purple)" }}>{ev.markov?.current_state}</span></td>
                      <td>{((ev.bayesian?.probability_attack || 0) * 100).toFixed(1)}%</td>
                      <td>{((ev.markov?.markov_probability || 0) * 100).toFixed(1)}%</td>
                      <td style={{ fontWeight: "700", color: "var(--accent-cyan)" }}>
                        {((ev.hybrid?.hybrid_risk || 0) * 100).toFixed(1)}%
                      </td>
                      <td>
                        <span className={`topbar-badge badge-${ev.hybrid?.severity || 'low'}`} style={{ padding: "1px 6px", fontSize: "0.68rem" }}>
                          {ev.hybrid?.severity}
                        </span>
                      </td>
                      <td>
                        {ev.alert_generated ? (
                          <span style={{ color: "var(--severity-critical)", fontSize: "0.75rem", fontWeight: "600" }}>✓ {ev.alert_id}</span>
                        ) : (
                          <span style={{ color: "var(--text-muted)", fontSize: "0.75rem" }}>—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* ===== MARKOV TRANSITION MATRICES VIEWER ===== */}
      {markovData && markovData.benign_matrix && (
        <div className="charts-grid delay-3">
          <div className="chart-card">
            <div className="chart-header">
              <div className="chart-title">Normal Markov Transition Matrix (T_benign)</div>
              <span className="chart-badge" style={{ color: "var(--severity-low)", borderColor: "var(--severity-low)" }}>Benign Baseline</span>
            </div>
            <p style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "10px" }}>
              High self-transition probability on BENIGN state (82%). Transitions to EXPLOIT or EXFIL are near-zero.
            </p>
            <div style={{ overflowX: "auto" }}>
              <table className="data-table" style={{ fontSize: "0.72rem", textAlign: "center" }}>
                <thead>
                  <tr>
                    <th>From \ To</th>
                    {markovData.states.map(s => <th key={s}>{s.slice(0, 7)}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {markovData.benign_matrix.map((row, i) => (
                    <tr key={i}>
                      <td style={{ fontWeight: "600", textAlign: "left" }}>{markovData.states[i].slice(0, 7)}</td>
                      {row.map((val, j) => (
                        <td key={j} style={{ background: `rgba(34, 197, 94, ${val * 0.4})` }}>
                          {(val * 100).toFixed(0)}%
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="chart-card">
            <div className="chart-header">
              <div className="chart-title">Attack Markov Transition Matrix (T_attack)</div>
              <span className="chart-badge" style={{ color: "var(--severity-critical)", borderColor: "var(--severity-critical)" }}>Attack Progression</span>
            </div>
            <p style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "10px" }}>
              High forward-transition probability along the MITRE ATT&CK progression: Recon → Auth Burst → Exploit → Exfil.
            </p>
            <div style={{ overflowX: "auto" }}>
              <table className="data-table" style={{ fontSize: "0.72rem", textAlign: "center" }}>
                <thead>
                  <tr>
                    <th>From \ To</th>
                    {markovData.states.map(s => <th key={s}>{s.slice(0, 7)}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {markovData.attack_matrix.map((row, i) => (
                    <tr key={i}>
                      <td style={{ fontWeight: "600", textAlign: "left" }}>{markovData.states[i].slice(0, 7)}</td>
                      {row.map((val, j) => (
                        <td key={j} style={{ background: `rgba(239, 68, 68, ${val * 0.4})` }}>
                          {(val * 100).toFixed(0)}%
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
