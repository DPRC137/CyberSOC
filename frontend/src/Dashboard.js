import {
  PieChart, Pie, Cell,
  BarChart, Bar,
  AreaChart, Area,
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from "recharts";

const COLORS = {
  cyan: "#22d3ee",
  blue: "#3b82f6",
  purple: "#a78bfa",
  pink: "#f472b6",
  green: "#34d399",
  amber: "#fbbf24",
  red: "#f87171",
  orange: "#fb923c",
};

const PIE_COLORS = [COLORS.cyan, COLORS.blue, COLORS.purple, COLORS.pink, COLORS.amber, COLORS.orange];
const RISK_COLORS = { Critical: COLORS.red, High: COLORS.orange, Medium: COLORS.amber, Low: COLORS.green };

/* Custom tooltip */
function CustomTooltip({ active, payload, label }) {
  if (!active || !payload || !payload.length) return null;
  return (
    <div className="custom-tooltip">
      {label && <div className="label">{label}</div>}
      {payload.map((entry, i) => (
        <div key={i} className="value" style={{ color: entry.color || entry.fill }}>
          {entry.name}: <strong>{typeof entry.value === 'number' ? entry.value.toLocaleString() : entry.value}</strong>
          {entry.unit || ''}
        </div>
      ))}
    </div>
  );
}

/* Custom pie label */
function renderPieLabel({ name, percent }) {
  return `${name} ${(percent * 100).toFixed(0)}%`;
}

export default function Dashboard({ data, onReset }) {
  const {
    rows = 0, columns = [], attackCount = 0, normalCount = 0, attackRate = 0,
    unusualTimeCount = 0, protocolChart = [], browserChart = [],
    attackByProtocol = [], failedLoginChart = [],
    packetChart = [], ipStats = {}, sessionStats = {}, riskChart = [], trendData = [], topRisky = [],
    modelMetrics = null,
  } = data || {};

  // Sort risk chart in logical order
  const riskOrder = ['Critical', 'High', 'Medium', 'Low'];
  const sortedRisk = [...(riskChart || [])].sort((a, b) => riskOrder.indexOf(a.name) - riskOrder.indexOf(b.name));

  return (
    <div className="animate-fade-in">
      {/* Reset button */}
      <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: "var(--space-md)" }}>
        <button className="upload-browse-btn" onClick={onReset} id="btn-reset">
          ← Upload New Dataset
        </button>
      </div>

      {/* ===== STATS CARDS ===== */}
      <div className="stats-grid">
        <div className="stat-card cyan delay-1">
          <div className="stat-icon">📊</div>
          <div className="stat-label">Total Sessions</div>
          <div className="stat-value cyan">{rows.toLocaleString()}</div>
          <div className="stat-sub">{columns.length} features analyzed</div>
        </div>

        <div className="stat-card red delay-2">
          <div className="stat-icon">🚨</div>
          <div className="stat-label">Attacks Detected</div>
          <div className="stat-value red">{attackCount.toLocaleString()}</div>
          <div className="stat-sub">{attackRate}% attack rate</div>
        </div>

        <div className="stat-card green delay-3">
          <div className="stat-icon">✅</div>
          <div className="stat-label">Normal Traffic</div>
          <div className="stat-value green">{normalCount.toLocaleString()}</div>
          <div className="stat-sub">{(100 - attackRate).toFixed(1)}% safe</div>
        </div>

        <div className="stat-card amber delay-4">
          <div className="stat-icon">🕐</div>
          <div className="stat-label">Unusual Time Access</div>
          <div className="stat-value amber">{unusualTimeCount.toLocaleString()}</div>
          <div className="stat-sub">{((unusualTimeCount / rows) * 100).toFixed(1)}% of sessions</div>
        </div>

        <div className="stat-card purple delay-5">
          <div className="stat-icon">🌐</div>
          <div className="stat-label">Avg IP Reputation</div>
          <div className="stat-value purple">{ipStats.mean}</div>
          <div className="stat-sub">Range: {ipStats.min} – {ipStats.max}</div>
        </div>

        <div className="stat-card blue delay-6">
          <div className="stat-icon">⏱</div>
          <div className="stat-label">Avg Session Duration</div>
          <div className="stat-value blue">{sessionStats.mean}s</div>
          <div className="stat-sub">Max: {sessionStats.max}s</div>
        </div>
      </div>

      {/* ===== MATHEMATICAL MODEL EVALUATION METRICS ===== */}
      {modelMetrics && modelMetrics.accuracy != null && (
        <div className="chart-card full-width delay-2" style={{ marginBottom: "var(--space-xl)", borderColor: "rgba(34, 211, 238, 0.3)" }}>
          <div className="chart-header">
            <div>
              <div className="chart-title" style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <span>🧠</span> Bayesian-Markov Model Performance Metrics
              </div>
              <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", marginTop: "4px" }}>
                Rigorous mathematical evaluation validated against {modelMetrics.total_samples || rows} dataset instances
              </div>
            </div>
            <span className="chart-badge" style={{ background: "rgba(34, 211, 238, 0.15)", color: "var(--accent-cyan)", border: "1px solid var(--accent-cyan)" }}>
              Mathematical Validation
            </span>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: "var(--space-md)", margin: "var(--space-md) 0" }}>
            <div style={{ background: "rgba(255,255,255,0.03)", padding: "12px", borderRadius: "8px", border: "1px solid rgba(255,255,255,0.05)", textAlign: "center" }}>
              <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase" }}>Accuracy</div>
              <div style={{ fontSize: "1.4rem", fontWeight: "700", color: "var(--accent-cyan)", marginTop: "4px" }}>
                {(modelMetrics.accuracy * 100).toFixed(2)}%
              </div>
            </div>

            <div style={{ background: "rgba(255,255,255,0.03)", padding: "12px", borderRadius: "8px", border: "1px solid rgba(255,255,255,0.05)", textAlign: "center" }}>
              <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase" }}>Precision</div>
              <div style={{ fontSize: "1.4rem", fontWeight: "700", color: "var(--accent-blue)", marginTop: "4px" }}>
                {(modelMetrics.precision * 100).toFixed(2)}%
              </div>
            </div>

            <div style={{ background: "rgba(255,255,255,0.03)", padding: "12px", borderRadius: "8px", border: "1px solid rgba(255,255,255,0.05)", textAlign: "center" }}>
              <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase" }}>Recall</div>
              <div style={{ fontSize: "1.4rem", fontWeight: "700", color: "var(--accent-purple)", marginTop: "4px" }}>
                {(modelMetrics.recall * 100).toFixed(2)}%
              </div>
            </div>

            <div style={{ background: "rgba(255,255,255,0.03)", padding: "12px", borderRadius: "8px", border: "1px solid rgba(255,255,255,0.05)", textAlign: "center" }}>
              <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase" }}>F1-Score</div>
              <div style={{ fontSize: "1.4rem", fontWeight: "700", color: "var(--severity-low)", marginTop: "4px" }}>
                {(modelMetrics.f1_score * 100).toFixed(2)}%
              </div>
            </div>

            <div style={{ background: "rgba(255,255,255,0.03)", padding: "12px", borderRadius: "8px", border: "1px solid rgba(255,255,255,0.05)", textAlign: "center" }}>
              <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase" }}>ROC-AUC</div>
              <div style={{ fontSize: "1.4rem", fontWeight: "700", color: "var(--accent-pink)", marginTop: "4px" }}>
                {(modelMetrics.roc_auc * 100).toFixed(2)}%
              </div>
            </div>
          </div>

          {modelMetrics.confusion_matrix && (
            <div style={{ marginTop: "var(--space-md)", background: "rgba(0,0,0,0.2)", padding: "16px", borderRadius: "8px" }}>
              <div style={{ fontSize: "0.85rem", fontWeight: "600", marginBottom: "10px", color: "var(--text-secondary)" }}>
                Confusion Matrix (Bayesian Posteriors vs Ground Truth)
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px", maxWidth: "420px", margin: "0 auto", textAlign: "center" }}>
                <div style={{ background: "rgba(34, 197, 94, 0.1)", border: "1px solid rgba(34, 197, 94, 0.3)", padding: "10px", borderRadius: "6px" }}>
                  <div style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>True Negatives (TN)</div>
                  <div style={{ fontSize: "1.2rem", fontWeight: "700", color: "var(--severity-low)" }}>{modelMetrics.confusion_matrix.tn}</div>
                </div>
                <div style={{ background: "rgba(239, 68, 68, 0.1)", border: "1px solid rgba(239, 68, 68, 0.3)", padding: "10px", borderRadius: "6px" }}>
                  <div style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>False Positives (FP)</div>
                  <div style={{ fontSize: "1.2rem", fontWeight: "700", color: "var(--severity-critical)" }}>{modelMetrics.confusion_matrix.fp}</div>
                </div>
                <div style={{ background: "rgba(234, 179, 8, 0.1)", border: "1px solid rgba(234, 179, 8, 0.3)", padding: "10px", borderRadius: "6px" }}>
                  <div style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>False Negatives (FN)</div>
                  <div style={{ fontSize: "1.2rem", fontWeight: "700", color: "var(--severity-medium)" }}>{modelMetrics.confusion_matrix.fn}</div>
                </div>
                <div style={{ background: "rgba(34, 211, 238, 0.1)", border: "1px solid rgba(34, 211, 238, 0.3)", padding: "10px", borderRadius: "6px" }}>
                  <div style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>True Positives (TP)</div>
                  <div style={{ fontSize: "1.2rem", fontWeight: "700", color: "var(--accent-cyan)" }}>{modelMetrics.confusion_matrix.tp}</div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ===== DATA COLUMNS ===== */}
      <div className="chart-card delay-3" style={{ marginBottom: "var(--space-xl)" }}>
        <div className="chart-header">
          <div className="chart-title">🧬 Dataset Features</div>
          <span className="chart-badge">{columns.length} columns</span>
        </div>
        <div className="columns-grid">
          {columns.map((col) => (
            <span key={col} className="column-tag">{col}</span>
          ))}
        </div>
      </div>

      {/* ===== SECTION: Attack Trends ===== */}
      <div className="section-heading delay-4">
        <h2>📈 Attack Trends</h2>
        <div className="section-line"></div>
      </div>

      {/* Trend area chart - full width */}
      <div className="charts-grid">
        <div className="chart-card full-width delay-5">
          <div className="chart-header">
            <div className="chart-title">Attack vs Normal Traffic (Batch Trend)</div>
            <span className="chart-badge">Time Series</span>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={trendData}>
              <defs>
                <linearGradient id="gradAttack" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={COLORS.red} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={COLORS.red} stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gradNormal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={COLORS.green} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={COLORS.green} stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="batch" />
              <YAxis />
              <Tooltip content={<CustomTooltip />} />
              <Legend />
              <Area type="monotone" dataKey="attacks" stroke={COLORS.red} fill="url(#gradAttack)" strokeWidth={2} name="Attacks" />
              <Area type="monotone" dataKey="normal" stroke={COLORS.green} fill="url(#gradNormal)" strokeWidth={2} name="Normal" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* ===== SECTION: Distribution Analysis ===== */}
      <div className="section-heading delay-5">
        <h2>🔬 Distribution Analysis</h2>
        <div className="section-line"></div>
      </div>

      <div className="charts-grid">
        {/* Protocol Pie */}
        <div className="chart-card delay-5">
          <div className="chart-header">
            <div className="chart-title">Protocol Distribution</div>
            <span className="chart-badge">Pie</span>
          </div>
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie
                data={protocolChart}
                cx="50%" cy="50%"
                innerRadius={60} outerRadius={100}
                dataKey="value"
                label={renderPieLabel}
                paddingAngle={4}
                strokeWidth={0}
              >
                {protocolChart.map((entry, index) => (
                  <Cell key={index} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Browser Pie */}
        <div className="chart-card delay-6">
          <div className="chart-header">
            <div className="chart-title">Browser Distribution</div>
            <span className="chart-badge">Pie</span>
          </div>
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie
                data={browserChart}
                cx="50%" cy="50%"
                innerRadius={60} outerRadius={100}
                dataKey="value"
                label={renderPieLabel}
                paddingAngle={4}
                strokeWidth={0}
              >
                {browserChart.map((entry, index) => (
                  <Cell key={index} fill={PIE_COLORS[(index + 2) % PIE_COLORS.length]} />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Packet Size Histogram */}
        <div className="chart-card delay-5">
          <div className="chart-header">
            <div className="chart-title">Packet Size Distribution</div>
            <span className="chart-badge">Histogram</span>
          </div>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={packetChart} barSize={36}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="range" />
              <YAxis />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="count" name="Packets" fill={COLORS.cyan} radius={[6, 6, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Attack Rate by Protocol */}
        <div className="chart-card delay-6">
          <div className="chart-header">
            <div className="chart-title">Attack Rate by Protocol (%)</div>
            <span className="chart-badge">Radar</span>
          </div>
          <ResponsiveContainer width="100%" height={280}>
            <RadarChart cx="50%" cy="50%" outerRadius={90} data={attackByProtocol}>
              <PolarGrid stroke="#334155" />
              <PolarAngleAxis dataKey="name" stroke="#94a3b8" />
              <PolarRadiusAxis angle={30} domain={[0, 100]} />
              <Radar name="Attack Rate" dataKey="rate" stroke={COLORS.pink} fill={COLORS.pink} fillOpacity={0.2} strokeWidth={2} />
              <Tooltip content={<CustomTooltip />} />
            </RadarChart>
          </ResponsiveContainer>
        </div>

        {/* Failed Logins */}
        <div className="chart-card delay-7">
          <div className="chart-header">
            <div className="chart-title">🔑 Failed Login Distribution</div>
            <span className="chart-badge">Bar</span>
          </div>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={failedLoginChart} barSize={40}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="logins" label={{ value: "Failed Logins", position: "insideBottom", offset: -5, fill: "#64748b" }} />
              <YAxis />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="count" name="Sessions" fill={COLORS.amber} radius={[8, 8, 0, 0]}>
                {failedLoginChart.map((entry, i) => (
                  <Cell key={i} fill={parseInt(entry.logins) >= 3 ? COLORS.red : parseInt(entry.logins) >= 2 ? COLORS.amber : COLORS.green} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Risk Levels (Hybrid Calibrated) */}
        <div className="chart-card delay-8">
          <div className="chart-header">
            <div className="chart-title">⚠️ Hybrid Risk Level Breakdown</div>
            <span className="chart-badge">Pie</span>
          </div>
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie
                data={sortedRisk}
                cx="50%" cy="50%"
                innerRadius={60} outerRadius={100}
                dataKey="value"
                label={renderPieLabel}
                paddingAngle={4}
                strokeWidth={0}
              >
                {sortedRisk.map((entry) => (
                  <Cell key={entry.name} fill={RISK_COLORS[entry.name] || COLORS.blue} />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* ===== SECTION: Top Risky Sessions Table ===== */}
      <div className="section-heading delay-7">
        <h2>🔥 Top Risky Sessions</h2>
        <div className="section-line"></div>
      </div>

      <div className="chart-card full-width delay-8" style={{ marginBottom: "var(--space-xl)" }}>
        <div className="chart-header">
          <div className="chart-title">Sessions with Highest Failed Logins (Attack Detected)</div>
          <span className="chart-badge">Top 10</span>
        </div>
        <div className="table-container">
          <table className="data-table" id="risky-sessions-table">
            <thead>
              <tr>
                <th>Session ID</th>
                <th>Protocol</th>
                <th>Browser</th>
                <th>Login Attempts</th>
                <th>Failed Logins</th>
                <th>IP Reputation</th>
                <th>Unusual Time</th>
              </tr>
            </thead>
            <tbody>
              {topRisky.map((row, i) => (
                <tr key={i}>
                  <td className="session-id">{row.session_id}</td>
                  <td>
                    <span className="badge badge-safe">{row.protocol_type}</span>
                  </td>
                  <td>{row.browser_type}</td>
                  <td>{row.login_attempts}</td>
                  <td>
                    <span className={`badge ${row.failed_logins >= 4 ? 'badge-danger' : row.failed_logins >= 3 ? 'badge-warn' : 'badge-safe'}`}>
                      {row.failed_logins}
                    </span>
                  </td>
                  <td style={{ color: row.ip_reputation_score < 30 ? COLORS.red : row.ip_reputation_score < 60 ? COLORS.amber : COLORS.green }}>
                    {row.ip_reputation_score.toFixed(1)}
                  </td>
                  <td>
                    {row.unusual_time_access ? (
                      <span className="badge badge-danger">Yes</span>
                    ) : (
                      <span className="badge badge-safe">No</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
