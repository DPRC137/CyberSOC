# 🛡️ CyberSOC: AI-Powered IoT Security Command Center
### Bayesian-Markov Hybrid Threat Detection System

An enterprise-grade, full-stack Security Operations Center (SOC) dashboard designed to monitor, detect, analyze, and mitigate cyber threats across IoT device networks using a mathematically grounded **Bayesian-Markov Hybrid Threat Detection Architecture**.

---

## 🧠 System Architecture & Mathematical Foundations

Traditional Intrusion Detection Systems (IDS) either rely strictly on static feature classification (which ignores the multi-step temporal progression of modern attack campaigns) or purely on transition models (which miss granular packet-level feature anomalies). **CyberSOC** resolves this trade-off by combining:

1. **Gaussian & Categorical Naive Bayes Classifier**:
   - Computes exact class posteriors $P(\text{Attack} \mid \mathbf{x})$ and $P(\text{Normal} \mid \mathbf{x})$ across continuous features (packet size, session duration, IP threat scores, login attempts) and discrete categorical features (protocol, encryption, browser, failed logins).
   - Provides explainable log-odds feature evidence: $\ln \frac{P(x_i \mid \text{Attack})}{P(x_i \mid \text{Normal})}$.
   - Evaluated on $9,537$ IoT intrusion records, achieving **84.6% Accuracy**, **90.3% Precision**, **74.4% Recall**, and **88.0% ROC-AUC**.

2. **Discrete-Time Markov Chain (DTMC) Sequence Analyzer**:
   - Models temporal attack progression across a 5-state security lifecycle:
     - $s_0$: `BENIGN_TELEMETRY`
     - $s_1$: `RECON_PROBE`
     - $s_2$: `CREDENTIAL_STRESS`
     - $s_3$: `EXPLOITATION`
     - $s_4$: `EXFIL_IMPACT`
   - Computes sequence log-likelihood ratios $\mathcal{L}(\mathbf{S}) = \sum_{t=2}^L \ln \frac{T_{\text{attack}}(s_{t-1}, s_t)}{T_{\text{benign}}(s_{t-1}, s_t)}$ and sigmoidal sequence attack probability $P_{\text{Markov}} = \frac{1}{1 + e^{-\mathcal{L}(\mathbf{S})}}$.

3. **Hybrid Risk Engine**:
   - Dynamically fuses spatial Bayesian probability and temporal Markov probability:
     $$R_{\text{Hybrid}} = w_B \cdot P_{\text{Bayes}} + w_M \cdot P_{\text{Markov}} + \Delta_{\text{context}}$$
     where $w_B = 0.50$, $w_M = 0.40$, and $\Delta_{\text{context}}$ applies calibrated adjustments for IP reputation and temporal anomalies.
   - Categorizes threats into severity tiers: **Critical** ($\ge 0.80$), **High** ($0.60 - 0.80$), **Medium** ($0.35 - 0.60$), and **Low** ($< 0.35$).
   - Automatically generates and persists security alerts in SQLite when $R_{\text{Hybrid}} \ge 0.60$.

---

## ✨ Key Features

1. **SOC Overview Hub**: Real-time operational metrics showing active threats, network bandwidth, connected devices, and 24-hour threat vs. normal traffic trends.
2. **Hybrid Detection Engine View**: Interactive live traffic generator, real-time event inspector, Bayesian feature evidence breakdown, and Markov 5x5 transition matrix visualizer.
3. **Global Threat Intel**: 3D isometric map featuring a rotating radar sweep plotting geographic attack origins and severity.
4. **IoT Device Management**: Endpoint inventory tracker displaying live device statuses, risk score progress bars, and filtering (Online, Offline, Warning, At Risk).
5. **Interactive Alert Center**: Triage queue where analysts investigate or resolve alerts, with state persisting across application restarts in local SQLite (`cyber_soc.db`).
6. **CSV Analytics Engine**: Upload network capture datasets (e.g., `intrusion_data.csv`) to run Bayesian-Markov model evaluation, confusion matrix generation, protocol distributions, and risk profiling.

---

## 🛠️ Technology Stack

- **Backend**: Python 3.9+, Flask (RESTful API), Pandas, NumPy, Scikit-learn, SQLite3.
- **Frontend**: React.js 19, React Router v7, Recharts, React-CountUp, Glassmorphism CSS.
- **Testing**: PyTest automated test suite with 100% pass rate across 19 unit & integration tests.

---

## 🚀 Linux Setup & Startup Instructions

### Prerequisites
- Python 3.9+ (`python3`, `pip`)
- Node.js 18+ and npm

### Quick Start (Linux)
Run the automated startup script:
```bash
./start_all.sh
```
This script will automatically:
1. Verify Python 3 and Node.js runtime environments.
2. Install Python dependencies from `requirements.txt`.
3. Non-destructively initialize the persistent SQLite database (`init_db.py`).
4. Execute the test suite (`pytest`) to ensure mathematical integrity.
5. Launch the Flask backend at `http://127.0.0.1:5000`.
6. Launch the React frontend at `http://localhost:3000`.

### Manual Step-by-Step (Linux)

**1. Install Dependencies**
```bash
pip install -r requirements.txt
cd frontend && npm install && cd ..
```

**2. Initialize Database**
```bash
python3 init_db.py
```

**3. Run Verification Test Suite**
```bash
pytest -v
```

**4. Start Backend Server**
```bash
python3 app.py
```

**5. Start Frontend Client**
```bash
cd frontend
npm start
```

---

## 🪟 Windows Setup & Startup Instructions

1. Double-click `start_all.bat` in the project root, or execute:
```cmd
start_all.bat
```

---

## 🧪 End-to-End Demonstration

To run the complete 10-step autonomous demonstration verifying traffic generation, event processing, Bayesian classification, Markov analysis, hybrid risk calculation, alert generation, dashboard updates, and restart persistence:

```bash
python3 demo_e2e.py
```

### Demonstration Steps:
1. **Generate normal network traffic**: Simulates benign IoT communications (telemetry, 0 failed logins).
2. **Generate malicious network traffic**: Simulates multi-stage attack (Recon $\to$ Brute Force $\to$ Exploit).
3. **Process events**: Ingests traffic into `DetectionPipeline`.
4. **Run Bayesian classification**: Computes exact posteriors and feature evidence.
5. **Run Markov sequence analysis**: Tracks endpoint transitions and sequence probabilities.
6. **Calculate hybrid risk**: Fuses Bayesian and Markov models into calibrated risk scores.
7. **Generate alerts**: Fires alerts for risk $\ge 0.60$ and stores in SQLite.
8. **Display results in dashboard**: Validates live metrics and threat feeds.
9. **Restart application**: Shuts down pipeline and re-instantiates clean instance.
10. **Confirm persisted data**: Verifies all alerts and historical events remain intact.

---

## 📡 RESTful API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/dashboard/live` | Live dashboard metrics, 24h trend, and top attacking IPs |
| `GET` | `/api/threats/feed` | Real-time threat feed with Bayesian, Markov, and Hybrid scores |
| `GET` | `/api/devices` | IoT device inventory with dynamically computed risk levels |
| `GET` | `/api/ai/anomalies` | Detected anomalies from the Bayesian-Markov hybrid engine |
| `GET` | `/api/geo/threats` | Global attack origins and geographic intensity |
| `GET` | `/api/alerts` | Persistent security alerts query with severity breakdown |
| `PUT` | `/api/alerts/<id>/status` | Update alert triage status (`new`, `investigating`, `resolved`) |
| `POST` | `/api/traffic/generate` | Generate parameterized normal or malicious traffic batches |
| `POST` | `/api/traffic/process` | Ingest and evaluate external raw network events |
| `GET` | `/api/model/metrics` | Model evaluation metrics (Accuracy, Precision, Recall, F1, ROC-AUC) |
| `GET` | `/api/model/markov-matrix` | 5x5 transition matrices for benign and attack states |
| `POST` | `/upload` | Forensic ingestion and deep Bayesian-Markov analysis of CSV logs |
