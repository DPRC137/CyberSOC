import React, { useState, useEffect } from "react";
import { BrowserRouter as Router, Routes, Route, NavLink, useLocation } from "react-router-dom";
import "./App.css";
import "./soc-theme.css";

// Components
import SOCOverview from "./SOCOverview";
import ThreatIntel from "./ThreatIntel";
import DeviceManager from "./DeviceManager";
import AlertCenter from "./AlertCenter";
import Upload from "./Upload";
import Dashboard from "./Dashboard";
import HybridAnalytics from "./HybridAnalytics";

function Sidebar() {
  return (
    <div className="sidebar">
      <div className="sidebar-header">
        <div className="sidebar-logo">🛡️</div>
        <div className="sidebar-title">CyberSOC</div>
      </div>
      <nav className="sidebar-nav">
        <NavLink to="/" className={({ isActive }) => (isActive ? "nav-item active" : "nav-item")} end>
          <span className="nav-icon">📊</span> SOC Overview
        </NavLink>
        <NavLink to="/hybrid" className={({ isActive }) => (isActive ? "nav-item active" : "nav-item")}>
          <span className="nav-icon">🧠</span> Hybrid Engine
        </NavLink>
        <NavLink to="/threats" className={({ isActive }) => (isActive ? "nav-item active" : "nav-item")}>
          <span className="nav-icon">🌍</span> Threat Intel
        </NavLink>
        <NavLink to="/devices" className={({ isActive }) => (isActive ? "nav-item active" : "nav-item")}>
          <span className="nav-icon">🖥️</span> Devices
        </NavLink>
        <NavLink to="/alerts" className={({ isActive }) => (isActive ? "nav-item active" : "nav-item")}>
          <span className="nav-icon">🚨</span> Alerts
        </NavLink>
        <NavLink to="/analytics" className={({ isActive }) => (isActive ? "nav-item active" : "nav-item")}>
          <span className="nav-icon">📁</span> CSV Analytics
        </NavLink>
      </nav>
    </div>
  );
}

function Topbar() {
  const [time, setTime] = useState(new Date());
  const location = useLocation();

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const getPageTitle = () => {
    switch (location.pathname) {
      case "/": return "SOC Command Center";
      case "/hybrid": return "Bayesian-Markov Hybrid Threat Engine";
      case "/threats": return "Global Threat Intelligence";
      case "/devices": return "IoT Device Management";
      case "/alerts": return "Security Alerts Log";
      case "/analytics": return "Historical CSV Analysis";
      default: return "CyberSOC";
    }
  };

  return (
    <div className="topbar">
      <div className="topbar-left">
        <h2 style={{ fontSize: "1.1rem", fontWeight: "600" }}>{getPageTitle()}</h2>
      </div>
      <div className="topbar-right">
        <div className="topbar-badge badge-safe">
          <div className="live-indicator safe"></div> System Stable
        </div>
        <div className="topbar-clock">
          ⏱️ {time.toISOString().split("T")[1].split(".")[0]} UTC
        </div>
      </div>
    </div>
  );
}

function MainApp() {
  const [csvData, setCsvData] = useState(null);
  const [loading, setLoading] = useState(false);

  return (
    <Router>
      <div className="particles-container">
        <div className="particle"></div>
        <div className="particle"></div>
        <div className="particle"></div>
        <div className="particle"></div>
        <div className="particle"></div>
      </div>
      <div className="app-container">
        <Sidebar />
        <div className="main-content">
          <Topbar />
          <div className="page-container">
            <Routes>
              <Route path="/" element={<SOCOverview />} />
              <Route path="/hybrid" element={<HybridAnalytics />} />
              <Route path="/threats" element={<ThreatIntel />} />
              <Route path="/devices" element={<DeviceManager />} />
              <Route path="/alerts" element={<AlertCenter />} />
              <Route path="/analytics" element={
                <div>
                  <div className="page-header">
                    <div>
                      <h1 className="page-title">Historical CSV Analysis</h1>
                      <div className="page-subtitle">Upload packet capture data for deep historical analysis</div>
                    </div>
                  </div>
                  {!csvData && (
                    <Upload onData={setCsvData} loading={loading} setLoading={setLoading} />
                  )}
                  {loading && (
                    <div className="loading-overlay">
                      <div className="loading-spinner"></div>
                    </div>
                  )}
                  {csvData && <Dashboard data={csvData} onReset={() => setCsvData(null)} />}
                </div>
              } />
            </Routes>
          </div>
        </div>
      </div>
    </Router>
  );
}

export default MainApp;
