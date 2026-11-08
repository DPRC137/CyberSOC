// Automatic dynamic API base URL detection for local development and Vercel production
export const API_BASE = 
  process.env.REACT_APP_API_URL !== undefined 
    ? process.env.REACT_APP_API_URL 
    : (typeof window !== "undefined" && (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1") && window.location.port === "3000")
      ? "http://127.0.0.1:5000"
      : "";
