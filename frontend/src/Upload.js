import { useState, useRef, useCallback } from "react";
import axios from "axios";
import { API_BASE } from "./apiConfig";

export default function Upload({ onData, loading, setLoading }) {
  const [file, setFile] = useState(null);
  const [dragging, setDragging] = useState(false);
  const fileInputRef = useRef(null);

  const handleFile = useCallback((f) => {
    if (f && f.name.endsWith(".csv")) {
      setFile(f);
    }
  }, []);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setDragging(false);
    const f = e.dataTransfer.files[0];
    handleFile(f);
  }, [handleFile]);

  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    setDragging(true);
  }, []);

  const handleDragLeave = useCallback(() => {
    setDragging(false);
  }, []);

  const handleUpload = async () => {
    if (!file) return;
    setLoading(true);
    const formData = new FormData();
    formData.append("file", file);
    try {
      const res = await axios.post(`${API_BASE}/upload`, formData);
      if (res.data.error) {
        alert("Server error: " + res.data.error);
      } else {
        onData(res.data);
      }
    } catch (err) {
      console.error("Upload error:", err);
      alert("Failed to upload. Make sure the Flask server is running on port 5000.");
    } finally {
      setLoading(false);
    }
  };

  const zoneClasses = [
    "upload-zone",
    dragging ? "dragging" : "",
    file ? "has-file" : "",
  ].filter(Boolean).join(" ");

  return (
    <section className="upload-section">
      <div
        id="upload-zone"
        className={zoneClasses}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onClick={() => fileInputRef.current?.click()}
      >
        <div className="upload-icon">
          {file ? "📄" : "☁️"}
        </div>

        {file ? (
          <>
            <div className="upload-file-info">
              ✓ {file.name} ({(file.size / 1024).toFixed(1)} KB)
            </div>
            <div className="upload-title">File ready for analysis</div>
            <div className="upload-subtitle">Click "Analyze" below or drop a different file</div>
          </>
        ) : (
          <>
            <div className="upload-title">Drop your IoT dataset here</div>
            <div className="upload-subtitle">
              Drag & drop a CSV file, or click to browse
            </div>
            <button
              className="upload-browse-btn"
              onClick={(e) => {
                e.stopPropagation();
                fileInputRef.current?.click();
              }}
            >
              📁 Browse Files
            </button>
          </>
        )}

        <input
          ref={fileInputRef}
          type="file"
          accept=".csv"
          className="upload-hidden-input"
          onChange={(e) => handleFile(e.target.files[0])}
        />
      </div>

      {file && (
        <div className="upload-actions" style={{ textAlign: "center" }}>
          <button
            id="btn-analyze"
            className={`btn-analyze ${loading ? "loading" : ""}`}
            onClick={handleUpload}
            disabled={loading}
          >
            {loading ? (
              <>
                <span className="spinner"></span>
                Analyzing…
              </>
            ) : (
              <>🔍 Analyze Network Data</>
            )}
          </button>
        </div>
      )}
    </section>
  );
}