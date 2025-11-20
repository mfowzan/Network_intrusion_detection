import React, { useState, useRef } from "react";
import "./App.css";
import Papa from "papaparse";
import { Line } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
} from "chart.js";

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement);

function App() {
  const [tab, setTab] = useState("live");

  // ========== Templates for all fields ==========
  const TEMPLATES = {
    normal: {
      duration: 5,
      protocol_type: "tcp",
      service: "http",
      flag: "SF",
      src_bytes: 200,
      dst_bytes: 300,
      land: 0,
      wrong_fragment: 0,
      urgent: 0,
      hot: 0,
      num_failed_logins: 0,
      logged_in: 1,
      num_compromised: 0,
      root_shell: 0,
      su_attempted: 0,
      num_root: 0,
      num_file_creations: 0,
      num_shells: 0,
      num_access_files: 0,
      num_outbound_cmds: 0,
      is_host_login: 0,
      is_guest_login: 0,
      count: 10,
      srv_count: 5,
      serror_rate: 0.0,
      srv_serror_rate: 0.0,
      rerror_rate: 0.0,
      srv_rerror_rate: 0.0,
      same_srv_rate: 0.8,
      diff_srv_rate: 0.05,
      srv_diff_host_rate: 0.0,
      dst_host_count: 10,
      dst_host_srv_count: 5,
      dst_host_same_srv_rate: 0.8,
      dst_host_diff_srv_rate: 0.02,
      dst_host_same_src_port_rate: 0.01,
      dst_host_srv_diff_host_rate: 0.0,
      dst_host_serror_rate: 0.0,
      dst_host_srv_serror_rate: 0.0,
      dst_host_rerror_rate: 0.0,
      dst_host_srv_rerror_rate: 0.0,
    },

    attack: {
      duration: 1,
      protocol_type: "tcp",
      service: "http",
      flag: "S0",
      src_bytes: 0,
      dst_bytes: 0,
      land: 0,
      wrong_fragment: 0,
      urgent: 0,
      hot: 0,
      num_failed_logins: 0,
      logged_in: 0,
      num_compromised: 0,
      root_shell: 0,
      su_attempted: 0,
      num_root: 0,
      num_file_creations: 0,
      num_shells: 0,
      num_access_files: 0,
      num_outbound_cmds: 0,
      is_host_login: 0,
      is_guest_login: 0,
      // attack-like indicators
      count: 400,
      srv_count: 300,
      serror_rate: 1.0,
      srv_serror_rate: 1.0,
      rerror_rate: 0.0,
      srv_rerror_rate: 0.0,
      same_srv_rate: 1.0,
      diff_srv_rate: 0.0,
      srv_diff_host_rate: 0.0,
      dst_host_count: 200,
      dst_host_srv_count: 150,
      dst_host_same_srv_rate: 0.99,
      dst_host_diff_srv_rate: 0.0,
      dst_host_same_src_port_rate: 1.0,
      dst_host_srv_diff_host_rate: 0.0,
      dst_host_serror_rate: 0.0,
      dst_host_srv_serror_rate: 0.0,
      dst_host_rerror_rate: 0.0,
      dst_host_srv_rerror_rate: 0.0,
    },
  };

  // ========== fullForm state containing all 41 features ==========
  const emptyFullForm = {
    duration: 0,
    protocol_type: "tcp",
    service: "http",
    flag: "SF",
    src_bytes: 0,
    dst_bytes: 0,
    land: 0,
    wrong_fragment: 0,
    urgent: 0,
    hot: 0,
    num_failed_logins: 0,
    logged_in: 1,
    num_compromised: 0,
    root_shell: 0,
    su_attempted: 0,
    num_root: 0,
    num_file_creations: 0,
    num_shells: 0,
    num_access_files: 0,
    num_outbound_cmds: 0,
    is_host_login: 0,
    is_guest_login: 0,
    count: 5,
    srv_count: 5,
    serror_rate: 0.0,
    srv_serror_rate: 0.0,
    rerror_rate: 0.0,
    srv_rerror_rate: 0.0,
    same_srv_rate: 1.0,
    diff_srv_rate: 0.0,
    srv_diff_host_rate: 0.0,
    dst_host_count: 5,
    dst_host_srv_count: 5,
    dst_host_same_srv_rate: 1.0,
    dst_host_diff_srv_rate: 0.0,
    dst_host_same_src_port_rate: 0.0,
    dst_host_srv_diff_host_rate: 0.0,
    dst_host_serror_rate: 0.0,
    dst_host_srv_serror_rate: 0.0,
    dst_host_rerror_rate: 0.0,
    dst_host_srv_rerror_rate: 0.0,
  };

  const [fullForm, setFullForm] = useState(emptyFullForm);

  const [preset, setPreset] = useState("custom");
  const [advancedOpen, setAdvancedOpen] = useState(false);

  // apply preset => replace all fields in fullForm
  const applyPreset = (type) => {
    setPreset(type);
    if (type === "custom") return;
    const tpl = TEMPLATES[type];
    setFullForm((prev) => ({ ...prev, ...tpl }));
  };

  // helper to set individual field and coerce numeric fields
  const setField = (key, value) => {
    // numeric keys
    const numericKeys = new Set([
      "duration","src_bytes","dst_bytes","land","wrong_fragment","urgent","hot",
      "num_failed_logins","logged_in","num_compromised","root_shell","su_attempted",
      "num_root","num_file_creations","num_shells","num_access_files","num_outbound_cmds",
      "is_host_login","is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
      "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate","srv_diff_host_rate",
      "dst_host_count","dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
      "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
      "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate"
    ]);
    if (numericKeys.has(key)) {
      // treat empty as 0
      const num = value === "" ? 0 : Number(value);
      setFullForm((prev) => ({ ...prev, [key]: isNaN(num) ? 0 : num }));
    } else {
      setFullForm((prev) => ({ ...prev, [key]: value }));
    }
  };

  // ========== Response normalization & formatting ==========
  const normalizeApiResponse = (data) => {
    if (!data || typeof data !== "object") {
      return {
        prediction: "Unknown",
        is_intrusion: false,
        confidence: 0,
        attack_probability: 0,
        normal_probability: 0,
      };
    }

    const confidence =
      typeof data.confidence === "number"
        ? data.confidence
        : typeof data.attack_probability === "number" && data.is_intrusion
        ? data.attack_probability
        : typeof data.normal_probability === "number" && !data.is_intrusion
        ? data.normal_probability
        : 0;

    return {
      prediction: data.prediction ?? (data.is_intrusion ? "Attack" : "Normal"),
      is_intrusion: !!data.is_intrusion,
      confidence: Number(confidence),
      attack_probability: Number(data.attack_probability ?? 0),
      normal_probability: Number(data.normal_probability ?? 0),
    };
  };

  // ========== states for results, live, batch ==========
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [batchResults, setBatchResults] = useState(null);
  const [liveData, setLiveData] = useState([]);
  const wsRef = useRef(null);
  const [liveStatus, setLiveStatus] = useState("disconnected");

  // safe format helper
  const fmt = (v) => {
    const n = Number(v ?? 0);
    if (Number.isFinite(n)) return n.toFixed(2);
    return "0.00";
  };

  // ========== predict single ==========
  const predict = async () => {
    const packet = { ...fullForm }; // send full exact payload
    try {
      const res = await fetch("http://127.0.0.1:8000/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(packet),
      });
      const data = await res.json();
      const safe = normalizeApiResponse(data);
      setResult(safe);
      setHistory((prev) => [...prev, safe.is_intrusion ? 1 : 0]);
    } catch (err) {
      console.error("Predict error:", err);
      setResult(normalizeApiResponse(null));
    }
  };

  // ========== batch CSV ==========
  const handleCSV = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    Papa.parse(file, {
      header: true,
      skipEmptyLines: true,
      complete: async (res) => {
        const rows = res.data.map((r) => {
          // build each row by taking fullForm defaults and overriding with CSV values if present
          const merged = { ...fullForm };
          Object.keys(merged).forEach((k) => {
            if (r[k] !== undefined && r[k] !== "") {
              // numeric fields -> coerce
              if (typeof merged[k] === "number") merged[k] = Number(r[k]);
              else merged[k] = r[k];
            }
          });
          return merged;
        });

        try {
          const resp = await fetch("http://127.0.0.1:8000/predict/batch", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ traffic_data: rows }),
          });
          const data = await resp.json();
          if (data && Array.isArray(data.results)) {
            data.results = data.results.map(normalizeApiResponse);
          }
          setBatchResults(data);
        } catch (err) {
          console.error("Batch predict error:", err);
          setBatchResults(null);
        }
      },
    });
  };

  // ========== live websocket ==========
  const startLiveStream = () => {
    wsRef.current = new WebSocket("ws://127.0.0.1:8000/live");
    wsRef.current.onopen = () => setLiveStatus("connected");
    wsRef.current.onclose = () => setLiveStatus("disconnected");
    wsRef.current.onmessage = (event) => {
      try {
        const raw = JSON.parse(event.data);
        const safe = normalizeApiResponse(raw);
        setLiveData((prev) => [safe, ...prev.slice(0, 49)]);
        setHistory((prev) => [...prev, safe.is_intrusion ? 1 : 0]);
      } catch (err) {
        console.error("Live parse error:", err);
      }
    };
  };
  const stopLiveStream = () => {
    if (wsRef.current) wsRef.current.close();
    setLiveStatus("disconnected");
  };

  const chartData = {
    labels: history.map((_, i) => i + 1),
    datasets: [
      {
        label: "Intrusion Timeline (1 = Attack, 0 = Normal)",
        data: history,
        borderWidth: 2,
      },
    ],
  };

  // helper to reset full form to defaults
  const resetFullForm = () => setFullForm(emptyFullForm);

  // helper to render an input row (label + input)
  const InputField = ({ k, value }) => {
    const isNumeric = typeof value === "number";
    return (
      <div className="field-item">
        <label>{k.replace(/_/g, ' ')}</label>
        <input
          value={fullForm[k]}
          onChange={(e) => setField(k, isNumeric ? e.target.value : e.target.value)}
        />
      </div>
    );
  };

  return (
    <div className="app-wrapper">
      {/* TABS */}
      <div className="tabs">
        <button className={tab === "live" ? "active" : ""} onClick={() => setTab("live")}>🔴 Live Monitor</button>
        <button className={tab === "manual" ? "active" : ""} onClick={() => setTab("manual")}>🟢 Manual Predict</button>
        <button className={tab === "batch" ? "active" : ""} onClick={() => setTab("batch")}>📁 Batch Upload</button>
      </div>

      {/* MANUAL */}
      {tab === "manual" && (
        <div className="tab-content">
          <h1>Manual Packet Analysis (All fields)</h1>

          <div className="traffic-controls-wrapper">
            <label>Traffic Type:</label>
            <select 
              value={preset} 
              onChange={(e) => applyPreset(e.target.value)} 
              className="traffic-type-select"
            >
              <option value="custom">Custom</option>
              <option value="normal">Normal</option>
              <option value="attack">Attack</option>
            </select>

            <div className="controls-buttons">
              <button 
                onClick={() => { setPreset("custom"); resetFullForm(); }} 
                className="reset-btn"
              >
                Reset
              </button>

              <button 
                onClick={() => setAdvancedOpen((s) => !s)} 
                className="toggle-fields-btn"
              >
                {advancedOpen ? "Hide Fields" : "Show All Fields"}
              </button>
            </div>
          </div>

          {/* Show a compact set of primary fields always, advanced (all) in collapsible */}
          <div className="input-group" style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8 }}>
            <input value={fullForm.duration} onChange={(e) => setField("duration", e.target.value)} placeholder="duration" />
            <select value={fullForm.protocol_type} onChange={(e) => setField("protocol_type", e.target.value)}>
              <option>tcp</option><option>udp</option><option>icmp</option>
            </select>
            <input value={fullForm.service} onChange={(e) => setField("service", e.target.value)} placeholder="service" />
            <input value={fullForm.flag} onChange={(e) => setField("flag", e.target.value)} placeholder="flag" />
            <input value={fullForm.src_bytes} onChange={(e) => setField("src_bytes", e.target.value)} placeholder="src_bytes" />
            <input value={fullForm.dst_bytes} onChange={(e) => setField("dst_bytes", e.target.value)} placeholder="dst_bytes" />
          </div>

          {/* Collapsible full field list */}
          {advancedOpen && (
            <div className="advanced-fields-panel">
              <h4>All NSL-KDD Fields (editable)</h4>
              <div className="fields-grid">
                {Object.keys(fullForm).map((k) => (
                  <InputField key={k} k={k} value={fullForm[k]} />
                ))}
              </div>
            </div>
          )}

          <button onClick={predict} className="predict-btn">
            Analyze Packet
          </button>

          {result && (
            <div className="result-box">
              <h3>{result.prediction}</h3>
              <p>Confidence: {fmt(result.confidence)}%</p>
            </div>
          )}
        </div>
      )}

      {/* LIVE */}
      {tab === "live" && (
        <div className="tab-content">
          <h1>Real-Time Network Intrusion Stream</h1>

          <div className="live-controls">
            <button onClick={startLiveStream} disabled={liveStatus === "connected"}>Start Live</button>
            <button onClick={stopLiveStream} disabled={liveStatus === "disconnected"}>Stop</button>
            <span className={`status ${liveStatus}`}>● {liveStatus}</span>
          </div>

          {liveData.length > 0 && (
            <table className="live-table">
              <thead><tr><th>#</th><th>Status</th><th>Confidence</th></tr></thead>
              <tbody>
                {liveData.map((p, i) => (
                  <tr key={i} className={p.is_intrusion ? "attack-row" : "normal-row"}>
                    <td>{i + 1}</td>
                    <td>{p.prediction}</td>
                    <td>{fmt(p.confidence)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {history.length > 0 && (
            <div className="chart-wrapper">
              <Line data={chartData} />
            </div>
          )}
        </div>
      )}

      {/* BATCH */}
      {tab === "batch" && (
        <div className="tab-content">
          <h1>Batch CSV Threat Analysis</h1>
          <input type="file" accept=".csv" className="upload-input" onChange={handleCSV} />

          {batchResults && (
            <>
              <div className="result-box">
                <p>Total: {batchResults.total_count}</p>
                <p>Attacks: {batchResults.intrusion_count}</p>
                <p>Normal: {batchResults.normal_count}</p>
              </div>

              <table className="batch-table">
                <thead><tr><th>#</th><th>Prediction</th><th>Confidence</th></tr></thead>
                <tbody>
                  {batchResults.results.map((r, i) => (
                    <tr key={i} className={r.is_intrusion ? "attack-row" : "normal-row"}>
                      <td>{i + 1}</td>
                      <td>{r.prediction}</td>
                      <td>{fmt(r.confidence)}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </div>
      )}
    </div>
  );
}

export default App;