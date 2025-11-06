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

  const [form, setForm] = useState({
    duration: 0,
    protocol_type: "tcp",
    service: "http",
    flag: "SF",
    src_bytes: 0,
    dst_bytes: 0,
  });

  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [batchResults, setBatchResults] = useState(null);

  const [liveData, setLiveData] = useState([]);
  const wsRef = useRef(null);
  const [liveStatus, setLiveStatus] = useState("disconnected");

  const buildFullFeatures = (d) => ({
    duration: Number(d.duration),
    protocol_type: d.protocol_type,
    service: d.service,
    flag: d.flag,
    src_bytes: Number(d.src_bytes),
    dst_bytes: Number(d.dst_bytes),
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
  });

  // ---------------- MANUAL PREDICTION ----------------
  const predict = async () => {
    const packet = buildFullFeatures(form);

    const response = await fetch("http://127.0.0.1:8000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(packet),
    });

    const data = await response.json();
    setResult(data);
    setHistory((prev) => [...prev, data.is_intrusion ? 1 : 0]);
  };

  // ---------------- BATCH CSV ----------------
  const handleCSV = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    Papa.parse(file, {
      header: true,
      skipEmptyLines: true,
      complete: async (res) => {
        const rows = res.data.map(buildFullFeatures);

        const response = await fetch("http://127.0.0.1:8000/predict/batch", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ traffic_data: rows }),
        });

        const data = await response.json();
        setBatchResults(data);
      },
    });
  };

  // ---------------- LIVE STREAM ----------------
  const startLiveStream = () => {
    wsRef.current = new WebSocket("ws://127.0.0.1:8000/live");
    wsRef.current.onopen = () => setLiveStatus("connected");
    wsRef.current.onclose = () => setLiveStatus("disconnected");

    wsRef.current.onmessage = (event) => {
      const packet = JSON.parse(event.data);
      setLiveData((prev) => [packet, ...prev.slice(0, 49)]);
      setHistory((prev) => [...prev, packet.is_intrusion ? 1 : 0]);
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

  return (
    <div className="app-wrapper">

      {/* ---------------- TABS ---------------- */}
      <div className="tabs">
        <button className={tab === "live" ? "active" : ""} onClick={() => setTab("live")}>🔴 Live Monitor</button>
        <button className={tab === "manual" ? "active" : ""} onClick={() => setTab("manual")}>🟢 Manual Predict</button>
        <button className={tab === "batch" ? "active" : ""} onClick={() => setTab("batch")}>📁 Batch Upload</button>
      </div>

      {/* ---------------- TAB CONTENT ---------------- */}

      {/* LIVE TAB */}
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
                    <td>{i + 1}</td><td>{p.prediction}</td><td>{p.confidence.toFixed(2)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {history.length > 0 && <Line data={chartData} />}
        </div>
      )}

      {/* MANUAL TAB */}
      {tab === "manual" && (
        <div className="tab-content">
          <h1>Manual Single Packet Analysis</h1>
          <div className="input-group">
            <input name="duration" placeholder="Duration" onChange={(e) => setForm({ ...form, duration: e.target.value })} value={form.duration} />
            <select name="protocol_type" onChange={(e) => setForm({ ...form, protocol_type: e.target.value })} value={form.protocol_type}>
              <option>tcp</option><option>udp</option><option>icmp</option>
            </select>
            <input name="service" placeholder="Service" onChange={(e) => setForm({ ...form, service: e.target.value })} value={form.service} />
            <input name="flag" placeholder="Flag" onChange={(e) => setForm({ ...form, flag: e.target.value })} value={form.flag} />
            <input name="src_bytes" placeholder="Source Bytes" onChange={(e) => setForm({ ...form, src_bytes: e.target.value })} value={form.src_bytes} />
            <input name="dst_bytes" placeholder="Destination Bytes" onChange={(e) => setForm({ ...form, dst_bytes: e.target.value })} value={form.dst_bytes} />
          </div>

          <button onClick={predict}>Analyze Packet</button>

          {result && (
            <div className="result-box">
              <h3>{result.prediction}</h3>
              <p>Confidence: {result.confidence.toFixed(2)}%</p>
            </div>
          )}
        </div>
      )}

      {/* BATCH TAB */}
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
                      <td>{i + 1}</td><td>{r.prediction}</td><td>{r.confidence.toFixed(2)}%</td>
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
