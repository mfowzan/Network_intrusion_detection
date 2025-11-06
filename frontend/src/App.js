import React, { useState, useEffect, useRef } from "react";
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

  const setExampleNormal = () => {
    setForm({
      duration: 0,
      protocol_type: "tcp",
      service: "http",
      flag: "SF",
      src_bytes: 181,
      dst_bytes: 5450,
    });
  };

  const setExampleAttack = () => {
    setForm({
      duration: 0,
      protocol_type: "icmp",
      service: "ecr_i",
      flag: "REJ",
      src_bytes: 0,
      dst_bytes: 0,
    });
  };

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

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

  const predict = async () => {
    const packet = buildFullFeatures(form);

    const response = await fetch("http://127.0.0.1:8000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(packet),
    });

    const data = await response.json();
    setResult(data);
    setHistory([...history, data.is_intrusion ? 1 : 0]);
  };

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

  // ------------------ LIVE MODE WEBSOCKET ------------------

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
        label: "Intrusion History (1 = Attack, 0 = Normal)",
        data: history,
        borderWidth: 2,
      },
    ],
  };

  return (
    <div className="container">
      <h1>Intrusion Detection Dashboard</h1>

      {/* LIVE STREAM SECTION */}
      <div className="live-controls">
        <button onClick={startLiveStream} disabled={liveStatus === "connected"}>
          Start Live Mode
        </button>
        <button onClick={stopLiveStream} disabled={liveStatus === "disconnected"}>
          Stop Live Mode
        </button>
        <span className={`status ${liveStatus}`}>● {liveStatus}</span>
      </div>

      {liveData.length > 0 && (
        <table className="live-table">
          <thead>
            <tr>
              <th>#</th><th>Status</th><th>Confidence</th>
            </tr>
          </thead>
          <tbody>
            {liveData.map((p, i) => (
              <tr key={i} className={p.is_intrusion ? "attack-row" : "normal-row"}>
                <td>{i + 1}</td>
                <td>{p.prediction}</td>
                <td>{p.confidence.toFixed(2)}%</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div className="example-btns">
        <button onClick={setExampleNormal}>Normal Example</button>
        <button onClick={setExampleAttack}>Attack Example</button>
      </div>

      <div className="input-group">
        <input name="duration" placeholder="Duration" onChange={handleChange} value={form.duration} />
        <select name="protocol_type" onChange={handleChange} value={form.protocol_type}>
          <option>tcp</option><option>udp</option><option>icmp</option>
        </select>
        <input name="service" placeholder="Service" onChange={handleChange} value={form.service} />
        <input name="flag" placeholder="Flag" onChange={handleChange} value={form.flag} />
        <input name="src_bytes" placeholder="Source Bytes" onChange={handleChange} value={form.src_bytes} />
        <input name="dst_bytes" placeholder="Destination Bytes" onChange={handleChange} value={form.dst_bytes} />
      </div>

      <button className="predict-btn" onClick={predict}>Predict</button>

      {result && (
        <div className="result-box">
          <h3>{result.prediction}</h3>
          <p>Confidence: {result.confidence.toFixed(2)}%</p>
        </div>
      )}

      {history.length > 0 && <Line data={chartData} />}

      <h2>Batch CSV Prediction</h2>
      <input type="file" accept=".csv" className="upload-input" onChange={handleCSV} />

      {batchResults && (
        <>
          <div className="result-box">
            <p>Total: {batchResults.total_count}</p>
            <p>Attacks: {batchResults.intrusion_count}</p>
            <p>Normal: {batchResults.normal_count}</p>
          </div>

          <table className="batch-table">
            <thead>
              <tr><th>#</th><th>Prediction</th><th>Confidence</th></tr>
            </thead>
            <tbody>
              {batchResults.results.map((r, i) => (
                <tr key={i} className={r.is_intrusion ? "attack-row" : "normal-row"}>
                  <td>{i + 1}</td>
                  <td>{r.prediction}</td>
                  <td>{r.confidence.toFixed(2)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}

export default App;
