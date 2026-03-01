import { useState } from "react";

function ScanForm({ onScan, scanning }) {
  const [targets, setTargets] = useState("");
  const [ports, setPorts] = useState("80,443,22,21,25,3306,5432,6379,8080");
  const [timeout, setTimeout] = useState(2000);
  const [maxConcurrent, setMaxConcurrent] = useState(1000);
  const [rateLimit, setRateLimit] = useState("");
  const [serviceDetection, setServiceDetection] = useState(true);
  const [llmEnabled, setLlmEnabled] = useState(false);

  const parsePorts = (portString) => {
    const ports = [];
    const parts = portString.split(",");

    for (const part of parts) {
      const trimmed = part.trim();
      if (trimmed.includes("-")) {
        const [start, end] = trimmed.split("-").map(Number);
        for (let i = start; i <= end; i++) {
          ports.push(i);
        }
      } else {
        ports.push(Number(trimmed));
      }
    }

    return ports;
  };

  const handleSubmit = (e) => {
    e.preventDefault();

    const config = {
      targets: targets.split(/[,\s]+/).filter(t => t.length > 0),
      ports: parsePorts(ports),
      timeout_ms: Number(timeout),
      max_concurrent: Number(maxConcurrent),
      rate_limit: rateLimit ? Number(rateLimit) : null,
      service_detection: serviceDetection,
      llm_enabled: llmEnabled,
    };

    onScan(config);
  };

  return (
    <form className="scan-form" onSubmit={handleSubmit}>
      <div className="form-group">
        <label>
          Targets (IP addresses, comma or space separated)
          <input
            type="text"
            value={targets}
            onChange={(e) => setTargets(e.target.value)}
            placeholder="192.168.1.1, 192.168.1.2"
            required
            disabled={scanning}
          />
        </label>
      </div>

      <div className="form-row">
        <div className="form-group">
          <label>
            Ports (e.g., 80,443,1-1000)
            <input
              type="text"
              value={ports}
              onChange={(e) => setPorts(e.target.value)}
              placeholder="80,443,22,1-1000"
              required
              disabled={scanning}
            />
          </label>
        </div>

        <div className="form-group">
          <label>
            Timeout (ms)
            <input
              type="number"
              value={timeout}
              onChange={(e) => setTimeout(e.target.value)}
              min="100"
              max="30000"
              disabled={scanning}
            />
          </label>
        </div>
      </div>

      <div className="form-row">
        <div className="form-group">
          <label>
            Max Concurrent
            <input
              type="number"
              value={maxConcurrent}
              onChange={(e) => setMaxConcurrent(e.target.value)}
              min="1"
              max="10000"
              disabled={scanning}
            />
          </label>
        </div>

        <div className="form-group">
          <label>
            Rate Limit (pkt/s, optional)
            <input
              type="number"
              value={rateLimit}
              onChange={(e) => setRateLimit(e.target.value)}
              placeholder="Leave empty for unlimited"
              disabled={scanning}
            />
          </label>
        </div>
      </div>

      <div className="form-options">
        <label className="checkbox">
          <input
            type="checkbox"
            checked={serviceDetection}
            onChange={(e) => setServiceDetection(e.target.checked)}
            disabled={scanning}
          />
          Service Detection (9,500+ signatures)
        </label>

        <label className="checkbox">
          <input
            type="checkbox"
            checked={llmEnabled}
            onChange={(e) => setLlmEnabled(e.target.checked)}
            disabled={scanning}
          />
          LLM Analysis (requires GEMINI_API_KEY)
        </label>
      </div>

      <button type="submit" disabled={scanning} className="scan-button">
        {scanning ? "Scanning..." : "Start Scan"}
      </button>
    </form>
  );
}

export default ScanForm;
