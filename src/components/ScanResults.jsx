function ScanResults({ results }) {
  if (!results || !results.targets || results.targets.length === 0) {
    return null;
  }

  const formatDuration = (ms) => {
    if (ms < 1000) return `${ms}ms`;
    return `${(ms / 1000).toFixed(2)}s`;
  };

  const getStateClass = (state) => {
    switch (state) {
      case "open": return "status-open";
      case "closed": return "status-closed";
      case "filtered": return "status-filtered";
      default: return "";
    }
  };

  const getRiskClass = (level) => {
    if (!level) return "";
    const l = level.toLowerCase();
    if (l === "critical") return "risk-critical";
    if (l === "high") return "risk-high";
    if (l === "medium") return "risk-medium";
    if (l === "low") return "risk-low";
    return "risk-info";
  };

  return (
    <div className="results">
      <div className="results-header">
        <h2>Scan Results</h2>
        <div className="stats">
          <span>Type: {results.scan_type}</span>
          <span>Duration: {formatDuration(results.total_duration_ms)}</span>
          <span>Timestamp: {new Date(results.timestamp).toLocaleString()}</span>
        </div>
      </div>

      {results.targets.map((host, hostIdx) => {
        const openPorts = host.ports.filter(p => p.state === "open");

        return (
          <div key={hostIdx} className="host">
            <div className="host-header">
              <h3>{host.ip}</h3>
              {host.hostname && <span className="hostname">({host.hostname})</span>}
              <span className="port-count">
                {openPorts.length} open port{openPorts.length !== 1 ? 's' : ''}
              </span>
              <span className="scan-time">
                {formatDuration(host.scan_duration_ms)}
              </span>
            </div>

            {openPorts.length > 0 && (
              <table className="ports-table">
                <thead>
                  <tr>
                    <th>Port</th>
                    <th>State</th>
                    <th>Latency</th>
                    <th>Service</th>
                    <th>Version</th>
                    <th>Info</th>
                  </tr>
                </thead>
                <tbody>
                  {openPorts.map((port, portIdx) => (
                    <tr key={portIdx}>
                      <td className="port-number">{port.port}</td>
                      <td>
                        <span className={`status ${getStateClass(port.state)}`}>
                          {port.state}
                        </span>
                      </td>
                      <td className="latency">
                        {port.latency_ms ? `${port.latency_ms}ms` : '-'}
                      </td>
                      <td className="service-name">
                        {port.service?.service_name || '-'}
                      </td>
                      <td className="version">
                        {port.service?.version || '-'}
                      </td>
                      <td className="service-info">
                        {port.service?.confidence && (
                          <span className={`confidence confidence-${port.service.confidence}`}>
                            {port.service.confidence}
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            {/* LLM Analysis Section */}
            {openPorts.some(p => p.llm_analysis) && (
              <div className="llm-section">
                <h4>AI Analysis</h4>
                {openPorts.filter(p => p.llm_analysis).map((port, idx) => (
                  <div key={idx} className="llm-analysis">
                    <div className="llm-header">
                      <strong>Port {port.port}</strong>
                      {port.llm_analysis.service_identification && (
                        <span className="ai-service">
                          {port.llm_analysis.service_identification.technology}
                        </span>
                      )}
                    </div>

                    {port.llm_analysis.vulnerability_assessment && (
                      <div className="vulnerabilities">
                        <div className={`risk-badge ${getRiskClass(port.llm_analysis.vulnerability_assessment.risk_level)}`}>
                          Risk: {port.llm_analysis.vulnerability_assessment.risk_level}
                        </div>

                        {port.llm_analysis.vulnerability_assessment.issues.length > 0 && (
                          <div className="issues">
                            <strong>Issues:</strong>
                            <ul>
                              {port.llm_analysis.vulnerability_assessment.issues.map((issue, i) => (
                                <li key={i}>{issue}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    )}

                    {port.llm_analysis.recommendations.length > 0 && (
                      <div className="recommendations">
                        <strong>Recommendations:</strong>
                        <ul>
                          {port.llm_analysis.recommendations.map((rec, i) => (
                            <li key={i}>{rec}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    <div className="confidence-score">
                      AI Confidence: {(port.llm_analysis.confidence * 100).toFixed(0)}%
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

export default ScanResults;
