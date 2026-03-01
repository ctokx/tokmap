import { useState } from "react";
import ScanForm from "./components/ScanForm";
import ScanResults from "./components/ScanResults";

// Check if running in Tauri
const isTauri = typeof window !== 'undefined' && window.__TAURI_IPC__;

function App() {
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);

  const handleScan = async (config) => {
    setScanning(true);
    setError(null);
    setResults(null);

    try {
      if (isTauri) {
        // Native Tauri app - use invoke
        const { invoke } = await import("@tauri-apps/api/tauri");
        const response = await invoke("run_scan", { request: config });

        if (response.success) {
          setResults(response.results);
        } else {
          setError(response.error);
        }
      } else {
        // Browser mode - show message
        setError(
          "Browser mode detected. For full functionality, you need:\n\n" +
          "Option 1: Use CLI - Open terminal as Administrator:\n" +
          "  tokmap --targets " + config.targets.join(",") +
          " --ports " + config.ports.slice(0, 5).join(",") +
          (config.ports.length > 5 ? "..." : "") +
          (config.service_detection ? " -s" : "") +
          (config.llm_enabled ? " --llm" : "") + "\n\n" +
          "Option 2: Build native app (needs icon file):\n" +
          "  Create src-tauri/icons/icon.ico\n" +
          "  Run: npm run tauri dev"
        );
      }
    } catch (err) {
      setError(err.toString());
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="app">
      <header>
        <h1>Tokmap</h1>
        <span className="subtitle">Network Scanner</span>
      </header>

      <div className="container">
        <ScanForm onScan={handleScan} scanning={scanning} />

        {error && (
          <div className="error">
            <strong>Error:</strong> {error}
          </div>
        )}

        {results && <ScanResults results={results} />}
      </div>
    </div>
  );
}

export default App;
