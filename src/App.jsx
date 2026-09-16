import React, { useState, useRef, useEffect } from 'react';
import { analyzeUrl } from './utils/scannerEngine';
import { Search, ShieldAlert, ShieldCheck, AlertTriangle, CheckCircle2 } from 'lucide-react';
import './App.css';

const App = () => {
  const [urlInput, setUrlInput] = useState('');
  const [scanData, setScanData] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  
  // To auto-focus input on mount
  const inputRef = useRef(null);

  useEffect(() => {
    if (inputRef.current) inputRef.current.focus();
  }, []);

  const triggerScan = () => {
    if (!urlInput.trim()) return;
    
    // Wipe previous results and show spinner
    setScanData(null);
    setIsScanning(true);

    // Adding a slight artificial delay for better UX (feels like it's actually digging deep)
    setTimeout(() => {
      const result = analyzeUrl(urlInput);
      setScanData(result);
      setIsScanning(false);
    }, 800);
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') triggerScan();
  };

  return (
    <div className="app-container">
      <div className="scanner-card">
        
        <div className="header-sec">
          <ShieldAlert size={42} className="logo-icon" />
          <h2>Phishing & URL Scanner</h2>
          <p>Analyze links for malicious patterns and tracking.</p>
        </div>

        <div className="input-group">
          <Search size={18} className="search-icon" />
          <input 
            ref={inputRef}
            type="text" 
            placeholder="Paste a suspicious URL here..."
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            onKeyDown={handleKeyPress}
            disabled={isScanning}
          />
          <button onClick={triggerScan} disabled={isScanning || !urlInput}>
            {isScanning ? 'Scanning...' : 'Analyze'}
          </button>
        </div>

        {/* Displaying Error from engine if URL is complete garbage */}
        {scanData?.error && (
          <div className="error-box">
            <AlertTriangle size={18} />
            <span>{scanData.error}</span>
          </div>
        )}

        {/* Results Panel */}
        {scanData && !scanData.error && (
          <div className="results-panel slide-up">
            
            <div className={`threat-badge ${scanData.threatLevel.toLowerCase()}`}>
              <span className="threat-label">Threat Level:</span>
              <strong>{scanData.threatLevel}</strong>
              <span className="score">({scanData.riskScore}/100)</span>
            </div>

            <div className="details-box">
              <div className="detail-item">
                <span className="label">Target Domain:</span>
                <span className="value truncate">{scanData.domain}</span>
              </div>
            </div>

            {/* Rendering Issues (if any) */}
            {scanData.issues.length > 0 && (
              <div className="findings-sec issues">
                <h4><AlertTriangle size={16} /> Vulnerabilities Found</h4>
                <ul>
                  {scanData.issues.map((issue, idx) => (
                    <li key={idx}>{issue}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Rendering Safe Points (if any) */}
            {scanData.positives.length > 0 && (
              <div className="findings-sec safes">
                <h4><ShieldCheck size={16} /> Security Checks Passed</h4>
                <ul>
                  {scanData.positives.map((safe, idx) => (
                    <li key={idx}>{safe}</li>
                  ))}
                </ul>
              </div>
            )}
            
          </div>
        )}

      </div>
    </div>
  );
};

export default App;