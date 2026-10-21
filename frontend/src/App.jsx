import { useState, useRef, useEffect } from 'react'
import axios from 'axios'
import './App.css'

function App() {
  const [logs, setLogs] = useState('')
  const [logFormat, setLogFormat] = useState('auto')
  const [analysis, setAnalysis] = useState(null)
  const [loading, setLoading] = useState(false)
  const [progress, setProgress] = useState([])
  const [error, setError] = useState(null)
  const [useWebSocket, setUseWebSocket] = useState(true)
  const fileInputRef = useRef(null)
  const wsRef = useRef(null)

  const handleFileUpload = (e) => {
    const file = e.target.files[0]
    if (file) {
      const reader = new FileReader()
      reader.onload = (event) => {
        setLogs(event.target.result)
      }
      reader.readAsText(file)
    }
  }

  const analyzeLogs = async () => {
    if (!logs.trim()) {
      setError('Please provide logs to analyze')
      return
    }

    setLoading(true)
    setError(null)
    setAnalysis(null)
    setProgress([])

    if (useWebSocket) {
      await analyzeWithWebSocket()
    } else {
      await analyzeWithREST()
    }
  }

  const analyzeWithWebSocket = async () => {
    try {
      wsRef.current = new WebSocket('ws://localhost:8000/ws/analyze')
      
      wsRef.current.onopen = () => {
        wsRef.current.send(JSON.stringify({
          logs: logs,
          log_format: logFormat
        }))
      }

      wsRef.current.onmessage = (event) => {
        const data = JSON.parse(event.data)
        setProgress(prev => [...prev, data])

        if (data.data && data.data.result) {
          setAnalysis(data.data.result)
          setLoading(false)
          wsRef.current.close()
        }
      }

      wsRef.current.onerror = (error) => {
        console.error('WebSocket error:', error)
        setError('WebSocket connection failed. Trying REST API...')
        wsRef.current.close()
        setUseWebSocket(false)
        analyzeWithREST()
      }

      wsRef.current.onclose = () => {
        if (loading && !analysis) {
          setLoading(false)
        }
      }
    } catch (err) {
      setError('WebSocket connection failed')
      setLoading(false)
    }
  }

  const analyzeWithREST = async () => {
    try {
      const response = await axios.post('http://localhost:8000/analyze', {
        logs: logs,
        log_format: logFormat
      })
      setAnalysis(response.data)
      setLoading(false)
    } catch (err) {
      setError(err.response?.data?.error || 'Analysis failed')
      setLoading(false)
    }
  }

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'high': return '#ef4444'
      case 'medium': return '#f59e0b'
      case 'low': return '#10b981'
      default: return '#6b7280'
    }
  }

  const getRiskScoreColor = (score) => {
    if (score >= 70) return '#ef4444'
    if (score >= 40) return '#f59e0b'
    return '#10b981'
  }

  return (
    <div className="app">
      <header className="header">
        <h1>🔒 Security Log Analyzer</h1>
        <p>AI-powered security log analysis using OpenAI</p>
      </header>

      <main className="main">
        <div className="upload-section">
          <div className="input-group">
            <label>Upload Log File:</label>
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileUpload}
              accept=".log,.txt,.json"
              className="file-input"
            />
          </div>

          <div className="input-group">
            <label>Or Paste Logs:</label>
            <textarea
              value={logs}
              onChange={(e) => setLogs(e.target.value)}
              placeholder="Paste your security logs here..."
              className="log-textarea"
              rows={10}
            />
          </div>

          <div className="input-group">
            <label>Log Format:</label>
            <select
              value={logFormat}
              onChange={(e) => setLogFormat(e.target.value)}
              className="format-select"
            >
              <option value="auto">Auto-detect</option>
              <option value="apache">Apache/Nginx</option>
              <option value="syslog">Syslog</option>
              <option value="json">JSON</option>
              <option value="generic">Generic</option>
            </select>
          </div>

          <button
            onClick={analyzeLogs}
            disabled={loading}
            className="analyze-button"
          >
            {loading ? 'Analyzing...' : 'Analyze Logs'}
          </button>

          {error && (
            <div className="error-message">
              {error}
            </div>
          )}
        </div>

        {loading && progress.length > 0 && (
          <div className="progress-section">
            <h3>Analysis Progress</h3>
            <div className="progress-list">
              {progress.map((item, index) => (
                <div key={index} className="progress-item">
                  <span className="progress-time">
                    {new Date(item.timestamp).toLocaleTimeString()}
                  </span>
                  <span className="progress-message">{item.message}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {analysis && (
          <div className="results-section">
            <h2>Analysis Results</h2>

            {/* Summary */}
            <div className="result-card">
              <h3>Summary</h3>
              <p>{analysis.analysis?.summary || 'No summary available'}</p>
              {analysis.analysis?.risk_score !== undefined && (
                <div className="risk-score">
                  <span>Risk Score: </span>
                  <span 
                    className="score-value"
                    style={{ color: getRiskScoreColor(analysis.analysis.risk_score) }}
                  >
                    {analysis.analysis.risk_score}/100
                  </span>
                </div>
              )}
            </div>

            {/* Statistics */}
            <div className="result-card">
              <h3>Statistics</h3>
              <div className="stats-grid">
                <div className="stat-item">
                  <span className="stat-label">Total Logs:</span>
                  <span className="stat-value">{analysis.parsed_logs?.length || 0}</span>
                </div>
                <div className="stat-item">
                  <span className="stat-label">Anomalies:</span>
                  <span className="stat-value">{analysis.anomalies?.length || 0}</span>
                </div>
                <div className="stat-item">
                  <span className="stat-label">Threats Detected:</span>
                  <span className="stat-value">{analysis.analysis?.threats?.length || 0}</span>
                </div>
              </div>
            </div>

            {/* Threats */}
            {analysis.analysis?.threats && analysis.analysis.threats.length > 0 && (
              <div className="result-card">
                <h3>Detected Threats</h3>
                <div className="threats-list">
                  {analysis.analysis.threats.map((threat, index) => (
                    <div key={index} className="threat-item">
                      <div className="threat-header">
                        <span className="threat-type">{threat.type}</span>
                        <span 
                          className="threat-severity"
                          style={{ backgroundColor: getSeverityColor(threat.severity) }}
                        >
                          {threat.severity}
                        </span>
                      </div>
                      <p className="threat-description">{threat.description}</p>
                      {threat.affected_ips && threat.affected_ips.length > 0 && (
                        <div className="affected-ips">
                          <span>Affected IPs: </span>
                          {threat.affected_ips.map((ip, i) => (
                            <span key={i} className="ip-tag">{ip}</span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Patterns */}
            {analysis.analysis?.patterns && analysis.analysis.patterns.length > 0 && (
              <div className="result-card">
                <h3>Patterns Detected</h3>
                <div className="patterns-list">
                  {analysis.analysis.patterns.map((pattern, index) => (
                    <div key={index} className="pattern-item">
                      <span className="pattern-description">{pattern.pattern}</span>
                      <span className="pattern-count">Count: {pattern.count}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Recommendations */}
            {analysis.analysis?.recommendations && analysis.analysis.recommendations.length > 0 && (
              <div className="result-card">
                <h3>Recommendations</h3>
                <ul className="recommendations-list">
                  {analysis.analysis.recommendations.map((rec, index) => (
                    <li key={index} className="recommendation-item">
                      {rec}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Anomalies */}
            {analysis.anomalies && analysis.anomalies.length > 0 && (
              <div className="result-card">
                <h3>Anomalies ({analysis.anomalies.length})</h3>
                <div className="anomalies-list">
                  {analysis.anomalies.slice(0, 10).map((anomaly, index) => (
                    <div key={index} className="anomaly-item">
                      <span 
                        className="anomaly-severity"
                        style={{ backgroundColor: getSeverityColor(anomaly.severity) }}
                      >
                        {anomaly.severity}
                      </span>
                      <span className="anomaly-type">{anomaly.type}</span>
                      <pre className="anomaly-log">{JSON.stringify(anomaly.log, null, 2)}</pre>
                    </div>
                  ))}
                  {analysis.anomalies.length > 10 && (
                    <p className="more-anomalies">
                      ... and {analysis.anomalies.length - 10} more anomalies
                    </p>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  )
}

export default App
