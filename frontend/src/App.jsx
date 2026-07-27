import { useState } from 'react'
import axios from 'axios'
import './App.css'

const API_URL = 'http://127.0.0.1:8000'

function App() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  const handleScan = async (e) => {
    e.preventDefault()
    if (!url.trim()) return

    setLoading(true)
    setError('')
    setResult(null)

    try {
      const response = await axios.post(`${API_URL}/predict`, { url: url.trim() })
      setResult(response.data)
    } catch (err) {
      setError('Could not reach the scanner. Is the backend running?')
    } finally {
      setLoading(false)
    }
  }

  const isPhishing = result?.prediction === 'Phishing'

  return (
    <div className="page">
      <div className="grid-overlay" />

      <header className="header">
        <div className="brand">
          <span className="brand-mark">◈</span>
          <span className="brand-name">URLGuard</span>
        </div>
        <p className="tagline">Paste a link. Know before you click.</p>
      </header>

      <main className="main">
        <form className="scan-form" onSubmit={handleScan}>
          <input
            type="text"
            className="url-input"
            placeholder="https://example.com/login"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            spellCheck="false"
          />
          <button type="submit" className="scan-btn" disabled={loading}>
            {loading ? 'Scanning…' : 'Scan URL'}
          </button>
        </form>

        {error && <div className="error-box">{error}</div>}

        {loading && (
          <div className="scan-progress">
            <div className="scan-line" />
            <span>Fetching page, checking signals…</span>
          </div>
        )}

        {result && !loading && (
          <section className={`result-card ${isPhishing ? 'danger' : 'safe'}`}>
            <div className="result-top">
              <div className="verdict">
                <span className="verdict-icon">{isPhishing ? '⚠' : '✓'}</span>
                <div>
                  <div className="verdict-label">
                    {isPhishing ? 'Likely Phishing' : 'Looks Legitimate'}
                  </div>
                  <div className="verdict-url" title={result.url}>{result.url}</div>
                </div>
              </div>
              <div className="confidence-ring">
                <svg viewBox="0 0 100 100">
                  <circle cx="50" cy="50" r="42" className="ring-bg" />
                  <circle
                    cx="50" cy="50" r="42"
                    className="ring-fill"
                    style={{
                      strokeDasharray: 264,
                      strokeDashoffset: 264 - (264 * result.confidence) / 100,
                    }}
                  />
                </svg>
                <span className="confidence-value">{result.confidence}%</span>
              </div>
            </div>

            <div className="prob-bars">
              <div className="prob-row">
                <span>Legitimate</span>
                <div className="prob-track">
                  <div
                    className="prob-fill safe-fill"
                    style={{ width: `${result.legitimate_probability}%` }}
                  />
                </div>
                <span className="prob-num">{result.legitimate_probability}%</span>
              </div>
              <div className="prob-row">
                <span>Phishing</span>
                <div className="prob-track">
                  <div
                    className="prob-fill danger-fill"
                    style={{ width: `${result.phishing_probability}%` }}
                  />
                </div>
                <span className="prob-num">{result.phishing_probability}%</span>
              </div>
            </div>

            <details className="signals">
              <summary>View {Object.keys(result.features_used).length} signals checked</summary>
              <div className="signal-grid">
                {Object.entries(result.features_used).map(([key, value]) => (
                  <div key={key} className={`signal-chip ${value === 1 ? 'good' : value === -1 ? 'bad' : 'neutral'}`}>
                    <span className="signal-name">{key}</span>
                    <span className="signal-dot" />
                  </div>
                ))}
              </div>
            </details>
          </section>
        )}
      </main>

      <footer className="footer">
        Random Forest model · trained on 11k+ labeled URLs · live signal extraction
      </footer>
    </div>
  )
}

export default App
