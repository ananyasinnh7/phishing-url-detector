import React, { useState } from 'react'
import { createRoot } from 'react-dom/client'
import './style.css'

const API = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000'

function App() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function scan(event) {
    event.preventDefault(); setError(''); setResult(null)
    if (!url.trim()) { setError('Enter a URL to scan.'); return }
    setLoading(true)
    try {
      const response = await fetch(`${API}/check-url`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({url}) })
      const data = await response.json()
      if (!response.ok) throw new Error(data.detail || 'Could not scan this URL.')
      setResult(data)
    } catch (err) { setError(err.message || 'Backend unavailable. Start the FastAPI server first.') }
    finally { setLoading(false) }
  }

  return <main className="page"><section className="card">
    <div className="eyebrow">SECURITY + MACHINE LEARNING</div><h1>Phishing URL Detector</h1>
    <p className="intro">Paste a link and receive an explainable lexical risk assessment without visiting the URL.</p>
    <form onSubmit={scan}><label htmlFor="url">URL to inspect</label><div className="input-row"><input id="url" value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com/login"/><button disabled={loading}>{loading ? 'Scanning…' : 'Scan URL'}</button></div></form>
    {error && <div className="error">{error}</div>}
    {result && <div className={`result ${result.verdict}`}><div className="result-head"><div><span className="label">VERDICT</span><h2>{result.verdict === 'suspicious' ? 'Suspicious URL' : 'No obvious red flags'}</h2></div><strong>{Math.round(result.confidence * 100)}%</strong></div><p className="normalized"><b>Normalized:</b> {result.normalized_url}</p><h3>Why this result?</h3><ul>{result.reasons.map(reason => <li key={reason.feature}><span>{reason.impact === 'risk' ? '⚠' : '✓'}</span>{reason.message}</li>)}</ul></div>}
    <aside>Educational detector only. A “safe” result does not guarantee safety. Never open suspicious links, and verify important requests through a trusted channel.</aside>
  </section></main>
}
createRoot(document.getElementById('root')).render(<App />)
