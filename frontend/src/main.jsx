import React, { useEffect, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import './style.css'

const API = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000'

const KPI_LABELS = [
  { key: 'total', title: 'Rows evaluated' },
  { key: 'accuracy', title: 'Accuracy' },
  { key: 'errors', title: 'Errors' },
  { key: 'average', title: 'Average score' },
]

function percent(value) {
  return `${Math.round(value * 100)}%`
}

function buildFeatureTrends(rows, featureNames) {
  if (!rows.length || !featureNames.length) return []
  const errorRows = rows.filter((row) => row.error_flag)
  const cleanRows = rows.filter((row) => !row.error_flag)
  if (!errorRows.length || !cleanRows.length) return []
  return featureNames.map((feature) => {
    const values = rows.map((row) => Number(row.feature_values?.[feature] || 0))
    const min = Math.min(...values)
    const max = Math.max(...values)
    const range = max - min || 1
    const avgFor = (set) => set.reduce((sum, row) => sum + ((Number(row.feature_values?.[feature] || 0) - min) / range), 0) / set.length
    const errorAvg = avgFor(errorRows)
    const cleanAvg = avgFor(cleanRows)
    return {
      feature,
      errorAvg,
      cleanAvg,
      diff: errorAvg - cleanAvg,
    }
  }).sort((a, b) => Math.abs(b.diff) - Math.abs(a.diff)).slice(0, 8)
}

function App() {
  const [tab, setTab] = useState('scanner')
  const [url, setUrl] = useState('')
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [dashboard, setDashboard] = useState({ loading: false, error: '', data: null, fetchedAt: '' })
  const [segment, setSegment] = useState('All')

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

  async function loadDashboard() {
    setDashboard((previous) => ({ ...previous, loading: true, error: '' }))
    try {
      const response = await fetch(`${API}/evaluation-data`)
      const data = await response.json()
      if (!response.ok) throw new Error(data.detail || 'Could not load evaluation dataset.')
      setDashboard({ loading: false, error: '', data, fetchedAt: new Date().toLocaleTimeString() })
      setSegment((current) => (data.segment_options.includes(current) ? current : 'All'))
    } catch (err) {
      setDashboard((previous) => ({
        ...previous,
        loading: false,
        error: err.message || 'Backend unavailable. Start the FastAPI server first.',
      }))
    }
  }

  useEffect(() => {
    if (tab === 'dashboard' && !dashboard.data && !dashboard.loading) {
      loadDashboard()
    }
  }, [tab, dashboard.data, dashboard.loading])

  const allRows = dashboard.data?.rows || []
  const featureNames = dashboard.data?.feature_names || []
  const filteredRows = useMemo(() => {
    if (segment === 'All') return allRows
    return allRows.filter((row) => row.segment === segment)
  }, [allRows, segment])
  const confusion = useMemo(() => filteredRows.reduce((counts, row) => {
    const key = `${row.actual_label}_${row.predicted_label}`
    return { ...counts, [key]: counts[key] + 1 }
  }, { safe_safe: 0, safe_suspicious: 0, suspicious_safe: 0, suspicious_suspicious: 0 }), [filteredRows])
  const kpis = useMemo(() => {
    const total = filteredRows.length
    const errors = filteredRows.filter((row) => row.error_flag).length
    const accuracy = total ? (total - errors) / total : 0
    const average = total ? filteredRows.reduce((sum, row) => sum + Number(row.score || 0), 0) / total : 0
    return { total, errors, accuracy, average }
  }, [filteredRows])
  const trends = useMemo(() => buildFeatureTrends(filteredRows, featureNames), [filteredRows, featureNames])
  const maxDiff = Math.max(0.0001, ...trends.map((item) => Math.abs(item.diff)))

  return (
    <main className="page">
      <section className="card wide">
        <div className="eyebrow">SECURITY + MACHINE LEARNING</div>
        <h1>Phishing URL Detector</h1>
        <p className="intro">Scan individual URLs and review model evaluation trends from the bundled sample dataset. The app never visits or resolves URLs.</p>
        <nav className="tabs" aria-label="Views">
          <button className={tab === 'scanner' ? 'tab active' : 'tab'} onClick={() => setTab('scanner')}>URL Scanner</button>
          <button className={tab === 'dashboard' ? 'tab active' : 'tab'} onClick={() => setTab('dashboard')}>Model Evaluation Dashboard</button>
        </nav>

        {tab === 'scanner' && (
          <>
            <form onSubmit={scan}>
              <label htmlFor="url">URL to inspect</label>
              <div className="input-row">
                <input id="url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://example.com/login" />
                <button disabled={loading}>{loading ? 'Scanning…' : 'Scan URL'}</button>
              </div>
            </form>
            {error && <div className="error">{error}</div>}
            {result && <div className={`result ${result.verdict}`}><div className="result-head"><div><span className="label">VERDICT</span><h2>{result.verdict === 'suspicious' ? 'Suspicious URL' : 'No obvious red flags'}</h2></div><strong>{Math.round(result.confidence * 100)}%</strong></div><p className="normalized"><b>Normalized:</b> {result.normalized_url}</p><h3>Why this result?</h3><ul>{result.reasons.map((reason) => <li key={reason.feature}><span>{reason.impact === 'risk' ? '⚠' : '✓'}</span>{reason.message}</li>)}</ul></div>}
            <aside>Educational detector only. A “safe” result does not guarantee safety. Never open suspicious links, and verify important requests through a trusted channel.</aside>
          </>
        )}

        {tab === 'dashboard' && (
          <section className="dashboard" aria-label="Model evaluation dashboard">
            <div className="dashboard-head">
              <div>
                <h2>Sample Evaluation Dashboard</h2>
                <p>Based on bundled sample evaluation data (not production telemetry).</p>
                {dashboard.fetchedAt && <small>Last refreshed: {dashboard.fetchedAt}</small>}
              </div>
              <div className="dashboard-controls">
                <label htmlFor="segment-filter">Segment</label>
                <select id="segment-filter" value={segment} onChange={(event) => setSegment(event.target.value)} disabled={dashboard.loading || !dashboard.data}>
                  {(dashboard.data?.segment_options || ['All']).map((option) => <option key={option} value={option}>{option}</option>)}
                </select>
                <button onClick={loadDashboard} disabled={dashboard.loading}>{dashboard.loading ? 'Refreshing…' : 'Refresh'}</button>
              </div>
            </div>

            {dashboard.loading && <div className="state">Loading evaluation data…</div>}
            {dashboard.error && <div className="error">{dashboard.error}</div>}
            {!dashboard.loading && !dashboard.error && !dashboard.data && <div className="state">No evaluation data available yet.</div>}
            {!dashboard.loading && !dashboard.error && dashboard.data && (
              <>
                <div className="kpi-grid">
                  {KPI_LABELS.map(({ key, title }) => (
                    <article className="kpi-card" key={key}>
                      <span>{title}</span>
                      {key === 'total' && <strong>{kpis.total}</strong>}
                      {key === 'accuracy' && <strong>{percent(kpis.accuracy)}</strong>}
                      {key === 'errors' && <strong>{kpis.errors} ({kpis.total ? percent(kpis.errors / kpis.total) : '0%'})</strong>}
                      {key === 'average' && <strong>{kpis.average.toFixed(3)}</strong>}
                    </article>
                  ))}
                </div>

                <div className="viz-grid">
                  <article className="panel">
                    <h3>Predicted vs Actual</h3>
                    <p>Confusion matrix counts for the selected segment.</p>
                    <table className="mini-table">
                      <thead>
                        <tr><th scope="col">Actual ↓ / Predicted →</th><th scope="col">Safe</th><th scope="col">Suspicious</th></tr>
                      </thead>
                      <tbody>
                        <tr><th scope="row">Safe</th><td>{confusion.safe_safe}</td><td>{confusion.safe_suspicious}</td></tr>
                        <tr><th scope="row">Suspicious</th><td>{confusion.suspicious_safe}</td><td>{confusion.suspicious_suspicious}</td></tr>
                      </tbody>
                    </table>
                  </article>

                  <article className="panel">
                    <h3>Feature-level Error Trends</h3>
                    <p>Bars show how feature intensity differs between error and correct predictions.</p>
                    {!trends.length && <div className="state compact">Need both errors and correct rows in this segment to compare feature trends.</div>}
                    {trends.map((item) => {
                      const width = (Math.abs(item.diff) / maxDiff) * 50
                      const isPositive = item.diff >= 0
                      return (
                        <div key={item.feature} className="trend-row">
                          <div className="trend-meta"><span>{item.feature}</span><small>{isPositive ? 'Higher in errors' : 'Higher in correct predictions'}</small></div>
                          <div className="trend-track">
                            <div className={`trend-bar ${isPositive ? 'right' : 'left'}`} style={isPositive ? { left: '50%', width: `${width}%` } : { right: '50%', width: `${width}%` }} />
                          </div>
                        </div>
                      )
                    })}
                  </article>
                </div>

                <article className="panel">
                  <h3>Evaluated examples</h3>
                  {!filteredRows.length && <div className="state compact">No rows in this segment.</div>}
                  {filteredRows.length > 0 && <div className="table-wrap"><table><thead><tr><th scope="col">URL (non-clickable)</th><th scope="col">Segment</th><th scope="col">Actual</th><th scope="col">Predicted</th><th scope="col">Score</th><th scope="col">Error</th></tr></thead><tbody>{filteredRows.map((row, index) => <tr key={`${row.url}-${index}`}><td className="url-cell">{row.url}</td><td>{row.segment}</td><td>{row.actual_label}</td><td>{row.predicted_label}</td><td>{Number(row.score).toFixed(3)}</td><td>{row.error_flag ? 'Yes' : 'No'}</td></tr>)}</tbody></table></div>}
                </article>
              </>
            )}
          </section>
        )}
      </section>
    </main>
  )
}
createRoot(document.getElementById('root')).render(<App />)
