import { useEffect, useState } from 'react'
import io from 'socket.io-client'
import './Dashboard.css'

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:5000'

export default function Dashboard() {
  const [data, setData] = useState(null)
  const [isConnected, setIsConnected] = useState(false)
  const [lastUpdate, setLastUpdate] = useState(null)
  const [clientCount, setClientCount] = useState(0)

  useEffect(() => {
    const socket = io(BACKEND_URL, {
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      reconnectionAttempts: 5,
    })

    socket.on('connect', () => {
      setIsConnected(true)
      console.log('Connected to backend')
    })

    socket.on('initial-data', (initialData) => {
      setData(initialData)
      setLastUpdate(new Date())
    })

    socket.on('dashboard-update', (newData) => {
      setData(newData)
      setLastUpdate(new Date())
    })

    socket.on('client-count', (count) => {
      setClientCount(count.count)
    })

    socket.on('disconnect', () => {
      setIsConnected(false)
    })

    return () => socket.disconnect()
  }, [])

  return (
    <div className="dashboard-container">
      <header className="dashboard-header">
        <div>
          <h1>🏦 Bank Indonesia - Security Ops Center</h1>
          <p className="subtitle">Real-time Monitoring: BGP/RPKI | DDoS | Prefix</p>
        </div>
        <div className="header-info">
          <span className={`status ${isConnected ? 'connected' : 'disconnected'}`}>
            ● {isConnected ? 'CONNECTED' : 'DISCONNECTED'}
          </span>
          <span className="count">👥 {clientCount} monitoring</span>
        </div>
      </header>

      {data ? (
        <main className="dashboard-main">
          <section className="section">
            <h2>🔒 Security Status</h2>
            <div className={`status-box ${data.status === 'SECURE' ? 'secure' : 'alert'}`}>
              ✓ STATUS: {data.status} — {data.prefix}
            </div>
            <p className="update-time">Last: {lastUpdate?.toLocaleTimeString()}</p>
          </section>

          <section className="section">
            <h2>📊 Services</h2>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Prefix</th>
                  <th>AS</th>
                  <th>Description</th>
                  <th>Status</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {data.services?.map((s, i) => (
                  <tr key={i}>
                    <td>{s.prefix}</td>
                    <td>{s.asNumber}</td>
                    <td>{s.description}</td>
                    <td><span className="badge">{s.status}</span></td>
                    <td>{s.lastUpdate}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>

          <section className="section incidents">
            <h2>🚨 Incidents</h2>
            <div className="metrics">
              <div className="metric">
                <div className="value">{data.incidents?.total || 0}</div>
                <div className="label">Total Detected</div>
              </div>
              <div className="metric active">
                <div className="value">{data.incidents?.active || 0}</div>
                <div className="label">Active</div>
              </div>
              <div className="metric">
                <div className="value">{data.incidents?.resolved || 0}</div>
                <div className="label">Resolved</div>
              </div>
              <div className="metric">
                <div className="value">{data.incidents?.domains || 0}</div>
                <div className="label">Affected Domains</div>
              </div>
            </div>
          </section>
        </main>
      ) : (
        <div className="loading">
          <div className="spinner"></div>
          <p>Connecting to {BACKEND_URL}...</p>
        </div>
      )}
    </div>
  )
}