import React, { useEffect, useState } from 'react';

const API_BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000';
const REFRESH_INTERVAL_MS = 5000;

function statusClass(status) {
  if (status === 'Malicious') return 'tag bad';
  if (status === 'Suspicious') return 'tag warn';
  return 'tag ok';
}

function formatDate(ts) {
  if (!ts) return '-';
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) return ts;
  return date.toLocaleString();
}

export default function LogsPage() {
  const [items, setItems] = useState([]);
  const [message, setMessage] = useState('');

  useEffect(() => {
    let active = true;

    const load = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/scan/logs?limit=100`);
        if (!response.ok) {
          const payload = await response.json();
          throw new Error(payload?.detail || 'Failed to load scan logs');
        }

        const payload = await response.json();
        if (!active) return;
        setItems(Array.isArray(payload.items) ? payload.items : []);
        setMessage('');
      } catch (error) {
        if (!active) return;
        setMessage(error?.message || `Cannot reach backend at ${API_BASE_URL}`);
      }
    };

    load();
    const timer = setInterval(load, REFRESH_INTERVAL_MS);

    return () => {
      active = false;
      clearInterval(timer);
    };
  }, []);

  return (
    <section className="page">
      <h2>Logs Page</h2>
      <p className="page-help">This is your scan history. Newest scan appears at the top.</p>
      {message && <p className="scan-message">{message}</p>}

      <div className="card table-wrap">
        <table>
          <thead>
            <tr>
              <th>File Name</th>
              <th>Status</th>
              <th>Risk</th>
              <th>Engine</th>
              <th>Date</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 ? (
              <tr>
                <td colSpan={5}>No scan logs yet.</td>
              </tr>
            ) : (
              items.map((entry, idx) => {
                const status = entry.overall_result || 'Suspicious';
                const risk = typeof entry.fused_risk === 'number' ? `${(entry.fused_risk * 100).toFixed(2)}%` : '-';
                return (
                  <tr key={`${entry.ts || 'na'}-${entry.file_name || 'file'}-${idx}`}>
                    <td>{entry.file_name || '-'}</td>
                    <td><span className={statusClass(status)}>{status}</span></td>
                    <td>{risk}</td>
                    <td>{entry.engine || '-'}</td>
                    <td>{formatDate(entry.ts)}</td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
