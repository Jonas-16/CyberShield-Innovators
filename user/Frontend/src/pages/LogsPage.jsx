import React, { useEffect, useState } from 'react';

const API_BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000';
const REFRESH_INTERVAL_MS = 5000;
const FOLLOW_UP_ACTIONS = new Set(['approved_via_result_page', 'rejected_via_result_page', 'deleted']);

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

function resultText(entry) {
  const suffix = String(entry?.file_name || entry?.path || '').toLowerCase().split('.').pop();
  const isImage = ['jpg', 'jpeg', 'jfif', 'png', 'bmp', 'gif', 'tif', 'tiff', 'webp'].includes(suffix);
  const prediction = String(entry?.predicted_label || '').toLowerCase();
  const decision = String(entry?.decision || '').toUpperCase();
  const engine = String(entry?.engine || '').toLowerCase();
  const warning = String(entry?.scanner_warning || '');
  const risk = typeof entry?.fused_risk === 'number' ? entry.fused_risk : null;
  const stegoThreshold = typeof entry?.stego_threshold === 'number' ? entry.stego_threshold : 0.7;
  const reasons = Array.isArray(entry?.reasons) ? entry.reasons.map((reason) => String(reason).toLowerCase()) : [];

  if (prediction === 'stego') return 'Suspicious';
  if (risk !== null && risk >= stegoThreshold) return 'Suspicious';
  if (isImage && engine && engine !== 'stg-ml') return 'Suspicious';
  if (decision === 'BLOCKED') return 'Malicious';
  if (decision === 'STEGO') return 'Suspicious';
  if (warning || (engine === 'heuristic' && reasons.some((reason) => reason.includes('could not inspect')))) {
    return 'Suspicious';
  }
  return entry?.overall_result || 'Safe';
}

function scanKey(entry) {
  return `${entry?.file_name || ''}:${entry?.path || ''}`;
}

function dedupeScans(items) {
  const rows = [];
  const seen = new Set();

  items.forEach((entry) => {
    if (FOLLOW_UP_ACTIONS.has(entry?.post_action)) return;
    const key = scanKey(entry);
    if (seen.has(key)) return;
    seen.add(key);
    rows.push(entry);
  });

  return rows;
}

function safetyScore(entry, status) {
  const risk = typeof entry?.fused_risk === 'number' ? entry.fused_risk : null;
  if (risk === null) return '-';

  const rawSafety = 1 - risk;
  let score = Math.max(0, Math.min(100, Math.round(rawSafety * 100)));
  if (status === 'Suspicious') score = Math.min(score, 69);
  if (status === 'Malicious') score = Math.min(score, 30);
  return `${score} / 100`;
}

function deviceLabel(entry) {
  const name = entry?.device_name || 'Unknown device';
  const os = [entry?.os_name, entry?.os_version].filter(Boolean).join(' ');
  return os ? `${name} (${os})` : name;
}

export default function LogsPage({ currentUser }) {
  const [items, setItems] = useState([]);
  const [message, setMessage] = useState('');
  const userId = currentUser?.id || 'guest';

  useEffect(() => {
    let active = true;

    const load = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/scan/logs?limit=100&user_id=${encodeURIComponent(userId)}`);
        if (!response.ok) {
          const payload = await response.json();
          throw new Error(payload?.detail || 'Failed to load scan logs');
        }

        const payload = await response.json();
        if (!active) return;
        setItems(dedupeScans(Array.isArray(payload.items) ? payload.items : []));
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
  }, [userId]);

  return (
    <section className="page">
      <h2>Logs Page</h2>
      <p className="page-help">This is {currentUser?.name}'s scan history. Newest scan appears at the top.</p>
      {message && <p className="scan-message">{message}</p>}

      <div className="card table-wrap">
        <table>
          <thead>
            <tr>
              <th>File Name</th>
              <th>Status</th>
              <th>Safety Score</th>
              <th>Device</th>
              <th>Engine</th>
              <th>Date</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 ? (
              <tr>
                <td colSpan={6}>No scan logs yet.</td>
              </tr>
            ) : (
              items.map((entry, idx) => {
                const status = resultText(entry);
                return (
                  <tr key={`${entry.ts || 'na'}-${entry.file_name || 'file'}-${idx}`}>
                    <td>{entry.file_name || '-'}</td>
                    <td><span className={statusClass(status)}>{status}</span></td>
                    <td>{safetyScore(entry, status)}</td>
                    <td>{deviceLabel(entry)}</td>
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
