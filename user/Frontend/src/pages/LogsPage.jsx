import React, { useEffect, useState } from 'react';

const API_BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000';
const REFRESH_INTERVAL_MS = 5000;

function statusClass(status) {
  if (status === 'Malicious') return 'tag bad';
  if (status === 'Review') return 'tag warn';
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
  const unsafeThreshold = typeof entry?.unsafe_threshold === 'number' ? entry.unsafe_threshold : 0.8;
  const reasons = Array.isArray(entry?.reasons) ? entry.reasons.map((reason) => String(reason).toLowerCase()) : [];

  if (risk !== null && risk >= unsafeThreshold) return 'Suspicious';
  if (prediction === 'stego') return 'Review';
  if (risk !== null && risk >= stegoThreshold) return 'Review';
  if (isImage && engine && engine !== 'stg-ml') return 'Suspicious';
  if (decision === 'BLOCKED') return 'Malicious';
  if (['STEGO', 'UNCERTAIN'].includes(decision)) return 'Review';
  if (['PENDING', 'IGNORED'].includes(decision)) return 'Suspicious';
  if (warning || (engine === 'heuristic' && reasons.some((reason) => reason.includes('could not inspect')))) {
    return 'Suspicious';
  }
  return entry?.overall_result || 'Safe';
}

function safetyScore(entry, status) {
  const risk = typeof entry?.fused_risk === 'number' ? entry.fused_risk : null;
  if (risk === null) return '-';

  const rawSafety = 1 - risk;
  let score = Math.max(0, Math.min(100, Math.round(rawSafety * 100)));
  if (status === 'Review') score = Math.min(score, 79);
  if (status === 'Suspicious') score = Math.min(score, 69);
  if (status === 'Malicious') score = Math.min(score, 30);
  return `${score}/100`;
}

function deviceLabel(entry) {
  const name = entry?.device_name || 'Unknown device';
  const os = [entry?.os_name, entry?.os_version].filter(Boolean).join(' ');
  return os ? `${name} (${os})` : name;
}

export default function LogsPage({ currentUser, deviceId }) {
  const [items, setItems] = useState([]);
  const [message, setMessage] = useState('');
  const [thisDeviceOnly, setThisDeviceOnly] = useState(false);
  const userId = currentUser?.id || 'guest';

  useEffect(() => {
    let active = true;

    const load = async () => {
      try {
        const params = new URLSearchParams({ limit: '500', user_id: userId });
        if (thisDeviceOnly) params.set('device_id', deviceId);
        const response = await fetch(`${API_BASE_URL}/api/scan/logs?${params.toString()}`);
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
  }, [userId, deviceId, thisDeviceOnly]);

  return (
    <section className="page">
      <h2>Logs Page</h2>
      <div className="logs-toolbar">
        <p className="page-help">Scans from all devices using your account are shown here. Newest scan appears at the top.</p>
        <label className="logs-device-switch">
          <input
            type="checkbox"
            checked={thisDeviceOnly}
            onChange={(event) => setThisDeviceOnly(event.target.checked)}
          />
          <span>This device</span>
        </label>
      </div>
      {message && <p className="scan-message">{message}</p>}

      <div className="card table-wrap logs-table-wrap">
        <table className="logs-table">
          <colgroup>
            <col className="logs-col-file" />
            <col className="logs-col-status" />
            <col className="logs-col-score" />
            <col className="logs-col-device" />
            <col className="logs-col-engine" />
            <col className="logs-col-date" />
          </colgroup>
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
                    <td className="logs-file-name" title={entry.file_name || '-'}>
                      {entry.file_name || '-'}
                    </td>
                    <td className="logs-status-cell"><span className={statusClass(status)}>{status}</span></td>
                    <td className="logs-score-cell">{safetyScore(entry, status)}</td>
                    <td className="logs-device-cell">{deviceLabel(entry)}</td>
                    <td className="logs-engine-cell">{entry.engine || '-'}</td>
                    <td className="logs-date-cell">{formatDate(entry.ts)}</td>
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
