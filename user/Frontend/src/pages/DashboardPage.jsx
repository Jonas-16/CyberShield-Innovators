import React, { useEffect, useMemo, useState } from 'react';

const API_BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000';
const REFRESH_INTERVAL_MS = 5000;
const FOLLOW_UP_ACTIONS = new Set(['approved_via_result_page', 'rejected_via_result_page', 'deleted']);

function formatDate(ts) {
  if (!ts) return '-';
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) return ts;
  return date.toLocaleString();
}

function scanKey(entry) {
  return `${entry?.file_name || ''}:${entry?.path || ''}`;
}

export default function DashboardPage() {
  const [logs, setLogs] = useState([]);
  const [message, setMessage] = useState('');

  useEffect(() => {
    let active = true;

    const loadLogs = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/scan/logs?limit=500`);
        if (!response.ok) {
          const payload = await response.json();
          throw new Error(payload?.detail || 'Failed to load dashboard stats');
        }

        const payload = await response.json();
        if (!active) return;
        setLogs(Array.isArray(payload.items) ? payload.items : []);
        setMessage('');
      } catch (error) {
        if (!active) return;
        setLogs([]);
        setMessage(error?.message || `Cannot reach backend at ${API_BASE_URL}`);
      }
    };

    loadLogs();
    const timer = setInterval(loadLogs, REFRESH_INTERVAL_MS);

    return () => {
      active = false;
      clearInterval(timer);
    };
  }, []);

  const stats = useMemo(() => {
    const uniqueScans = new Map();

    logs.forEach((entry) => {
      if (!entry?.file_name || FOLLOW_UP_ACTIONS.has(entry.post_action)) return;
      const key = scanKey(entry);
      if (!uniqueScans.has(key)) {
        uniqueScans.set(key, entry);
      }
    });

    const scans = Array.from(uniqueScans.values());
    scans.sort((a, b) => Date.parse(b.ts || '') - Date.parse(a.ts || ''));

    return {
      lastScan: formatDate(scans[0]?.ts),
      filesScanned: scans.length,
      threatsBlocked: scans.filter((entry) => (
        entry.overall_result === 'Malicious' || String(entry.decision || '').toUpperCase() === 'BLOCKED'
      )).length,
    };
  }, [logs]);

  return (
    <section className="page dashboard-page">
      <div className="dashboard-hero card">
        <div>
          <p className="hero-kicker">Cyber Shield Innovators</p>
          <h2>User-to-cloud file scanning</h2>
          <p className="page-help">
            The user laptop runs this UI. Files are uploaded to the backend scanner, which can run on another demo laptop now and a cloud server later.
          </p>
        </div>
        <div className="hero-pill-stack">
          <span className="hero-pill">Upload Scan: ON</span>
          <span className="hero-pill">Mode: Backend API</span>
        </div>
      </div>

      <div className="summary-grid compact">
        <article className="card stat-card">
          <h4>Last Scan</h4>
          <p>{stats.lastScan}</p>
        </article>
        <article className="card stat-card">
          <h4>Files Scanned</h4>
          <p>{stats.filesScanned}</p>
        </article>
        <article className="card stat-card">
          <h4>Threats Blocked</h4>
          <p>{stats.threatsBlocked}</p>
        </article>
      </div>
      {message && <p className="scan-message">{message}</p>}

      <div className="dashboard-columns">
        <article className="card">
          <h3>Main Threats We Stop</h3>
          <div className="threat-tags">
            <span className="threat-tag">Virus</span>
            <span className="threat-tag">Malware</span>
            <span className="threat-tag">Ransomware</span>
            <span className="threat-tag">Hidden Payload</span>
          </div>
        </article>

        <article className="card">
          <h3>Demo Flow</h3>
          <ul className="bullet-list">
            <li>User chooses a file in the frontend</li>
            <li>Frontend uploads it to the backend API</li>
            <li>Backend stores and scans the file</li>
            <li>Frontend shows the returned safety result</li>
          </ul>
        </article>
      </div>
    </section>
  );
}
