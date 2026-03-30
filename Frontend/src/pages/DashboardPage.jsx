import React, { useEffect, useMemo, useState } from 'react';

const API_BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000';
const LOG_POLL_INTERVAL_MS = 10000;
const NON_SCAN_POST_ACTIONS = new Set(['approved_via_result_page', 'rejected_via_result_page', 'deleted']);

function formatTimestamp(value) {
  if (!value) return '--';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '--';
  return date.toLocaleString();
}

export default function DashboardPage() {
  const [items, setItems] = useState([]);

  useEffect(() => {
    let active = true;

    const loadLogs = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/scan/logs?limit=500`);
        if (!response.ok) {
          return;
        }
        const payload = await response.json();
        if (active) {
          setItems(Array.isArray(payload.items) ? payload.items : []);
        }
      } catch (_) {
        // keep current dashboard values if backend is unavailable
      }
    };

    loadLogs();
    const timer = setInterval(loadLogs, LOG_POLL_INTERVAL_MS);

    return () => {
      active = false;
      clearInterval(timer);
    };
  }, []);

  const stats = useMemo(() => {
    const scanItems = items.filter((item) => !NON_SCAN_POST_ACTIONS.has(item?.post_action || ''));
    const filesScanned = scanItems.length;
    const threatsBlocked = scanItems.filter((item) => item?.decision === 'BLOCKED').length;
    const lastScan = scanItems.length > 0 ? formatTimestamp(scanItems[0]?.ts) : '--';
    return { filesScanned, threatsBlocked, lastScan };
  }, [items]);

  return (
    <section className="page dashboard-page">
      <div className="dashboard-hero card">
        <div>
          <p className="hero-kicker">Cyber Shield Innovators</p>
          <h2>Automatic protection for every download</h2>
          <p className="page-help">
            Files are scanned automatically only when the browser or app downloads directly into
            {' '}<strong>D:\Download</strong>. Manual upload is optional for extra checks.
          </p>
        </div>
        <div className="hero-pill-stack">
          <span className="hero-pill">Auto Scan: ON</span>
          <span className="hero-pill">Mode: Staging Folder</span>
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
          <h3>Automatic Download Flow</h3>
          <ul className="bullet-list">
            <li>Set the browser or app download path to <strong>D:\Download</strong></li>
            <li>Download the file as usual</li>
            <li>Sandbox monitor detects the finished file there</li>
            <li>The file is pushed into Windows Sandbox for review</li>
          </ul>
        </article>
      </div>
    </section>
  );
}
