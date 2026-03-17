import React from 'react';

export default function DashboardPage() {
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
          <p>2026-02-13 10:42 AM</p>
        </article>
        <article className="card stat-card">
          <h4>Files Scanned</h4>
          <p>124</p>
        </article>
        <article className="card stat-card">
          <h4>Threats Blocked</h4>
          <p>9</p>
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
