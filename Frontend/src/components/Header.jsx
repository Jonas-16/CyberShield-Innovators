import React from 'react';

// header with centered title and optional status pill
export default function Header({ systemStatus, statusClass }) {
  return (
    <header className="topbar">
      <h1>Cyber Shield Innovators</h1>
      {systemStatus && (
        <div className="status-wrap header-status" aria-label="System status">
          <span className="status-label">System Status:</span>{' '}
          <span className={statusClass(systemStatus)}>{systemStatus}</span>
        </div>
      )}
    </header>
  );
}
