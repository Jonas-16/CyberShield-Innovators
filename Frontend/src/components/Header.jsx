import React from 'react';
import appLogo from '../../Logos/Picsart_26-03-30_21-07-39-025.png';

// header with centered title and optional status pill
export default function Header({ systemStatus, statusClass }) {
  return (
    <header className="topbar">
      <div className="brand-lockup">
        <img src={appLogo} alt="Cyber Shield Innovators logo" className="brand-logo" />
        <h1>Cyber Shield Innovators</h1>
      </div>
      {systemStatus && (
        <div className="status-wrap header-status" aria-label="System status">
          <span className="status-label">System Status:</span>{' '}
          <span className={statusClass(systemStatus)}>{systemStatus}</span>
        </div>
      )}
    </header>
  );
}
