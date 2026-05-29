import React from 'react';
import logoSrc from '../../Logos/logo.png';

// header with centered title and optional status pill
export default function Header({ systemStatus, statusClass, currentUser, onLogout }) {
  return (
    <header className="topbar">
      <div className="brand">
        <img src={logoSrc} alt="Cyber Shield Innovators logo" className="brand-logo" />
        <h1>Cyber Shield Innovators</h1>
      </div>
      <div className="header-actions">
        {systemStatus && (
          <div className="status-wrap" aria-label="System status">
            <span className="status-label">System Status:</span>{' '}
            <span className={statusClass(systemStatus)}>{systemStatus}</span>
          </div>
        )}
        {currentUser && (
          <div className="status-wrap user-chip" aria-label="Signed in user">
            <span className="status-label">{currentUser.name}</span>
            <button type="button" className="btn subtle header-logout" onClick={onLogout}>Logout</button>
          </div>
        )}
      </div>
    </header>
  );
}
