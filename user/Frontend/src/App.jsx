import React from 'react';
import { useMemo, useState } from 'react';
import Header from './components/Header';
import NavTabs from './components/NavTabs';
import DashboardPage from './pages/DashboardPage';
import ScanPage from './pages/ScanPage';
import ResultPage from './pages/ResultPage';
import DecoderReportPage from './pages/DecoderReportPage';
import LogsPage from './pages/LogsPage';
import SettingsPage from './pages/SettingsPage';
import AuthPage from './pages/AuthPage';
import { clearCurrentUser, loadCurrentUser, localDeviceId } from './auth';

const pages = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'scan', label: 'Scan Page' },
  { id: 'result', label: 'Result Page' },
  { id: 'decoder-report', label: 'Decoder Report' },
  { id: 'logs', label: 'Logs Page' },
  { id: 'settings', label: 'Settings' }
];

const overallResult = 'Safe';

function mapResultToSystemStatus(result) {
  if (result === 'Malicious') return 'Threat Detected';
  if (result === 'Suspicious') return 'Monitoring';
  if (result === 'Review') return 'Review';
  return 'Safe';
}

export default function App() {
  const [activePage, setActivePage] = useState('dashboard');
  const [theme, setTheme] = useState('dark');
  const [currentUser, setCurrentUser] = useState(() => loadCurrentUser());
  const [deviceId, setDeviceId] = useState(() => localDeviceId());
  const systemStatus = mapResultToSystemStatus(overallResult);

  // remember theme preference
  React.useEffect(() => {
    document.body.classList.toggle('light-mode', theme === 'light');
    localStorage.setItem('theme', theme);
  }, [theme]);

  React.useEffect(() => {
    const stored = localStorage.getItem('theme');
    if (stored === 'light' || stored === 'dark') {
      setTheme(stored);
    }
  }, []);

  React.useEffect(() => {
    let active = true;
    fetch(`${import.meta.env.VITE_WATCHER_URL || 'http://127.0.0.1:8765'}/api/device`)
      .then((response) => (response.ok ? response.json() : null))
      .then((device) => {
        if (active && device?.device_id) setDeviceId(device.device_id);
      })
      .catch(() => {});
    return () => { active = false; };
  }, []);

  const toggleTheme = () => {
    setTheme((t) => (t === 'dark' ? 'light' : 'dark'));
  };

  function statusClass(status) {
    if (status === 'Threat Detected') return 'status-pill danger';
    if (status === 'Monitoring' || status === 'Review') return 'status-pill monitoring';
    return 'status-pill safe';
  }

  const activeContent = useMemo(() => {
    if (activePage === 'dashboard') return <DashboardPage currentUser={currentUser} deviceId={deviceId} />;
    if (activePage === 'scan') return <ScanPage currentUser={currentUser} deviceId={deviceId} />;
    if (activePage === 'result') return <ResultPage overallResult={overallResult} currentUser={currentUser} deviceId={deviceId} />;
    if (activePage === 'decoder-report') return <DecoderReportPage currentUser={currentUser} deviceId={deviceId} />;
    if (activePage === 'logs') return <LogsPage currentUser={currentUser} deviceId={deviceId} />;
    return <SettingsPage theme={theme} onToggleTheme={toggleTheme} currentUser={currentUser} />;
  }, [activePage, theme, currentUser, deviceId]);

  const handleLogout = () => {
    clearCurrentUser();
    setCurrentUser(null);
    setActivePage('dashboard');
  };

  if (!currentUser) {
    return <AuthPage onAuthenticated={setCurrentUser} />;
  }

  return (
    <div className="app-shell">
      <Header
        systemStatus={systemStatus}
        statusClass={statusClass}
        currentUser={currentUser}
        onLogout={handleLogout}
      />

      <div className="main-layout">
        <aside className="sidebar">
          <NavTabs pages={pages} activePage={activePage} onPageChange={setActivePage} />
        </aside>

        <main className="content">{activeContent}</main>
      </div>
    </div>
  );
}
