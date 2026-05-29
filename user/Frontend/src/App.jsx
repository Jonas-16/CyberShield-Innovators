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
import { clearCurrentUser, loadCurrentUser } from './auth';

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

  const toggleTheme = () => {
    setTheme((t) => (t === 'dark' ? 'light' : 'dark'));
  };

  function statusClass(status) {
    if (status === 'Threat Detected') return 'status-pill danger';
    if (status === 'Monitoring' || status === 'Review') return 'status-pill monitoring';
    return 'status-pill safe';
  }

  const activeContent = useMemo(() => {
    if (activePage === 'dashboard') return <DashboardPage currentUser={currentUser} />;
    if (activePage === 'scan') return <ScanPage currentUser={currentUser} />;
    if (activePage === 'result') return <ResultPage overallResult={overallResult} currentUser={currentUser} />;
    if (activePage === 'decoder-report') return <DecoderReportPage currentUser={currentUser} />;
    if (activePage === 'logs') return <LogsPage currentUser={currentUser} />;
    return <SettingsPage theme={theme} onToggleTheme={toggleTheme} currentUser={currentUser} />;
  }, [activePage, theme, currentUser]);

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
