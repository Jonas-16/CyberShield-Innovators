import React from 'react';
import { useMemo, useState } from 'react';
import Header from './components/Header';
import NavTabs from './components/NavTabs';
import DashboardPage from './pages/DashboardPage';
import ScanPage from './pages/ScanPage';
import ResultPage from './pages/ResultPage';
import LogsPage from './pages/LogsPage';

const pages = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'scan', label: 'Scan Page' },
  { id: 'result', label: 'Result Page' },
  { id: 'logs', label: 'Logs Page' }
];

const overallResult = 'Safe';

function mapResultToSystemStatus(result) {
  if (result === 'Malicious') return 'Threat Detected';
  if (result === 'Suspicious') return 'Monitoring';
  return 'Safe';
}

export default function App() {
  const [activePage, setActivePage] = useState('dashboard');
  const [theme, setTheme] = useState('dark');
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
    if (status === 'Monitoring') return 'status-pill monitoring';
    return 'status-pill safe';
  }

  const activeContent = useMemo(() => {
    if (activePage === 'dashboard') return <DashboardPage />;
    if (activePage === 'scan') return <ScanPage />;
    if (activePage === 'result') return <ResultPage overallResult={overallResult} />;
    return <LogsPage />;
  }, [activePage]);

  return (
    <div className="app-shell">
      <Header systemStatus={systemStatus} statusClass={statusClass} />

      <div className="main-layout">
        <aside className="sidebar">
          <NavTabs pages={pages} activePage={activePage} onPageChange={setActivePage} />
          <button
            type="button"
            className="theme-toggle"
            onClick={toggleTheme}
            style={{ marginTop: '20px' }}
          >
            {theme === 'dark' ? '☀️ Light mode' : '🌙 Dark mode'}
          </button>
        </aside>

        <main className="content">{activeContent}</main>
      </div>
    </div>
  );
}
