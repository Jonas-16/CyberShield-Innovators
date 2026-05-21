import React, { useEffect, useMemo, useRef, useState } from 'react';
import { scopedKey } from '../auth';

const MONITORED_FOLDERS_KEY = 'monitoredFolders';
const API_BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000';
const WATCHER_URL = import.meta.env.VITE_WATCHER_URL || 'http://127.0.0.1:8765';

function normalizePath(value) {
  return String(value || '').trim().replace(/^"+|"+$/g, '');
}

function loadFolders(storageKey = MONITORED_FOLDERS_KEY) {
  try {
    const parsed = JSON.parse(localStorage.getItem(storageKey) || '[]');
    return Array.isArray(parsed) ? parsed.map(normalizePath).filter(Boolean) : [];
  } catch (_) {
    return [];
  }
}

export default function SettingsPage({ theme, onToggleTheme, currentUser }) {
  const userId = currentUser?.id || 'guest';
  const foldersKey = scopedKey(MONITORED_FOLDERS_KEY, userId);
  const [folderPath, setFolderPath] = useState('');
  const [folders, setFolders] = useState(() => loadFolders(foldersKey));
  const [message, setMessage] = useState('');
  const [watcherStatus, setWatcherStatus] = useState(null);
  const [isPickingFolder, setIsPickingFolder] = useState(false);
  const activeFoldersKeyRef = useRef(foldersKey);

  useEffect(() => {
    if (activeFoldersKeyRef.current !== foldersKey) return;
    localStorage.setItem(foldersKey, JSON.stringify(folders));
  }, [folders, foldersKey]);

  useEffect(() => {
    activeFoldersKeyRef.current = foldersKey;
    setFolders(loadFolders(foldersKey));
  }, [foldersKey]);

  const refreshWatcherStatus = async () => {
    try {
      const response = await fetch(`${WATCHER_URL}/api/health`);
      if (!response.ok) throw new Error('Watcher health check failed');
      const payload = await response.json();
      setWatcherStatus({ connected: true, ...payload });
      return true;
    } catch (error) {
      setWatcherStatus({
        connected: false,
        last_error: `Local folder watcher is not running at ${WATCHER_URL}.`,
      });
      return false;
    }
  };

  const syncWatcher = async (nextFolders, successMessage) => {
    localStorage.setItem(foldersKey, JSON.stringify(nextFolders));
    try {
      const response = await fetch(`${WATCHER_URL}/api/settings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          folders: nextFolders,
          backend_url: API_BASE_URL,
          user_id: userId,
          scan_existing: false,
        }),
      });

      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload?.detail || 'Folder watcher rejected the settings.');
      }

      setWatcherStatus((current) => ({ ...(current || {}), connected: true, folders: nextFolders.length, last_error: null }));
      setMessage(successMessage);
    } catch (error) {
      setMessage(`${successMessage} Start the local folder watcher to activate monitoring.`);
      setWatcherStatus({
        connected: false,
        last_error: error?.message || `Local folder watcher is not running at ${WATCHER_URL}.`,
      });
    }
  };

  useEffect(() => {
    let active = true;

    const loadWatcherSettings = async () => {
      const healthOk = await refreshWatcherStatus();
      if (!healthOk || !active) return;

      try {
        const response = await fetch(`${WATCHER_URL}/api/settings`);
        if (!response.ok) throw new Error('Failed to load watcher settings');
        const payload = await response.json();
        if (!active) return;
        if (payload.user_id && payload.user_id !== userId) {
          const savedFolders = loadFolders(foldersKey);
          const watcherFolders = Array.isArray(payload.folders) ? payload.folders.map(normalizePath).filter(Boolean) : [];
          const nextFolders = savedFolders.length > 0 ? savedFolders : watcherFolders;
          setFolders(nextFolders);
          await syncWatcher(nextFolders, 'Watcher switched to the current signed-in user.');
          return;
        }
        if (Array.isArray(payload.folders) && payload.folders.length > 0) {
          setFolders(payload.folders);
          localStorage.setItem(foldersKey, JSON.stringify(payload.folders));
        } else if (folders.length > 0) {
          await syncWatcher(folders, 'Saved folders connected to the local watcher.');
        }
      } catch (error) {
        if (!active) return;
        await refreshWatcherStatus();
        setMessage(error?.message || 'Watcher is online, but settings could not be loaded.');
      }
    };

    loadWatcherSettings();
    const timer = setInterval(refreshWatcherStatus, 5000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [folders.length, foldersKey, userId]);

  const folderCountText = useMemo(() => {
    if (folders.length === 0) return 'No folders selected';
    if (folders.length === 1) return '1 folder monitored';
    return `${folders.length} folders monitored`;
  }, [folders.length]);

  const addFolder = async (event) => {
    event.preventDefault();
    const nextPath = normalizePath(folderPath);

    if (!nextPath) {
      setMessage('Enter a folder path first.');
      return;
    }

    const exists = folders.some((folder) => folder.toLowerCase() === nextPath.toLowerCase());
    if (exists) {
      setMessage('This folder is already in the monitored list.');
      return;
    }

    const nextFolders = [...folders, nextPath];
    setFolders(nextFolders);
    setFolderPath('');
    await syncWatcher(nextFolders, 'Folder added to monitoring list.');
  };

  const removeFolder = async (path) => {
    const nextFolders = folders.filter((folder) => folder !== path);
    setFolders(nextFolders);
    await syncWatcher(nextFolders, 'Folder removed from monitoring list.');
  };

  const clearFolders = async () => {
    setFolders([]);
    await syncWatcher([], 'Monitoring list cleared.');
  };

  const pickFolder = async () => {
    setIsPickingFolder(true);
    setMessage('Opening folder picker on this user device...');
    try {
      const response = await fetch(`${WATCHER_URL}/api/pick-folder`);
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload?.detail || 'Folder picker failed.');
      }

      const selectedPath = normalizePath(payload?.path);
      if (!selectedPath) {
        setMessage('Folder selection cancelled.');
        return;
      }

      setFolderPath(selectedPath);
      setMessage('Folder selected. Click Add to monitor it.');
      await refreshWatcherStatus();
    } catch (error) {
      setMessage(error?.message || `Start the local folder watcher at ${WATCHER_URL} to browse folders.`);
      setWatcherStatus({
        connected: false,
        last_error: error?.message || `Local folder watcher is not running at ${WATCHER_URL}.`,
      });
    } finally {
      setIsPickingFolder(false);
    }
  };

  return (
    <section className="page settings-page">
      <h2>Settings</h2>
      <p className="page-help">
        Add user-device folders that should be monitored for files to scan.
      </p>

      <div className="settings-grid">
        <article className="card settings-card">
          <h3>Folder Monitoring</h3>
          <div className="watcher-status-row">
            <span className={watcherStatus?.connected ? 'tag ok' : 'tag warn'}>
              {watcherStatus?.connected ? 'Watcher connected' : 'Watcher offline'}
            </span>
            <button type="button" className="btn subtle" onClick={refreshWatcherStatus}>Refresh</button>
          </div>
          <p className="scan-meta">
            Watcher API: {WATCHER_URL} | Cloud API: {API_BASE_URL}
          </p>
          {watcherStatus?.last_error && <p className="scan-message">{watcherStatus.last_error}</p>}

          <form className="settings-form" onSubmit={addFolder}>
            <label className="field-label" htmlFor="folderPathInput">Folder path</label>
            <div className="settings-input-row">
              <input
                id="folderPathInput"
                className="path-input"
                type="text"
                value={folderPath}
                onChange={(event) => setFolderPath(event.target.value)}
                placeholder="C:\\Users\\Name\\Downloads"
              />
              <button type="button" className="btn subtle" onClick={pickFolder} disabled={isPickingFolder}>
                {isPickingFolder ? 'Opening...' : 'Browse'}
              </button>
              <button type="submit" className="btn">Add</button>
            </div>
          </form>

          <div className="monitor-summary">
            <span className="tag ok">{folderCountText}</span>
            {folders.length > 0 && (
              <button type="button" className="btn subtle" onClick={clearFolders}>Clear All</button>
            )}
          </div>

          <div className="folder-list">
            {folders.length === 0 ? (
              <p className="muted-text">No monitored folders yet.</p>
            ) : (
              folders.map((folder) => (
                <div className="folder-row" key={folder}>
                  <div>
                    <p className="folder-path">{folder}</p>
                    <p className="scan-meta">Monitoring enabled</p>
                  </div>
                  <button type="button" className="btn danger" onClick={() => removeFolder(folder)}>
                    Remove
                  </button>
                </div>
              ))
            )}
          </div>

          {message && <p className="scan-message">{message}</p>}
        </article>

        <article className="card settings-card">
          <h3>User Details</h3>
          <div className="profile-list">
            <p><span>Name</span>{currentUser?.name || '-'}</p>
            <p><span>Email</span>{currentUser?.email || '-'}</p>
            <p><span>User ID</span>{userId}</p>
          </div>
        </article>

        <article className="card settings-card">
          <h3>Appearance</h3>
          <div className="theme-setting-row">
            <div>
              <p className="setting-title">Theme</p>
              <p className="muted-text">{theme === 'dark' ? 'Dark mode is active.' : 'Light mode is active.'}</p>
            </div>
            <button type="button" className="theme-toggle" onClick={onToggleTheme}>
              {theme === 'dark' ? 'Light mode' : 'Dark mode'}
            </button>
          </div>
        </article>
      </div>
    </section>
  );
}
