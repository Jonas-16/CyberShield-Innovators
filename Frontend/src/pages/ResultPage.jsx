import React, { useEffect, useMemo, useState } from 'react';

const API_BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000';
const CLEARED_RESULT_KEY = 'clearedResultMarker';
const LATEST_POLL_INTERVAL_MS = 5000;
const TERMINAL_POST_ACTIONS = new Set(['approved_via_result_page', 'rejected_via_result_page', 'deleted']);

function resultClass(result) {
  if (result === 'No file selected') return 'overall warn';
  if (result === 'Malicious') return 'overall bad';
  if (result === 'Suspicious') return 'overall warn';
  return 'overall safe';
}

function getErrorMessage(error) {
  if (error instanceof TypeError) {
    return `Cannot reach backend at ${API_BASE_URL}`;
  }
  return error?.message || 'Request failed';
}

function buildMarker(payload) {
  const base = payload?.scan_result && typeof payload.scan_result === 'object'
    ? {
        ...payload.scan_result,
        file_name: payload?.file_name || payload.scan_result?.file_name,
        path: payload?.staging_path || payload.scan_result?.path,
      }
    : payload;

  return `${base?.file_name || ''}:${base?.ts || ''}:${base?.post_action || ''}:${base?.path || ''}`;
}

function buildLatestPayload(payload) {
  return {
    file_name: payload.file_name,
    scan_result: payload,
    overall_result: payload.overall_result,
    status: payload.post_action || 'logged'
  };
}

function isTerminalPayload(payload) {
  return TERMINAL_POST_ACTIONS.has(payload?.post_action || '');
}

export default function ResultPage({ overallResult }) {
  const [fileInfo, setFileInfo] = useState(null);
  const [message, setMessage] = useState('');
  const [isBusy, setIsBusy] = useState(false);
  const [isManualUpload, setIsManualUpload] = useState(false);

  useEffect(() => {
    const raw = localStorage.getItem('latestSandboxFile');
    if (raw) {
      try {
        const parsed = JSON.parse(raw);
        setFileInfo(parsed);
        setIsManualUpload(true);
        return;
      } catch (_) {
        localStorage.removeItem('latestSandboxFile');
      }
    }

    const loadLatest = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/scan/latest`);
        if (!response.ok) return;
        const payload = await response.json();
        if (isTerminalPayload(payload)) {
          return;
        }
        const clearedMarker = localStorage.getItem(CLEARED_RESULT_KEY);
        const marker = buildMarker(payload);
        if (clearedMarker && clearedMarker === marker) {
          return;
        }
        setFileInfo(buildLatestPayload(payload));
        setIsManualUpload(false);
        setMessage(payload.message || '');
      } catch (_) {
        // ignore latest-result failures on initial render
      }
    };

    loadLatest();
  }, []);

  useEffect(() => {
    let active = true;

    const loadLatest = async () => {
      if (isManualUpload && fileInfo?.file_name) {
        return;
      }

      try {
        const response = await fetch(`${API_BASE_URL}/api/scan/latest`);
        if (!response.ok) return;

        const payload = await response.json();
        if (!active || isTerminalPayload(payload)) return;

        const clearedMarker = localStorage.getItem(CLEARED_RESULT_KEY);
        const marker = buildMarker(payload);
        if (clearedMarker && clearedMarker === marker) {
          return;
        }

        setFileInfo(buildLatestPayload(payload));
        setIsManualUpload(false);
        setMessage(payload.message || '');
      } catch (_) {
        // ignore polling failures and keep current UI state
      }
    };

    loadLatest();
    const timer = setInterval(loadLatest, LATEST_POLL_INTERVAL_MS);

    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [fileInfo?.file_name, isManualUpload]);

  useEffect(() => {
    const fileName = fileInfo?.file_name;
    if (!fileName || !isManualUpload) return;

    const refresh = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/scan/results/${encodeURIComponent(fileName)}`);
        if (response.status === 404) {
          localStorage.removeItem('latestSandboxFile');
          setFileInfo(null);
          setIsManualUpload(false);

          try {
            const latestResponse = await fetch(`${API_BASE_URL}/api/scan/latest`);
            if (latestResponse.ok) {
              const latestPayload = await latestResponse.json();
              if (isTerminalPayload(latestPayload)) {
                setMessage('No file is currently available in sandbox.');
                return;
              }
              const clearedMarker = localStorage.getItem(CLEARED_RESULT_KEY);
              const marker = buildMarker(latestPayload);
              if (!clearedMarker || clearedMarker !== marker) {
                setFileInfo(buildLatestPayload(latestPayload));
                setMessage(latestPayload.message || '');
                return;
              }
            }
          } catch (_) {
            // ignore latest-result fallback failure
          }

          setMessage('No file is currently available in sandbox.');
          return;
        }
        if (!response.ok) return;
        const payload = await response.json();
        setFileInfo(payload);
        setIsManualUpload(true);
        localStorage.setItem('latestSandboxFile', JSON.stringify(payload));
      } catch (_) {
        // keep cached result when backend is unavailable
      }
    };

    refresh();
  }, [fileInfo?.file_name, isManualUpload]);

  const scan = fileInfo?.scan_result || null;
  const hasFile = Boolean(fileInfo?.file_name);
  const postAction = scan?.post_action || null;
  const risk = typeof scan?.fused_risk === 'number' ? scan.fused_risk : null;
  const score = !hasFile ? null : (risk === null ? 50 : Math.max(1, Math.min(99, Math.round((1 - risk) * 100))));
  const resultText = hasFile ? (fileInfo?.overall_result || overallResult) : 'No file selected';
  const warningText = scan?.scanner_warning
    ? 'ML engine is unavailable; running heuristic fallback mode.'
    : '';
  const isActiveSandboxReview = Boolean(
    hasFile &&
    !isManualUpload &&
    scan?.source === 'download-monitor' &&
    postAction === 'manual_review_required'
  );
  const showSaveButton = hasFile && !isManualUpload && postAction !== 'auto_saved_safe' && postAction !== 'auto_deleted_blocked';
  const showDeleteButton = hasFile && ((!isManualUpload && postAction !== 'auto_saved_safe' && postAction !== 'auto_deleted_blocked') || (isManualUpload && !postAction && resultText !== 'Safe'));
  const showClearButton = hasFile;
  const canDelete = showDeleteButton;

  const tags = useMemo(() => {
    if (!scan) {
      return ['Sandbox: Pending', 'Threat Pattern: Pending', 'Hidden Data: Pending', 'Adversarial Check: Pending'];
    }

    const decisionTag = `Sandbox: ${scan.decision || 'UNCERTAIN'}`;
    const engineTag = `Engine: ${scan.engine || 'unknown'}`;
    const riskTag = risk === null ? 'Risk: N/A' : `Risk: ${(risk * 100).toFixed(2)}%`;
    const warnTag = scan.scanner_warning ? 'Model: Fallback mode' : 'Model: Active';
    return [decisionTag, engineTag, riskTag, warnTag];
  }, [scan, risk]);

  const clearCurrentResult = (nextMessage) => {
    const marker = buildMarker(scan || fileInfo || {});
    if (marker !== ':::') {
      localStorage.setItem(CLEARED_RESULT_KEY, marker);
    }
    localStorage.removeItem('latestSandboxFile');
    setFileInfo(null);
    setIsManualUpload(false);
    setMessage(nextMessage);
  };

  const saveFile = async () => {
    if (!fileInfo?.file_name) {
      setMessage('No sandbox file available. Upload from Scan Page first.');
      return;
    }

    setIsBusy(true);
    setMessage('Preparing file for save...');

    try {
      const response = await fetch(`${API_BASE_URL}/api/scan/files/${encodeURIComponent(fileInfo.file_name)}`);
      if (!response.ok) {
        const payload = await response.json();
        throw new Error(payload?.detail || 'Failed to fetch file');
      }

      const blob = await response.blob();
      if (window.showSaveFilePicker) {
        const handle = await window.showSaveFilePicker({ suggestedName: fileInfo.file_name });
        const writable = await handle.createWritable();
        await writable.write(blob);
        await writable.close();
      } else {
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = fileInfo.file_name;
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        URL.revokeObjectURL(url);
      }

      if (isActiveSandboxReview) {
        const approveResponse = await fetch(`${API_BASE_URL}/api/scan/files/${encodeURIComponent(fileInfo.file_name)}/approve`, {
          method: 'POST'
        });
        if (!approveResponse.ok) {
          const payload = await approveResponse.json();
          throw new Error(payload?.detail || 'Failed to approve file');
        }
        clearCurrentResult('File saved, removed from the sandbox, and the sandbox session will now close.');
        return;
      }

      const deleteResponse = await fetch(`${API_BASE_URL}/api/scan/files/${encodeURIComponent(fileInfo.file_name)}`, { method: 'DELETE' });
      if (!deleteResponse.ok) {
        const payload = await deleteResponse.json();
        throw new Error(payload?.detail || 'Failed to remove file after save');
      }

      clearCurrentResult('File saved and removed from sandbox.');
    } catch (error) {
      setMessage(getErrorMessage(error));
    } finally {
      setIsBusy(false);
    }
  };

  const deleteFile = async () => {
    if (!fileInfo?.file_name) {
      setMessage('No sandbox file available to delete.');
      return;
    }

    setIsBusy(true);
    setMessage('Deleting file from sandbox...');

    try {
      if (isActiveSandboxReview) {
        const response = await fetch(`${API_BASE_URL}/api/scan/files/${encodeURIComponent(fileInfo.file_name)}/reject`, {
          method: 'POST'
        });
        const payload = await response.json();
        if (!response.ok) {
          throw new Error(payload?.detail || 'Reject failed');
        }
        clearCurrentResult(`Deleted: ${payload.file_name}. The sandbox session will now close.`);
        return;
      }

      const response = await fetch(`${API_BASE_URL}/api/scan/files/${encodeURIComponent(fileInfo.file_name)}`, {
        method: 'DELETE'
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload?.detail || 'Delete failed');
      }

      clearCurrentResult(
        isManualUpload
          ? `Deleted sandbox copy: ${payload.file_name}. Original uploaded file remains in its source folder.`
          : `Deleted: ${payload.file_name}`
      );
    } catch (error) {
      setMessage(getErrorMessage(error));
    } finally {
      setIsBusy(false);
    }
  };

  const clearResults = () => {
    clearCurrentResult('Results cleared.');
  };

  return (
    <section className="page">
      <h2>Result Page</h2>
      <p className="page-help">This page tells you clearly if your file is safe or not.</p>

      <div className="result-grid">
        <article className="card result-main">
          <h3>Safety Score</h3>
          <p className="score">
            {score === null ? '--' : score} <span>/100</span>
          </p>
          <p className={resultClass(resultText)}>Result: {resultText}</p>
          <p className="muted-text">Higher score means lower risk.</p>
        </article>

        <article className="card result-layers">
          <h3>What We Checked</h3>
          <div className="tag-list">
            {tags.map((tag) => (
              <span key={tag} className="tag ok">{tag}</span>
            ))}
          </div>
          {warningText && <p className="scan-message">{warningText}</p>}
        </article>
      </div>

      <div className="action-row">
        {showSaveButton && (
          <button type="button" className="btn" onClick={saveFile} disabled={isBusy || !hasFile}>Save</button>
        )}
        {showClearButton && (
          <button type="button" className="btn" onClick={clearResults} disabled={isBusy}>Clear Results</button>
        )}
        {showDeleteButton && (
          <button type="button" className="btn danger" onClick={deleteFile} disabled={isBusy || !canDelete}>Delete</button>
        )}
      </div>
      {fileInfo?.file_name && <p className="scan-file">Sandbox file: {fileInfo.file_name}</p>}
      {isActiveSandboxReview && (
        <p className="scan-message">Save will store the file in a folder you choose, remove it from the sandbox, and then close the sandbox. Delete will reject it and close the sandbox.</p>
      )}
      {message && <p className="scan-message">{message}</p>}
    </section>
  );
}


