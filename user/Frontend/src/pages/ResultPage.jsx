import React, { useEffect, useMemo, useState } from 'react';

const API_BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000';
const CLEARED_RESULT_KEY = 'clearedResultMarker';
const LATEST_SCAN_KEY = 'latestCloudScan';
const LATEST_POLL_INTERVAL_MS = 5000;
const TERMINAL_POST_ACTIONS = new Set(['approved_via_result_page', 'rejected_via_result_page', 'deleted']);

function resultClass(result) {
  if (result === 'No file selected') return 'overall warn';
  if (result === 'Malicious') return 'overall bad';
  if (result === 'Suspicious') return 'overall warn';
  return 'overall safe';
}

function tagTone(tag) {
  const value = String(tag || '').toLowerCase();
  const riskMatch = value.match(/risk(?: score)?:\s*(\d+(?:\.\d+)?)%/);
  if (riskMatch) {
    const riskPercent = Number(riskMatch[1]);
    if (riskPercent >= 70) return 'bad';
    if (riskPercent >= 40) return 'warn';
    return 'ok';
  }
  if (value.includes('malicious')) return 'bad';
  if (value.includes('suspicious') || value.includes('uncertain') || value.includes('fallback')) return 'warn';
  return 'ok';
}

function getErrorMessage(error) {
  if (error?.name === 'AbortError') {
    return 'Save cancelled.';
  }
  if (error instanceof TypeError) {
    return `Cannot reach backend at ${API_BASE_URL}`;
  }
  return error?.message || 'Request failed';
}

async function saveBlobWithPicker(blob, fileName) {
  if (window.showSaveFilePicker) {
    const handle = await window.showSaveFilePicker({ suggestedName: fileName });
    const writable = await handle.createWritable();
    await writable.write(blob);
    await writable.close();
    return;
  }

  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = fileName;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function buildMarker(payload) {
  const base = payload?.scan_result && typeof payload.scan_result === 'object'
    ? {
        ...payload.scan_result,
        file_name: payload?.file_name || payload.scan_result?.file_name,
        path: payload.scan_result?.path || payload?.staging_path,
      }
    : payload;

  return `${base?.file_name || ''}:${base?.ts || ''}:${base?.post_action || ''}:${base?.path || ''}`;
}

function buildLatestPayload(payload) {
  if (payload?.scan_result || payload?.status) {
    return payload;
  }

  return {
    file_name: payload.file_name,
    scan_result: payload,
    overall_result: payload.overall_result,
    status: payload.post_action || 'logged',
    source: payload.source || 'download-monitor',
    ts: payload.ts,
  };
}

function payloadPostAction(payload) {
  return payload?.post_action || payload?.scan_result?.post_action || '';
}

function isTerminalPayload(payload) {
  return TERMINAL_POST_ACTIONS.has(payloadPostAction(payload));
}

function isDirectBackendUpload(payload) {
  return payload?.source === 'manual-upload' || payload?.source === 'cloud-upload';
}

function isPendingPayload(payload) {
  return payload?.status === 'processing' || payload?.status === 'queued';
}

function getResultText(scan, fallbackResult) {
  const suffix = String(scan?.file_name || scan?.path || '').toLowerCase().split('.').pop();
  const isImage = ['jpg', 'jpeg', 'jfif', 'png', 'bmp', 'gif', 'tif', 'tiff', 'webp'].includes(suffix);
  const prediction = String(scan?.predicted_label || '').toLowerCase();
  const decision = String(scan?.decision || '').toUpperCase();
  const engine = String(scan?.engine || '').toLowerCase();
  const warning = String(scan?.scanner_warning || '');
  const risk = typeof scan?.fused_risk === 'number' ? scan.fused_risk : null;
  const stegoThreshold = typeof scan?.stego_threshold === 'number' ? scan.stego_threshold : 0.7;
  const reasons = Array.isArray(scan?.reasons) ? scan.reasons.map((reason) => String(reason).toLowerCase()) : [];

  if (prediction === 'stego') return 'Suspicious';
  if (risk !== null && risk >= stegoThreshold) return 'Suspicious';
  if (isImage && engine && engine !== 'stg-ml') return 'Suspicious';
  if (decision === 'BLOCKED') return 'Malicious';
  if (decision === 'STEGO') return 'Suspicious';
  if (warning || (engine === 'heuristic' && reasons.some((reason) => reason.includes('could not inspect')))) {
    return 'Suspicious';
  }
  return fallbackResult || 'Safe';
}

function getDecisionLabel(scan, result) {
  if (!scan) return '-';
  const decision = String(scan?.decision || '').toUpperCase();
  if (result === 'Suspicious' && decision === 'ALLOWED') return 'Suspicious';
  if (decision === 'ALLOWED') return 'Safe';
  if (decision === 'BLOCKED') return 'Malicious';
  return decision || '-';
}

function computeSafetyScore(scan, result) {
  if (!scan) return null;
  const risk = typeof scan?.fused_risk === 'number' ? scan.fused_risk : null;
  if (risk === null) return result === 'Safe' ? 50 : 40;

  const rawSafety = 1 - risk;
  let score = Math.max(0, Math.min(100, Math.round(rawSafety * 100)));
  if (result === 'Suspicious') score = Math.min(score, 69);
  if (result === 'Malicious') score = Math.min(score, 30);
  return score;
}

function formatRiskPercent(risk) {
  if (typeof risk !== 'number') return 'N/A';
  const riskPercent = Math.max(0, Math.min(100, risk * 100));
  return `${riskPercent.toFixed(2)}%`;
}

export default function ResultPage({ overallResult }) {
  const [fileInfo, setFileInfo] = useState(null);
  const [message, setMessage] = useState('');
  const [isBusy, setIsBusy] = useState(false);
  const [isManualUpload, setIsManualUpload] = useState(false);

  useEffect(() => {
    const raw = localStorage.getItem(LATEST_SCAN_KEY);
    if (raw) {
      try {
        const parsed = JSON.parse(raw);
        setFileInfo(parsed);
        setIsManualUpload(isDirectBackendUpload(parsed));
        return;
      } catch (_) {
        localStorage.removeItem(LATEST_SCAN_KEY);
      }
    }

    const loadLatest = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/scan/latest`);
        if (!response.ok) return;
        const payload = await response.json();
        if (isTerminalPayload(payload)) return;
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
        if (!active) return;
        if (isTerminalPayload(payload)) return;

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
          localStorage.removeItem(LATEST_SCAN_KEY);
          setFileInfo(null);
          setIsManualUpload(false);

          try {
            const latestResponse = await fetch(`${API_BASE_URL}/api/scan/latest`);
            if (latestResponse.ok) {
              const latestPayload = await latestResponse.json();
              if (isTerminalPayload(latestPayload)) {
                setMessage('No cloud scan result is currently available.');
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

          setMessage('No cloud scan result is currently available.');
          return;
        }
        if (!response.ok) return;
        const payload = await response.json();
        if (isTerminalPayload(payload)) {
          localStorage.removeItem(LATEST_SCAN_KEY);
          setFileInfo(null);
          setIsManualUpload(false);
          setMessage('No cloud scan result is currently available.');
          return;
        }
        setFileInfo(payload);
        setIsManualUpload(isDirectBackendUpload(payload));
        localStorage.setItem(LATEST_SCAN_KEY, JSON.stringify(payload));
      } catch (_) {
        // keep cached result when backend is unavailable
      }
    };

    refresh();
    const timer = setInterval(refresh, 2000);

    return () => clearInterval(timer);
  }, [fileInfo?.file_name, isManualUpload]);

  const scan = fileInfo?.scan_result || null;
  const hasFile = Boolean(fileInfo?.file_name);
  const isProcessing = isPendingPayload(fileInfo);
  const postAction = scan?.post_action || null;
  const isTerminalResult = isTerminalPayload(fileInfo);
  const risk = typeof scan?.fused_risk === 'number' ? scan.fused_risk : null;
  const resultText = !hasFile ? 'No file selected' : (isProcessing ? 'Processing' : getResultText(scan, fileInfo?.overall_result || overallResult));
  const safetyScore = !hasFile || isProcessing ? null : computeSafetyScore(scan, resultText);
  const warningText = scan?.scanner_warning
    ? 'ML engine is unavailable; running heuristic fallback mode.'
    : '';
  const isActiveSandboxReview = Boolean(
    hasFile &&
    !isManualUpload &&
    postAction === 'manual_review_required'
  );
  const showSaveButton = hasFile && !isProcessing && !isTerminalResult && !isManualUpload && postAction !== 'auto_saved_safe' && postAction !== 'auto_deleted_blocked';
  const showDeleteButton = hasFile && !isProcessing && !isTerminalResult && ((!isManualUpload && postAction !== 'auto_saved_safe' && postAction !== 'auto_deleted_blocked') || (isManualUpload && !postAction));
  const showClearButton = hasFile;
  const canDelete = showDeleteButton;

  const tags = useMemo(() => {
    if (!scan) {
      return ['Decision: Pending', 'Threat Pattern: Pending', 'Hidden Data: Pending', 'Adversarial Check: Pending'];
    }

    const decisionTag = `Decision: ${getDecisionLabel(scan, resultText)}`;
    const engineTag = `Engine: ${scan.engine || 'unknown'}`;
    const riskTag = `Risk Score: ${formatRiskPercent(risk)}`;
    const warnTag = scan.scanner_warning ? 'Model: Fallback mode' : 'Model: Active';
    return [decisionTag, engineTag, riskTag, warnTag];
  }, [scan, risk, resultText]);

  const saveFile = async () => {
    if (!fileInfo?.file_name) {
      setMessage('No scanned file available. Upload from Scan Page first.');
      return;
    }

    setIsBusy(true);
    setMessage('Choose where to save the file...');

    try {
      const response = await fetch(`${API_BASE_URL}/api/scan/files/${encodeURIComponent(fileInfo.file_name)}`);
      if (!response.ok) {
        const payload = await response.json();
        throw new Error(payload?.detail || 'Failed to fetch file');
      }

      const blob = await response.blob();
      await saveBlobWithPicker(blob, fileInfo.file_name);

      if (isActiveSandboxReview) {
        const approveResponse = await fetch(`${API_BASE_URL}/api/scan/files/${encodeURIComponent(fileInfo.file_name)}/approve?restore_to_downloads=false`, {
          method: 'POST'
        });
        if (!approveResponse.ok) {
          const payload = await approveResponse.json();
          throw new Error(payload?.detail || 'Failed to approve file');
        }
        localStorage.removeItem(LATEST_SCAN_KEY);
        setFileInfo(null);
        setIsManualUpload(false);
        setMessage('File saved, approved, and removed from sandbox. The sandbox session will now close.');
        return;
      }

      const deleteResponse = await fetch(`${API_BASE_URL}/api/scan/files/${encodeURIComponent(fileInfo.file_name)}`, { method: 'DELETE' });
      if (!deleteResponse.ok) {
        const payload = await deleteResponse.json();
        throw new Error(payload?.detail || 'Failed to remove file after save');
      }
      localStorage.removeItem(LATEST_SCAN_KEY);
      setFileInfo(null);
      setIsManualUpload(false);
      setMessage('File saved and removed from sandbox.');
    } catch (error) {
      setMessage(getErrorMessage(error));
    } finally {
      setIsBusy(false);
    }
  };

  const deleteFile = async () => {
    if (!fileInfo?.file_name) {
      setMessage('No cloud copy available to delete.');
      return;
    }

    setIsBusy(true);
    setMessage('Deleting backend copy...');

    try {
      const actionPath = isActiveSandboxReview
        ? `/api/scan/files/${encodeURIComponent(fileInfo.file_name)}/reject`
        : `/api/scan/files/${encodeURIComponent(fileInfo.file_name)}`;
      const response = await fetch(`${API_BASE_URL}${actionPath}`, {
        method: isActiveSandboxReview ? 'POST' : 'DELETE'
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload?.detail || 'Delete failed');
      }

      const marker = buildMarker(fileInfo);
      if (marker !== ':::') {
        localStorage.setItem(CLEARED_RESULT_KEY, marker);
      }
      localStorage.removeItem(LATEST_SCAN_KEY);
      setFileInfo(null);
      setIsManualUpload(false);
      setMessage(
        isManualUpload
          ? `Deleted backend copy: ${payload.file_name}. Original file remains on the user machine.`
          : `Deleted: ${payload.file_name}`
      );
    } catch (error) {
      setMessage(getErrorMessage(error));
    } finally {
      setIsBusy(false);
    }
  };

  const clearResults = () => {
    const marker = buildMarker(fileInfo || scan || {});
    if (marker !== ':::') {
      localStorage.setItem(CLEARED_RESULT_KEY, marker);
    }
    localStorage.removeItem(LATEST_SCAN_KEY);
    setFileInfo(null);
    setIsManualUpload(false);
    setMessage('Results cleared.');
  };

  return (
    <section className="page">
      <h2>Result Page</h2>
      <p className="page-help">This page shows the file safety score with its risk percentage.</p>

      <div className="result-grid">
        <article className="card result-main">
          <h3>Safety Score</h3>
          <p className="score">
            {safetyScore === null ? '--' : Math.round(safetyScore)} <span>/100</span>
          </p>
          <p className={resultClass(resultText)}>Result: {resultText}</p>
          <p className="muted-text">Risk: {formatRiskPercent(risk)}</p>
        </article>

        <article className="card result-layers">
          <h3>What We Checked</h3>
          <div className="tag-list">
            {tags.map((tag) => (
              <span key={tag} className={`tag ${tagTone(tag)}`}>{tag}</span>
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
      {fileInfo?.file_name && <p className="scan-file">Scanned file: {fileInfo.file_name}</p>}
      {message && <p className="scan-message">{message}</p>}
    </section>
  );
}
