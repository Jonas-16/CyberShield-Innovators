import React, { useEffect, useMemo, useState } from 'react';

const API_BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000';
const LATEST_SCAN_JOB_KEY = 'latestScanJob';

function isPendingResult(payload) {
  return payload?.status === 'processing' || payload?.status === 'queued';
}

function getStatusMessage(payload) {
  if (!payload) return '';
  if (payload?.status === 'ignored') {
    return payload?.message || 'Unsupported file type.';
  }
  if (payload?.status === 'failed') {
    return `Scan failed: ${payload?.file_name || 'file'}`;
  }
  if (isPendingResult(payload)) {
    return payload?.message || `Queued ${payload?.file_name || 'file'} for sandbox review...`;
  }
  return `Scan completed: ${payload?.file_name || 'file'}`;
}

function formatPercent(value) {
  return typeof value === 'number' ? `${(value * 100).toFixed(2)}%` : '-';
}

function buildDetailRows(result) {
  const scan = result?.scan_result || null;
  if (!scan) return [];

  const reasons = Array.isArray(scan?.reasons) ? scan.reasons.filter(Boolean).join(', ') : '';
  return [
    { label: 'Overall Result', value: result?.overall_result || '-' },
    { label: 'Decision', value: scan?.decision || '-' },
    { label: 'Engine', value: scan?.engine || '-' },
    { label: 'Risk Score', value: typeof scan?.fused_risk === 'number' ? formatPercent(scan.fused_risk) : '-' },
    { label: 'Static Score', value: typeof scan?.static_prob === 'number' ? formatPercent(scan.static_prob) : '-' },
    { label: 'Prediction', value: scan?.predicted_label || '-' },
    { label: 'Confidence', value: formatPercent(scan?.confidence) },
    { label: 'Stego Probability', value: formatPercent(scan?.stego_prob) },
    { label: 'Cover Probability', value: formatPercent(scan?.cover_prob) },
    { label: 'Scanner Stage', value: scan?.scanner_stage || '-' },
    { label: 'Reasons', value: reasons || '-' },
  ].filter((item) => item.value !== '-');
}

export default function ScanPage() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [message, setMessage] = useState('');
  const [result, setResult] = useState(null);
  const [scanId, setScanId] = useState(null);

  useEffect(() => {
    const raw = localStorage.getItem(LATEST_SCAN_JOB_KEY);
    if (!raw) {
      return;
    }

    try {
      const payload = JSON.parse(raw);
      setSelectedFile({ name: payload.file_name });
      setResult(payload);
      setScanId(payload.scan_id || null);
      setMessage(getStatusMessage(payload));
    } catch (_) {
      // Ignore malformed cached payloads.
    }
  }, []);


  useEffect(() => {
    if (!scanId || !isPendingResult(result)) {
      return;
    }

    let active = true;

    const poll = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/scan/jobs/${encodeURIComponent(scanId)}`);
        if (!response.ok) return;
        const payload = await response.json();
        if (!active) {
          return;
        }

        if (isPendingResult(payload)) {
          setResult(payload);
          localStorage.setItem(LATEST_SCAN_JOB_KEY, JSON.stringify(payload));
          setMessage(payload?.message || `Waiting for remote review of ${payload?.file_name || 'file'}...`);
          return;
        }

        localStorage.setItem(LATEST_SCAN_JOB_KEY, JSON.stringify(payload));
        setResult(payload);
        setMessage(getStatusMessage(payload));
      } catch (_) {
        // keep current state during polling failures
      }
    };

    poll();
    const timer = setInterval(poll, 2000);

    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [result?.file_name, result?.status]);

  const currentStep = useMemo(() => {
    if (isUploading) return 2;
    if (isPendingResult(result)) return 4;
    if (result) return 6;
    if (selectedFile) return 1;
    return 0;
  }, [isUploading, result, selectedFile]);

  const scanDetails = useMemo(() => {
    return buildDetailRows(result);
  }, [result]);

  const handleFileChange = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setSelectedFile({ name: file.name });
    setResult(null);
      setMessage('Uploading file into the sandbox queue...');
    setIsUploading(true);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch(`${API_BASE_URL}/api/scan/upload`, {
        method: 'POST',
        body: formData
      });

      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload?.detail || 'Upload failed');
      }

      localStorage.setItem(LATEST_SCAN_JOB_KEY, JSON.stringify(payload));
      setResult(payload);
      setScanId(payload.scan_id || null);
      setMessage(getStatusMessage(payload));
    } catch (error) {
      const isNetworkError = error instanceof TypeError && String(error.message || '').toLowerCase().includes('fetch');
      if (isNetworkError) {
        setMessage(`Cannot reach backend at ${API_BASE_URL}. Start FastAPI server and retry.`);
      } else {
        setMessage(error.message || 'Upload failed');
      }
      setResult(null);
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <section className="page">
      <h2>Scan Page</h2>
      <p className="page-help">
        This laptop is the client. Uploaded files are sent to the remote scanning laptop for analysis and the result is polled back here.
      </p>

      <div className="card upload-card">
        <h3>Remote File Check</h3>
        <label htmlFor="scanFileInput" className="upload-dropzone">
          <span>{isUploading ? 'Queueing...' : 'Click here to choose a file'}</span>
          <span className="muted">The file is uploaded to Laptop 2, scanned there, and the report is returned here.</span>
          <input id="scanFileInput" type="file" onChange={handleFileChange} disabled={isUploading} />
        </label>
        {selectedFile && <p className="scan-file">Selected: {selectedFile.name}</p>}
        {message && <p className="scan-message">{message}</p>}
        {scanId && <p className="scan-meta">Scan ID: {scanId}</p>}
        {result?.staging_path && <p className="scan-meta">Staging path: {result.staging_path}</p>}
        {scanDetails.length > 0 && (
          <div className="scan-detail-list">
            {scanDetails.map((detail) => (
              <p key={detail.label} className="scan-meta">
                {detail.label}: {detail.value}
              </p>
            ))}
          </div>
        )}
      </div>

      <ol className="step-list">
        <li className={`step ${currentStep >= 1 ? 'done' : ''}`}>1. File Detected</li>
        <li className={`step ${currentStep >= 2 ? (currentStep === 2 ? 'current' : 'done') : ''}`}>2. Upload Received</li>
        <li className={`step ${currentStep >= 3 ? (currentStep === 3 ? 'current' : 'done') : ''}`}>3. Preparing Scan</li>
        <li className={`step ${currentStep >= 4 ? (currentStep === 4 ? 'current' : 'done') : ''}`}>4. Running Scanner</li>
        <li className={`step ${currentStep >= 5 ? (currentStep === 5 ? 'current' : 'done') : ''}`}>5. Finalizing Result</li>
        <li className={`step ${currentStep >= 6 ? 'done' : ''}`}>6. Scan Completed</li>
      </ol>
    </section>
  );
}


