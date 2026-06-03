import React, { useEffect, useMemo, useState } from 'react';
import { scopedKey } from '../auth';

const API_BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000';
const WATCHER_URL = import.meta.env.VITE_WATCHER_URL || 'http://127.0.0.1:8765';
const LATEST_SCAN_KEY = 'latestCloudScan';

function isPendingResult(payload) {
  return payload?.status === 'processing' || payload?.status === 'queued';
}

function isCloudUpload(payload) {
  if (!payload) return false;
  return ['cloud-upload', 'manual-upload', 'cloud-sandbox-upload'].includes(payload?.source);
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
    return payload?.message || `Scanning ${payload?.file_name || 'file'} on the backend...`;
  }
  return `Scan completed: ${payload?.file_name || 'file'}`;
}

function formatPercent(value) {
  return typeof value === 'number' ? `${(value * 100).toFixed(2)}%` : '-';
}

function resultText(scan, fallbackResult) {
  const risk = typeof scan?.fused_risk === 'number' ? scan.fused_risk : null;
  const stegoThreshold = typeof scan?.stego_threshold === 'number' ? scan.stego_threshold : 0.7;
  const unsafeThreshold = typeof scan?.unsafe_threshold === 'number' ? scan.unsafe_threshold : 0.8;
  const prediction = String(scan?.predicted_label || '').toLowerCase();
  const decision = String(scan?.decision || '').toUpperCase();

  if (decision === 'BLOCKED') return 'Malicious';
  if (risk !== null && risk >= unsafeThreshold) return 'Suspicious';
  if (risk !== null && risk >= stegoThreshold) return 'Review';
  if (prediction === 'stego') return 'Review';
  if (['STEGO', 'UNCERTAIN'].includes(decision)) return 'Review';
  if (['PENDING', 'IGNORED'].includes(decision)) return 'Suspicious';
  if (prediction === 'cover' || decision === 'ALLOWED' || decision === 'COVER') return 'Safe';
  return fallbackResult || '-';
}

function formatSafetyScore(scan, status) {
  const risk = typeof scan?.fused_risk === 'number' ? scan.fused_risk : null;
  if (risk === null) return '-';

  const rawSafety = 1 - risk;
  let score = Math.max(0, Math.min(100, Math.round(rawSafety * 100)));
  if (status === 'Review') score = Math.min(score, 79);
  if (status === 'Suspicious') score = Math.min(score, 69);
  if (status === 'Malicious') score = Math.min(score, 30);
  return `${score} / 100`;
}

function absoluteReportUrl(url) {
  if (!url) return '';
  if (url.startsWith('http://') || url.startsWith('https://')) return url;
  return `${API_BASE_URL}${url}`;
}

function downloadUrl(url) {
  const absolute = absoluteReportUrl(url);
  if (!absolute) return '';
  const separator = absolute.includes('?') ? '&' : '?';
  return `${absolute}${separator}download=true`;
}

function buildDetailRows(result) {
  const scan = result?.scan_result || null;
  if (!scan) return [];

  const reasons = Array.isArray(scan?.reasons) ? scan.reasons.filter(Boolean).join(', ') : '';
  const status = resultText(scan, result?.overall_result);
  const decoder = scan?.stego_decoder || null;
  const apkAnalysis = scan?.apk_static_analysis || null;
  return [
    { label: 'Overall Result', value: status },
    { label: 'Safety Score', value: formatSafetyScore(scan, status) },
    { label: 'Decision', value: scan?.decision || '-' },
    { label: 'Engine', value: scan?.engine || '-' },
    { label: 'Risk Score', value: typeof scan?.fused_risk === 'number' ? formatPercent(scan.fused_risk) : '-' },
    { label: 'APK Malware Probability', value: formatPercent(scan?.apk_malware_prob) },
    { label: 'APK Benign Probability', value: formatPercent(scan?.apk_benign_prob) },
    { label: 'APK Structural Risk', value: formatPercent(scan?.apk_structural_risk) },
    { label: 'APK Evidence Level', value: apkAnalysis?.evidence_level || '-' },
    { label: 'APK DEX Files', value: apkAnalysis ? String(apkAnalysis.dex_count ?? 0) : '-' },
    { label: 'APK Certificate Files', value: apkAnalysis ? String(apkAnalysis.certificate_file_count ?? 0) : '-' },
    { label: 'Prediction', value: scan?.predicted_label || '-' },
    { label: 'Confidence', value: formatPercent(scan?.confidence) },
    { label: 'Stego Probability', value: formatPercent(scan?.stego_prob) },
    { label: 'Cover Probability', value: formatPercent(scan?.cover_prob) },
    { label: 'Scanner Stage', value: scan?.scanner_stage || '-' },
    { label: 'Decoder Status', value: decoder?.skipped ? (decoder.reason || 'No decode needed for this file.') : '-' },
    { label: 'Readable Hidden Message', value: decoder ? (decoder.readable_message_found ? 'Yes' : 'No') : '-' },
    { label: 'Decoder Candidates', value: decoder ? String(decoder.candidate_count ?? 0) : '-' },
    { label: 'Reasons', value: reasons || '-' },
  ].filter((item) => item.value !== '-');
}

async function loadDeviceInfo() {
  try {
    const response = await fetch(`${WATCHER_URL}/api/device`);
    if (!response.ok) return null;
    return response.json();
  } catch (_) {
    return null;
  }
}

function uploadUrl(userId, deviceInfo) {
  const params = new URLSearchParams({ user_id: userId });
  if (deviceInfo?.device_id) params.set('device_id', deviceInfo.device_id);
  if (deviceInfo?.device_name) params.set('device_name', deviceInfo.device_name);
  if (deviceInfo?.os_name) params.set('os_name', deviceInfo.os_name);
  if (deviceInfo?.os_version) params.set('os_version', deviceInfo.os_version);
  if (deviceInfo?.machine) params.set('machine', deviceInfo.machine);
  return `${API_BASE_URL}/api/scan/upload?${params.toString()}`;
}

export default function ScanPage({ currentUser }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [message, setMessage] = useState('');
  const [result, setResult] = useState(null);
  const userId = currentUser?.id || 'guest';
  const latestScanKey = scopedKey(LATEST_SCAN_KEY, userId);

  useEffect(() => {
    const raw = localStorage.getItem(latestScanKey);
    if (!raw) {
      return;
    }

    try {
      const payload = JSON.parse(raw);
      if (!isCloudUpload(payload)) {
        return;
      }

      setSelectedFile({ name: payload.file_name });
      setResult(payload);
      setMessage(getStatusMessage(payload));
    } catch (_) {
      // Ignore malformed cached payloads.
    }
  }, [latestScanKey]);


  useEffect(() => {
    const fileName = result?.file_name;
    if (!fileName || !isPendingResult(result) || !isCloudUpload(result)) {
      return;
    }

    let active = true;

    const poll = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/scan/latest?user_id=${encodeURIComponent(userId)}`);
        if (!response.ok) return;
        const payload = await response.json();
        if (!active) {
          return;
        }

        const latestFileName = payload?.file_name || payload?.scan_result?.file_name;
        if (latestFileName !== fileName) {
          setMessage(`Waiting for backend scan of ${fileName}...`);
          return;
        }

        if (isPendingResult(payload)) {
          setMessage(payload?.message || `Waiting for backend scan of ${fileName}...`);
          return;
        }

        localStorage.setItem(latestScanKey, JSON.stringify(payload));
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
  }, [result?.file_name, result?.status, latestScanKey, userId]);

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
  const decoderReportUrl = absoluteReportUrl(result?.scan_result?.stego_decoder?.report_url);
  const cleanImageUrl = absoluteReportUrl(result?.scan_result?.stego_decoder?.sanitized_image?.url);
  const cleanImageDownloadUrl = downloadUrl(result?.scan_result?.stego_decoder?.sanitized_image?.url);

  const handleFileChange = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setSelectedFile({ name: file.name });
    setResult(null);
    setMessage('Uploading file to the backend scanner...');
    setIsUploading(true);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const deviceInfo = await loadDeviceInfo();
      const response = await fetch(uploadUrl(userId, deviceInfo), {
        method: 'POST',
        body: formData
      });

      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload?.detail || 'Upload failed');
      }

      localStorage.setItem(latestScanKey, JSON.stringify(payload));
      setResult(payload);
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
        Select a file on {currentUser?.name}'s laptop. The app will scan the file and show the result here.
      </p>

      <div className="card upload-card">
        <h3>Manual File Check</h3>
        <label htmlFor="scanFileInput" className="upload-dropzone">
          <span>{isUploading ? 'Uploading...' : 'Click here to choose a file'}</span>
          <span className="muted">Uploaded files are scanned on the backend machine.</span>
          <input id="scanFileInput" type="file" onChange={handleFileChange} disabled={isUploading} />
        </label>
        {selectedFile && <p className="scan-file">Selected: {selectedFile.name}</p>}
        {message && <p className="scan-message">{message}</p>}
        {result?.staging_path && <p className="scan-meta">Backend file path: {result.staging_path}</p>}
        {cleanImageUrl && (
          <p className="scan-message">
            Cleaned image ready: <a href={cleanImageDownloadUrl}>Download image with embedded data removed</a>
          </p>
        )}
        {decoderReportUrl && (
          <p className="scan-message">
            <a href={decoderReportUrl} target="_blank" rel="noreferrer">Show decoded data report</a>
          </p>
        )}
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
