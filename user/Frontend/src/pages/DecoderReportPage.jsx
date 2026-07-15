import React, { useEffect, useMemo, useState } from 'react';
import { scopedKey } from '../auth';

const API_BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000';
const LATEST_SCAN_KEY = 'latestCloudScan';
const LATEST_POLL_INTERVAL_MS = 5000;

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

function assetUrl(decoder, fileName) {
  if (!decoder?.report_id || !fileName) return '';
  return absoluteReportUrl(`/api/scan/reports/${encodeURIComponent(decoder.report_id)}/${encodeURIComponent(fileName)}`);
}

function decoderFromPayload(payload) {
  const scan = payload?.scan_result || payload || {};
  return scan?.stego_decoder || null;
}

function summaryRows(decoder) {
  if (!decoder) return [];
  if (decoder.error) {
    return [
      { label: 'Decoder Status', value: 'Error' },
      { label: 'Reason', value: decoder.error },
    ];
  }
  if (decoder.skipped) {
    return [
      { label: 'Decoder Status', value: 'Skipped' },
      { label: 'Reason', value: decoder.reason || 'No decode needed for this file.' },
    ];
  }
  return [
    { label: 'Readable Message', value: decoder.readable_message_found ? 'Yes' : 'No' },
    { label: 'Extracted Data', value: decoder.extracted_data ? 'Available' : 'None' },
    { label: 'Protected', value: decoder.likely_encrypted_or_protected ? 'Yes' : 'No' },
    { label: 'Passphrase Required', value: decoder.passphrase_required ? 'Yes' : 'No' },
    { label: 'Suspected Tool', value: decoder.suspected_tool || 'Unknown' },
  ];
}

function extractedDataIsImage(item) {
  return item?.type === 'image' || /\.(png|jpe?g|gif|webp|bmp)$/i.test(String(item?.file_name || item?.extension || ''));
}

export default function DecoderReportPage({ currentUser, deviceId }) {
  const userId = currentUser?.id || 'guest';
  const latestScanKey = scopedKey(LATEST_SCAN_KEY, userId);
  const [payload, setPayload] = useState(null);
  const [message, setMessage] = useState('');
  const [extractedImageFailed, setExtractedImageFailed] = useState(false);

  useEffect(() => {
    const raw = localStorage.getItem(latestScanKey);
    if (!raw) return;
    try {
      setPayload(JSON.parse(raw));
    } catch (_) {
      localStorage.removeItem(latestScanKey);
    }
  }, [latestScanKey]);

  useEffect(() => {
    let active = true;

    const loadLatest = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/scan/latest?user_id=${encodeURIComponent(userId)}&device_id=${encodeURIComponent(deviceId)}`);
        if (!response.ok) return;
        const latest = await response.json();
        if (!active) return;
        setPayload(latest);
        localStorage.setItem(latestScanKey, JSON.stringify(latest));
        setMessage('');
      } catch (_) {
        if (active) setMessage(`Cannot reach backend at ${API_BASE_URL}`);
      }
    };

    loadLatest();
    const timer = setInterval(loadLatest, LATEST_POLL_INTERVAL_MS);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [latestScanKey, userId, deviceId]);

  const decoder = decoderFromPayload(payload);
  const cleanImageUrl = absoluteReportUrl(decoder?.sanitized_image?.url);
  const cleanImageDownloadUrl = downloadUrl(decoder?.sanitized_image?.url);
  const rows = useMemo(() => summaryRows(decoder), [decoder]);
  const fileName = payload?.file_name || payload?.scan_result?.file_name || '';
  const extractedData = decoder?.extracted_data || null;
  const extractedDataUrl = assetUrl(decoder, extractedData?.file_name);
  const extractedDataImage = extractedDataIsImage(extractedData);

  useEffect(() => {
    setExtractedImageFailed(false);
  }, [extractedDataUrl]);

  return (
    <section className="page decoder-page">
      <h2>Decoder Report</h2>
      <p className="page-help">Review the cleaned image and the single best recovered hidden payload.</p>
      <div className="decoder-info-note">
        The decoder checks the image areas where hidden data is commonly stored, then shows the clearest recovered result here. If it finds text, you will see the message. If it finds an image, you will see that image.
      </div>

      <div className="decoder-summary">
        <article className="card">
          <h3>Cleaned Image</h3>
          {fileName && <p className="scan-file">Scanned file: {fileName}</p>}
          {decoder?.error && <p className="scan-message">Decoder error: {decoder.error}</p>}
          {decoder?.sanitized_image?.method && <p className="scan-message">{decoder.sanitized_image.method}</p>}
          {decoder?.sanitized_image?.error && <p className="scan-message">{decoder.sanitized_image.error}</p>}
          {decoder?.skipped && <p className="scan-message">{decoder.reason || 'No decode needed for this file.'}</p>}
          {!decoder && <p className="scan-message">No decoder status is available yet. Scan an image file first.</p>}
          {message && <p className="scan-message">{message}</p>}
          {cleanImageUrl && (
            <div className="cleaned-image-panel">
              <img src={cleanImageUrl} alt="Cleaned image with embedded data removed" />
              <a className="btn" href={cleanImageDownloadUrl}>Download Clean Image</a>
            </div>
          )}
        </article>

        {rows.length > 0 && (
          <article className="card decoder-stats">
            {rows.map((row) => (
              <p key={row.label}>
                <span>{row.label}</span>
                <strong>{row.value}</strong>
              </p>
            ))}
          </article>
        )}
      </div>

      {decoder && !decoder.skipped && !decoder.error && (
        <article className="card extracted-data-card">
          <h3>Extracted Data</h3>
          {!extractedData ? (
            <p className="muted-text">No readable hidden data was recovered.</p>
          ) : (
            <div className="extracted-data-preview">
              {extractedDataImage && extractedDataUrl && !extractedImageFailed ? (
                <img
                  className="extracted-image"
                  src={extractedDataUrl}
                  alt="Extracted hidden data"
                  onError={() => setExtractedImageFailed(true)}
                />
              ) : extractedDataImage && extractedImageFailed ? (
                <p className="muted-text">The extracted image could not be displayed. Rescan the original file after restarting the backend.</p>
              ) : (
                <pre className="decoded-text-block">{extractedData.content || 'Decoded text is not available in this scan result.'}</pre>
              )}
            </div>
          )}
        </article>
      )}
    </section>
  );
}
