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
  if (decoder.skipped) {
    return [
      { label: 'Decoder Status', value: 'Skipped' },
      { label: 'Reason', value: decoder.reason || 'No decode needed for this file.' },
    ];
  }
  return [
    { label: 'Readable Message', value: decoder.readable_message_found ? 'Yes' : 'No' },
    { label: 'Protected', value: decoder.likely_encrypted_or_protected ? 'Yes' : 'No' },
    { label: 'Passphrase Required', value: decoder.passphrase_required ? 'Yes' : 'No' },
    { label: 'Candidates', value: String(decoder.candidate_count ?? 0) },
    { label: 'Artifacts', value: String(decoder.artifact_count ?? 0) },
    { label: 'Suspected Tool', value: decoder.suspected_tool || 'Unknown' },
  ];
}

function artifactIsImage(artifact) {
  return /\.(png|jpe?g|gif|webp)$/i.test(String(artifact?.file_name || ''));
}

export default function DecoderReportPage({ currentUser }) {
  const userId = currentUser?.id || 'guest';
  const latestScanKey = scopedKey(LATEST_SCAN_KEY, userId);
  const [payload, setPayload] = useState(null);
  const [message, setMessage] = useState('');
  const [showDecodedData, setShowDecodedData] = useState(false);

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
        const response = await fetch(`${API_BASE_URL}/api/scan/latest?user_id=${encodeURIComponent(userId)}`);
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
  }, [latestScanKey, userId]);

  const decoder = decoderFromPayload(payload);
  const reportUrl = absoluteReportUrl(decoder?.report_url);
  const cleanImageUrl = absoluteReportUrl(decoder?.sanitized_image?.url);
  const cleanImageDownloadUrl = downloadUrl(decoder?.sanitized_image?.url);
  const rows = useMemo(() => summaryRows(decoder), [decoder]);
  const fileName = payload?.file_name || payload?.scan_result?.file_name || '';
  const candidates = Array.isArray(decoder?.candidates) ? decoder.candidates : [];
  const findings = Array.isArray(decoder?.findings) ? decoder.findings : [];
  const artifacts = Array.isArray(decoder?.artifacts) ? decoder.artifacts : [];
  const imageArtifacts = artifacts.filter(artifactIsImage);
  const fileArtifacts = artifacts.filter((artifact) => !artifactIsImage(artifact));

  return (
    <section className="page decoder-page">
      <h2>Decoder Report</h2>
      <p className="page-help">Review recovered hidden-message candidates and steganography artifacts.</p>

      <div className="decoder-summary">
        <article className="card">
          <h3>Cleaned Image</h3>
          {fileName && <p className="scan-file">Scanned file: {fileName}</p>}
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

      {decoder && !decoder.skipped && (
        <div className="action-row">
          <button type="button" className="btn" onClick={() => setShowDecodedData((value) => !value)}>
            {showDecodedData ? 'Hide Decoded Data' : 'Show Decoded Data'}
          </button>
        </div>
      )}

      {reportUrl && showDecodedData && !decoder?.skipped && (
        <div className="decoded-data-panel">
          <div className="action-row">
            <a className="btn" href={reportUrl} target="_blank" rel="noreferrer">Open Full Report</a>
          </div>
          <div className="decoder-native-grid">
            <article className="card">
              <h3>Decoded Candidates</h3>
              {candidates.length === 0 ? (
                <p className="muted-text">No readable hidden-message candidates were recovered.</p>
              ) : (
                <div className="decoder-card-list">
                  {candidates.map((candidate) => {
                    const href = assetUrl(decoder, candidate.file_name);
                    return (
                      <div className="decoder-item" key={`${candidate.kind}-${candidate.file_name}`}>
                        <p><strong>{candidate.kind}</strong> {candidate.name}</p>
                        <p className="scan-meta">{candidate.size} bytes, score {Number(candidate.score || 0).toFixed(2)}</p>
                        {candidate.note && <p className="scan-message">{candidate.note}</p>}
                        {href && <a href={href} target="_blank" rel="noreferrer">Open candidate</a>}
                      </div>
                    );
                  })}
                </div>
              )}
            </article>

            <article className="card">
              <h3>Assessment</h3>
              {findings.length === 0 ? (
                <p className="muted-text">No extra findings.</p>
              ) : (
                <div className="decoder-card-list">
                  {findings.map((finding) => (
                    <div className="decoder-item" key={`${finding.level}-${finding.title}`}>
                      <span className={`tag ${finding.level === 'high' ? 'bad' : finding.level === 'medium' ? 'warn' : 'ok'}`}>{finding.level}</span>
                      <p><strong>{finding.title}</strong></p>
                      <p className="scan-meta">{finding.detail}</p>
                    </div>
                  ))}
                </div>
              )}
            </article>
          </div>

          {imageArtifacts.length > 0 && (
            <article className="card">
              <h3>Visual Artifacts</h3>
              <div className="artifact-preview-grid">
                {imageArtifacts.map((artifact) => {
                  const href = assetUrl(decoder, artifact.file_name);
                  return (
                    <a className="artifact-preview" href={href} target="_blank" rel="noreferrer" key={artifact.file_name}>
                      <span>{artifact.name}</span>
                      <img src={href} alt={artifact.name} />
                    </a>
                  );
                })}
              </div>
            </article>
          )}

          {fileArtifacts.length > 0 && (
            <article className="card">
              <h3>Analysis Files</h3>
              <div className="decoder-link-list">
                {fileArtifacts.map((artifact) => (
                  <a href={assetUrl(decoder, artifact.file_name)} target="_blank" rel="noreferrer" key={artifact.file_name}>
                    {artifact.name} <span>{artifact.kind}</span>
                  </a>
                ))}
              </div>
            </article>
          )}
        </div>
      )}
    </section>
  );
}
