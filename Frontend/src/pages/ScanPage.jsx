import React, { useMemo, useState } from 'react';

const API_BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000';

export default function ScanPage() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [message, setMessage] = useState('');
  const [result, setResult] = useState(null);

  const currentStep = useMemo(() => {
    if (isUploading) return 2;
    if (result) return 6;
    if (selectedFile) return 1;
    return 0;
  }, [isUploading, result, selectedFile]);

  const handleFileChange = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setSelectedFile(file);
    setResult(null);
    setMessage('Uploading file to sandbox queue...');
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

      localStorage.setItem('latestSandboxFile', JSON.stringify(payload));
      setResult(payload);
      setMessage(`Queued: ${payload.file_name}`);
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
        Automatic sandboxing works when the browser or app downloads directly into
        {' '}<strong>D:\Download</strong>. Use this page only if you want to manually submit a file.
      </p>

      <div className="card scan-config-card">
        <h3>Automatic Download Setup</h3>
        <p className="muted-text">
          Set your browser or app download location to <strong>D:\Download</strong>.
          When the download finishes there, the sandbox monitor sends it into Windows Sandbox automatically.
        </p>
      </div>

      <div className="card upload-card">
        <h3>Manual File Check</h3>
        <label htmlFor="scanFileInput" className="upload-dropzone">
          <span>{isUploading ? 'Uploading...' : 'Click here to choose a file'}</span>
          <span className="muted">File will be sent to sandbox queue immediately</span>
          <input id="scanFileInput" type="file" onChange={handleFileChange} disabled={isUploading} />
        </label>
        {selectedFile && <p className="scan-file">Selected: {selectedFile.name}</p>}
        {message && <p className="scan-message">{message}</p>}
        {result?.staging_path && <p className="scan-meta">Staging path: {result.staging_path}</p>}
      </div>

      <ol className="step-list">
        <li className={`step ${currentStep >= 1 ? 'done' : ''}`}>1. File Detected</li>
        <li className={`step ${currentStep === 2 ? 'current' : currentStep > 2 ? 'done' : ''}`}>2. Queued in Sandbox</li>
        <li className={`step ${currentStep >= 3 ? 'done' : ''}`}>3. Checking New Threat Patterns</li>
        <li className={`step ${currentStep >= 4 ? 'done' : ''}`}>4. Checking Hidden Data</li>
        <li className={`step ${currentStep >= 5 ? 'done' : ''}`}>5. Checking Adversarial Attacks</li>
        <li className={`step ${currentStep >= 6 ? 'done' : ''}`}>6. Scan Completed</li>
      </ol>
    </section>
  );
}
