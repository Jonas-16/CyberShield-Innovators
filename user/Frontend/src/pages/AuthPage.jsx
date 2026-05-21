import React, { useMemo, useState } from 'react';
import { saveCurrentUser } from '../auth';

const API_BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000';

export default function AuthPage({ onAuthenticated }) {
  const [mode, setMode] = useState('signin');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const title = useMemo(() => (mode === 'signup' ? 'Create Account' : 'Sign In'), [mode]);

  const submit = async (event) => {
    event.preventDefault();
    const cleanEmail = email.trim().toLowerCase();
    const cleanName = name.trim();

    if (!cleanEmail || !password.trim()) {
      setMessage('Enter your email and password.');
      return;
    }

    if (mode === 'signup') {
      if (!cleanName) {
        setMessage('Enter your name to create an account.');
        return;
      }
    }

    setIsSubmitting(true);
    setMessage(mode === 'signup' ? 'Creating account...' : 'Signing in...');

    try {
      const response = await fetch(`${API_BASE_URL}/api/auth/${mode === 'signup' ? 'signup' : 'login'}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: cleanName,
          email: cleanEmail,
          password,
        }),
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload?.detail || 'Authentication failed');
      }

      saveCurrentUser(payload.user);
      onAuthenticated(payload.user);
    } catch (error) {
      const messageText = error instanceof TypeError
        ? `Cannot reach backend at ${API_BASE_URL}. Start FastAPI and XAMPP MySQL.`
        : (error?.message || 'Authentication failed');
      setMessage(messageText);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="auth-shell">
      <section className="auth-panel card">
        <p className="hero-kicker">Cyber Shield Innovators</p>
        <h2>{title}</h2>
        <p className="page-help">Use your account to keep dashboard results and scan logs separate on each device.</p>

        <div className="auth-tabs" role="tablist" aria-label="Authentication mode">
          <button
            type="button"
            className={`auth-tab ${mode === 'signin' ? 'active' : ''}`}
            onClick={() => {
              setMode('signin');
              setMessage('');
            }}
          >
            Sign In
          </button>
          <button
            type="button"
            className={`auth-tab ${mode === 'signup' ? 'active' : ''}`}
            onClick={() => {
              setMode('signup');
              setMessage('');
            }}
          >
            Sign Up
          </button>
        </div>

        <form className="auth-form" onSubmit={submit}>
          {mode === 'signup' && (
            <>
              <label className="field-label" htmlFor="authName">Name</label>
              <input
                id="authName"
                className="path-input"
                type="text"
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="Your name"
              />
            </>
          )}

          <label className="field-label" htmlFor="authEmail">Email</label>
          <input
            id="authEmail"
            className="path-input"
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            placeholder="you@example.com"
          />

          <label className="field-label" htmlFor="authPassword">Password</label>
          <input
            id="authPassword"
            className="path-input"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder="Password"
          />

          <button type="submit" className="btn auth-submit" disabled={isSubmitting}>
            {isSubmitting ? 'Please wait...' : title}
          </button>
        </form>
        {message && <p className="scan-message">{message}</p>}
      </section>
    </div>
  );
}
