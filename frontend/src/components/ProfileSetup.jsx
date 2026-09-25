import { useMemo, useState } from 'react';
import { Eye, EyeOff, Sun, Moon, Check, X, ShieldCheck, Mail } from 'lucide-react';
import SplineScene from './SplineScene';
import { completeProfileSetup, getPasswordChecks, validateUsername } from '../lib/auth';

const STRENGTH_LABELS = ['', 'Weak', 'Fair', 'Good', 'Strong'];

const suggestUsername = (user) => {
  const base = (user?.displayName || user?.email?.split('@')[0] || '')
    .toLowerCase()
    .replace(/\s+/g, '_')
    .replace(/[^a-z0-9_.]/g, '')
    .slice(0, 20);
  return base.length >= 3 ? base : '';
};

/**
 * Shown after a first-time Google sign-in (and on every visit until it's
 * completed). The user must pick a username and a strong password before
 * reaching the app.
 */
export default function ProfileSetup({ firebaseUser, theme, toggleTheme, onComplete, onCancel }) {
  const [username, setUsername] = useState(() => suggestUsername(firebaseUser));
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [touched, setTouched] = useState({ username: false, confirm: false });
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  const email = firebaseUser.email || '';
  const trimmedUsername = username.trim();
  const usernameError = validateUsername(trimmedUsername);
  const checks = useMemo(
    () => getPasswordChecks(password, { username: trimmedUsername, email }),
    [password, trimmedUsername, email],
  );
  const passedCount = checks.filter((c) => c.ok).length;
  const allPassed = passedCount === checks.length;
  const strength = !password ? 0 : allPassed ? (password.length >= 12 ? 4 : 3) : passedCount >= 4 ? 2 : 1;
  const mismatch = confirm.length > 0 && confirm !== password;
  const canSubmit = !usernameError && allPassed && confirm === password && !saving;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setTouched({ username: true, confirm: true });
    if (!canSubmit) return;
    setError('');
    setSaving(true);
    const result = await completeProfileSetup(
      firebaseUser.uid,
      trimmedUsername,
      email,
      password,
      firebaseUser.displayName || '',
      firebaseUser.photoURL || '',
    );
    if (result.success) {
      onComplete({
        uid: firebaseUser.uid,
        email,
        displayName: trimmedUsername,
        photoURL: firebaseUser.photoURL || '',
      });
    } else {
      setError(result.error || 'Profile setup failed. Please try again.');
      setSaving(false);
    }
  };

  return (
    <div className="login-page">
      <button onClick={toggleTheme} className="login-theme-toggle" aria-label="Toggle theme">
        {theme === 'dark' ? <Sun size={20} /> : <Moon size={20} />}
      </button>

      <section className="login-form-section">
        <div className="login-form-container">
          <div className="login-form-inner">
            <div className="setup-header animate-element animate-delay-200">
              {firebaseUser.photoURL ? (
                <img src={firebaseUser.photoURL} alt="" className="setup-avatar" referrerPolicy="no-referrer" />
              ) : (
                <div className="setup-avatar setup-avatar--icon"><ShieldCheck size={32} /></div>
              )}
              <span className="setup-step">Step 2 of 2 · Secure your account</span>
            </div>

            <h1 className="login-title animate-element animate-delay-300">Set up your password</h1>
            <p className="login-description animate-element animate-delay-400">
              Welcome{firebaseUser.displayName ? `, ${firebaseUser.displayName}` : ''}! Choose a username and a
              strong password. You can then sign in with either Google or your username/email and password.
            </p>

            <form onSubmit={handleSubmit} className="login-form" noValidate>
              <div className="animate-element animate-delay-400">
                <label className="login-label">Google account</label>
                <div className="setup-email">
                  <Mail size={16} aria-hidden />
                  <span>{email}</span>
                </div>
              </div>

              <div className="animate-element animate-delay-500">
                <label className="login-label" htmlFor="setup-username">Username</label>
                <div className={`glass-input-wrapper${touched.username && usernameError ? ' glass-input-wrapper--error' : ''}`}>
                  <input
                    id="setup-username"
                    type="text"
                    placeholder="e.g. alex_dev"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    onBlur={() => setTouched((t) => ({ ...t, username: true }))}
                    className="glass-input"
                    autoComplete="username"
                    maxLength={20}
                    autoFocus
                  />
                </div>
                <p className={`setup-hint${touched.username && usernameError ? ' setup-hint--error' : ''}`}>
                  {touched.username && usernameError
                    ? usernameError
                    : '3–20 characters: letters, numbers, dots and underscores.'}
                </p>
              </div>

              <div className="animate-element animate-delay-600">
                <label className="login-label" htmlFor="setup-password">Password</label>
                <div className="glass-input-wrapper">
                  <div className="password-wrapper">
                    <input
                      id="setup-password"
                      type={showPassword ? 'text' : 'password'}
                      placeholder="Create a strong password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="glass-input glass-input-password"
                      autoComplete="new-password"
                      aria-describedby="setup-password-rules"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword((v) => !v)}
                      className="password-toggle-btn"
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                    >
                      {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                    </button>
                  </div>
                </div>

                <div className="pw-strength" data-level={strength} aria-live="polite">
                  <div className="pw-strength-bars" aria-hidden>
                    {[1, 2, 3, 4].map((n) => <span key={n} className={n <= strength ? 'on' : ''} />)}
                  </div>
                  <span className="pw-strength-label">
                    {password ? `Strength: ${STRENGTH_LABELS[strength]}` : 'Password strength'}
                  </span>
                </div>

                <ul id="setup-password-rules" className="pw-rules">
                  {checks.map((c) => (
                    <li key={c.id} className={c.ok ? 'ok' : ''}>
                      {c.ok ? <Check size={14} aria-hidden /> : <X size={14} aria-hidden />}
                      <span>{c.label}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="animate-element animate-delay-700">
                <label className="login-label" htmlFor="setup-confirm">Confirm password</label>
                <div className={`glass-input-wrapper${(touched.confirm || confirm) && mismatch ? ' glass-input-wrapper--error' : ''}`}>
                  <input
                    id="setup-confirm"
                    type={showPassword ? 'text' : 'password'}
                    placeholder="Re-enter your password"
                    value={confirm}
                    onChange={(e) => setConfirm(e.target.value)}
                    onBlur={() => setTouched((t) => ({ ...t, confirm: true }))}
                    className="glass-input"
                    autoComplete="new-password"
                  />
                </div>
                {mismatch && <p className="setup-hint setup-hint--error">Passwords don't match.</p>}
                {!mismatch && confirm && confirm === password && (
                  <p className="setup-hint setup-hint--ok">Passwords match.</p>
                )}
              </div>

              {error && <div className="login-error" role="alert">{error}</div>}

              <button type="submit" className="animate-element animate-delay-700 login-submit-btn" disabled={!canSubmit}>
                {saving ? 'Securing your account…' : 'Save password & continue'}
              </button>
            </form>

            <p className="animate-element animate-delay-800 login-switch-text">
              Not you?{' '}
              <a href="#" onClick={(e) => { e.preventDefault(); onCancel(); }}>
                Use a different Google account
              </a>
            </p>

            <p className="animate-element animate-delay-900 login-branding">
              Engineered by <span className="login-branding-name">Faizan Q & Team</span>
            </p>
          </div>
        </div>
      </section>

      <section className="login-robot-section">
        <div className="login-robot-container animate-slide-right animate-delay-300">
          <div className="login-robot-spotlight" />
          <div className="login-robot-canvas">
            <SplineScene scene="https://prod.spline.design/kZDDjO5HuC9GJUM2/scene.splinecode" className="login-spline" />
          </div>
          <div className="login-robot-overlay">
            <div className="login-robot-text">
              <h2 className="login-robot-title">API Secure</h2>
              <p className="login-robot-subtitle">Ease your testing</p>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
