import { useState } from 'react';
import { Eye, EyeOff, Chrome, Sun, Moon } from 'lucide-react';
import SplineScene from './SplineScene';
import { signInWithGoogleSimple, signInWithPassword } from '../lib/auth';

export default function LoginPage({ onLogin, theme, toggleTheme }) {
  const [showPassword, setShowPassword] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);

  // Handle email/password sign-in
  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const result = await signInWithPassword(email.trim(), password);
      if (result.success) {
        const userData = {
          uid: result.user.uid,
          email: result.user.email,
          displayName: result.userData?.username || result.user.displayName || email.split('@')[0],
          photoURL: result.userData?.google_photo_url || result.user.photoURL || '',
        };
        onLogin(userData);
      } else {
        setError(result.error || 'Login failed');
      }
    } catch (err) {
      setError(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  // Handle Google sign-in
  const handleGoogleSignIn = async () => {
    setError('');
    setGoogleLoading(true);

    try {
      const result = await signInWithGoogleSimple();

      if (result.success && result.user) {
        if (result.isNewUser) {
          // New user — App shows the password setup screen from the auth listener
          setGoogleLoading(false);
        } else {
          // Existing user — go directly to app
          const userData = {
            uid: result.user.uid,
            email: result.user.email,
            displayName: result.userData?.username || result.user.displayName || 'User',
            photoURL: result.userData?.google_photo_url || result.user.photoURL || '',
          };
          setGoogleLoading(false);
          onLogin(userData);
        }
      } else {
        setError(result.error || 'Google sign-in failed');
        setGoogleLoading(false);
      }
    } catch (err) {
      setError(err.message || 'Google sign-in failed');
      setGoogleLoading(false);
    }
  };

  // --- Google Loading Overlay ---
  if (googleLoading) {
    return (
      <div className="google-loading-overlay">
        <div className="google-loading-content">
          <Chrome size={48} className="google-loading-icon" />
          <h2 className="google-loading-title">Signing in with Google...</h2>
          <p className="google-loading-subtitle">Please complete the popup</p>
          <div className="google-loading-dots">
            <span className="dot dot-1" />
            <span className="dot dot-2" />
            <span className="dot dot-3" />
          </div>
        </div>
      </div>
    );
  }

  // --- Main Sign-In Page ---
  return (
    <div className="login-page">
      {/* Theme Toggle */}
      <button onClick={toggleTheme} className="login-theme-toggle" aria-label="Toggle theme">
        {theme === 'dark' ? <Sun size={20} /> : <Moon size={20} />}
      </button>

      {/* Left: Sign-in form */}
      <section className="login-form-section">
        <div className="login-form-container">
          <div className="login-form-inner">
            <h1 className="login-title animate-element animate-delay-200">Welcome Back</h1>
            <p className="login-description animate-element animate-delay-300">
              Sign in to access your API Secure account
            </p>

            <form onSubmit={handleSubmit} className="login-form">
              <div className="animate-element animate-delay-400">
                <label className="login-label">Email or Username</label>
                <div className="glass-input-wrapper">
                  <input
                    type="text"
                    placeholder="Enter your email or username"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="glass-input"
                    required
                  />
                </div>
              </div>

              <div className="animate-element animate-delay-500">
                <label className="login-label">Password</label>
                <div className="glass-input-wrapper">
                  <div className="password-wrapper">
                    <input
                      type={showPassword ? 'text' : 'password'}
                      placeholder="Enter your password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="glass-input glass-input-password"
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="password-toggle-btn"
                    >
                      {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                    </button>
                  </div>
                </div>
              </div>

              <div className="animate-element animate-delay-600 login-remember-row">
                <label className="login-checkbox-label">
                  <input type="checkbox" className="login-checkbox" />
                  <span>Keep me signed in</span>
                </label>
              </div>

              {error && <div className="login-error">{error}</div>}

              <button
                type="submit"
                className="animate-element animate-delay-700 login-submit-btn"
                disabled={loading}
              >
                {loading ? 'Please wait...' : 'Login'}
              </button>
            </form>

            {/* Divider */}
            <div className="animate-element animate-delay-800 login-divider">
              <span className="login-divider-line"></span>
              <span className="login-divider-text">Or</span>
            </div>

            {/* Google Sign-In Button */}
            <button
              onClick={handleGoogleSignIn}
              className="animate-element animate-delay-900 login-google-btn"
              disabled={googleLoading}
            >
              <Chrome size={24} className="login-google-icon" />
              Continue with Google
            </button>

            {/* Create Account hint */}
            <p className="animate-element animate-delay-1000 login-switch-text">
              New to API Secure?{' '}
              <a
                href="#"
                onClick={(e) => {
                  e.preventDefault();
                  handleGoogleSignIn();
                }}
              >
                Sign in with Google to get started
              </a>
            </p>

            {/* Branding */}
            <p className="animate-element animate-delay-1100 login-branding">
              Engineered by <span className="login-branding-name">Faizan Q & Team</span>
            </p>
          </div>
        </div>
      </section>

      {/* Right: 3D Robot */}
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
