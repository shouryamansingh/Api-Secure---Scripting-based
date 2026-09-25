import { useEffect, useState } from 'react';

export default function WelcomeScreen({ username, onComplete }) {
  const [show, setShow] = useState(true);

  useEffect(() => {
    const timer = setTimeout(() => {
      setShow(false);
      setTimeout(() => onComplete(), 500);
    }, 2500);
    return () => clearTimeout(timer);
  }, [onComplete]);

  if (!show) return null;

  return (
    <div className="welcome-screen">
      <div className="welcome-content" style={{ animation: 'smoothZoomIn 0.6s cubic-bezier(0.16, 1, 0.3, 1) forwards' }}>
        {/* Avatar */}
        <div
          className="welcome-avatar-wrap"
          style={{ animation: 'smoothZoomIn 0.5s cubic-bezier(0.16, 1, 0.3, 1) 0.2s forwards', opacity: 0 }}
        >
          <div className="welcome-avatar-pulse" />
          <div className="welcome-avatar">
            {(username || 'U').charAt(0).toUpperCase()}
          </div>
        </div>

        {/* Message */}
        <div
          className="welcome-message"
          style={{ animation: 'slideUp 0.6s cubic-bezier(0.16, 1, 0.3, 1) 0.4s forwards', opacity: 0 }}
        >
          <h1 className="welcome-heading">Welcome, {username}</h1>
          <p className="welcome-sub">Your account is ready</p>
        </div>

        {/* Dots */}
        <div
          className="welcome-dots"
          style={{ animation: 'slideUp 0.5s cubic-bezier(0.16, 1, 0.3, 1) 0.6s forwards', opacity: 0 }}
        >
          <div className="welcome-dot" style={{ animationDelay: '0ms' }} />
          <div className="welcome-dot" style={{ animationDelay: '200ms' }} />
          <div className="welcome-dot" style={{ animationDelay: '400ms' }} />
        </div>
      </div>
    </div>
  );
}
