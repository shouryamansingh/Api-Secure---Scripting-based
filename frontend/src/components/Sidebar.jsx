import { useState, useCallback, useEffect } from 'react';
import { LogOut, Settings, Shield, Terminal, History } from 'lucide-react';
import { useNavigate, useLocation } from 'react-router-dom';

const PAGE_TO_PATH = {
  'scanner':         '/scanner',
  'token-generator': '/testcurl',
  'history':         '/history',
  'settings':        '/settings',
};
const PATH_TO_PAGE = {
  '/scanner':  'scanner',
  '/testcurl': 'token-generator',
  '/history':  'history',
  '/settings': 'settings',
  '/':         'scanner',
};

export default function Sidebar({ user, onLogout }) {
  const navigate   = useNavigate();
  const location   = useLocation();
  const activePage = PATH_TO_PAGE[location.pathname] || 'scanner';
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  const [avatarImgFailed, setAvatarImgFailed] = useState(false);

  const photoURL = user?.photoURL || '';
  useEffect(() => setAvatarImgFailed(false), [photoURL]);

  const handleLogout = async () => {
    setIsLoggingOut(true);
    await onLogout();
    setIsLoggingOut(false);
  };

  const links = [
    { id: 'scanner', label: 'Scanner', icon: <Shield size={18} /> },
    { id: 'token-generator', label: 'Test Curl', icon: <Terminal size={18} /> },
    { id: 'history', label: 'History', icon: <History size={18} /> },
    { id: 'settings', label: 'Settings', icon: <Settings size={18} /> },
  ];

  const avatarLetter = (user?.displayName || 'U').charAt(0).toUpperCase();
  const isEmojiAvatar = photoURL.startsWith('emoji:');
  const showImg = photoURL && !isEmojiAvatar && !avatarImgFailed;
  const handleAvatarError = useCallback(() => setAvatarImgFailed(true), []);

  return (
    <aside className="sidebar-nav">
      {/* Brand */}
      <div className="sidebar-nav-logo">
        <img
          src="/app-logo.svg"
          alt="API Secure"
          className="sidebar-app-logo"
        />
        <span className="sidebar-nav-logo-text">API Secure</span>
      </div>

      {/* Nav links */}
      <div className="sidebar-nav-links">
        {links.map((link) => (
          <button
            key={link.id}
            className={`sidebar-nav-link${activePage === link.id ? ' active' : ''}`}
            onClick={() => navigate(PAGE_TO_PATH[link.id])}
            title={link.label}
          >
            <span className="sidebar-nav-icon">{link.icon}</span>
            <span className="sidebar-nav-label">{link.label}</span>
          </button>
        ))}
      </div>

      {/* Bottom: User + Logout */}
      <div className="sidebar-nav-footer">
        {/* User profile: emoji avatar, or image with fallback, or initial letter */}
        <div className="sidebar-nav-user">
          {isEmojiAvatar ? (
            <div className="sidebar-nav-avatar sidebar-nav-avatar-emoji" title={user?.displayName || 'User'}>
              {photoURL.replace('emoji:', '')}
            </div>
          ) : showImg ? (
            <img
              src={photoURL}
              alt="Avatar"
              className="sidebar-nav-avatar-img"
              onError={handleAvatarError}
            />
          ) : (
            <div className="sidebar-nav-avatar" title={user?.displayName || 'User'}>{avatarLetter}</div>
          )}
          <span className="sidebar-nav-username">{user?.displayName || 'User'}</span>
        </div>

        {/* Logout */}
        <button
          className="sidebar-nav-link sidebar-nav-logout"
          onClick={handleLogout}
          disabled={isLoggingOut}
          title="Logout"
        >
          <span className="sidebar-nav-icon">
            <LogOut size={18} className={isLoggingOut ? 'sidebar-pulse' : ''} />
          </span>
          <span className="sidebar-nav-label">
            {isLoggingOut ? 'Signing out…' : 'Logout'}
          </span>
        </button>
      </div>
    </aside>
  );
}
