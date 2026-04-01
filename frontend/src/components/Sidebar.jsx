import { useState, useCallback, useEffect } from 'react';
import { motion } from 'framer-motion';
import { LogOut, Settings, Shield, Terminal, History } from 'lucide-react';

export default function Sidebar({ user, onLogout, activePage, onNavigate }) {
  const [open, setOpen] = useState(false);
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
    { id: 'scanner', label: 'Scanner', icon: <Shield size={20} /> },
    { id: 'token-generator', label: 'Token Generator', icon: <Terminal size={20} /> },
    { id: 'history', label: 'History', icon: <History size={20} /> },
    { id: 'settings', label: 'Settings', icon: <Settings size={20} /> },
  ];

  const avatarLetter = (user?.displayName || 'U').charAt(0).toUpperCase();
  const isEmojiAvatar = photoURL.startsWith('emoji:');
  const showImg = photoURL && !isEmojiAvatar && !avatarImgFailed;
  const handleAvatarError = useCallback(() => setAvatarImgFailed(true), []);

  return (
    <motion.aside
      className="sidebar-nav"
      animate={{ width: open ? 204 : 60 }}
      transition={{ duration: 0.28, ease: [0.25, 0.1, 0.25, 1] }}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
    >
      {/* Logo */}
      <div className="sidebar-nav-logo">
        <div className="sidebar-nav-logo-icon">⚡</div>
        <motion.span
          className="sidebar-nav-logo-text"
          animate={{ opacity: open ? 1 : 0, x: open ? 0 : -8 }}
          transition={{ duration: 0.22 }}
          style={{ display: open ? 'inline-block' : 'none' }}
        >
          API Secure
        </motion.span>
      </div>

      {/* Nav links */}
      <div className="sidebar-nav-links">
        {links.map((link) => (
          <button
            key={link.id}
            className={`sidebar-nav-link${activePage === link.id ? ' active' : ''}`}
            onClick={() => onNavigate(link.id)}
            title={link.label}
          >
            <span className="sidebar-nav-icon">{link.icon}</span>
            <motion.span
              className="sidebar-nav-label"
              animate={{ opacity: open ? 1 : 0, x: open ? 0 : -10 }}
              transition={{ duration: 0.25, ease: [0.25, 0.1, 0.25, 1] }}
              style={{ display: open ? 'inline-block' : 'none' }}
            >
              {link.label}
            </motion.span>
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
          <motion.span
            className="sidebar-nav-username"
            animate={{ opacity: open ? 1 : 0, x: open ? 0 : -10 }}
            transition={{ duration: 0.25 }}
            style={{ display: open ? 'block' : 'none' }}
          >
            {user?.displayName || 'User'}
          </motion.span>
        </div>

        {/* Logout */}
        <button
          className="sidebar-nav-link sidebar-nav-logout"
          onClick={handleLogout}
          disabled={isLoggingOut}
          title="Logout"
        >
          <span className="sidebar-nav-icon">
            <LogOut size={20} className={isLoggingOut ? 'sidebar-pulse' : ''} />
          </span>
          <motion.span
            className="sidebar-nav-label"
            animate={{ opacity: open ? 1 : 0, x: open ? 0 : -10 }}
            transition={{ duration: 0.25 }}
            style={{ display: open ? 'inline-block' : 'none' }}
          >
            {isLoggingOut ? 'Signing out...' : 'Logout'}
          </motion.span>
        </button>
      </div>
    </motion.aside>
  );
}
