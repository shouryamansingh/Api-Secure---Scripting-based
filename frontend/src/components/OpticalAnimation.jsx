import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';

export default function OpticalAnimation({ onComplete }) {
  const [phase, setPhase] = useState('startup'); // startup | transform | subtitle | complete
  const [bgColor, setBgColor] = useState('#000000');

  useEffect(() => {
    const startupTimer = setTimeout(() => {
      setPhase('transform');
      setTimeout(() => setBgColor('#FFFFFF'), 500);
    }, 5000);
    const transformTimer = setTimeout(() => setPhase('subtitle'), 8000);
    const subtitleTimer = setTimeout(() => setPhase('complete'), 10000);
    const completeTimer = setTimeout(() => onComplete(), 12000);

    return () => {
      clearTimeout(startupTimer);
      clearTimeout(transformTimer);
      clearTimeout(subtitleTimer);
      clearTimeout(completeTimer);
    };
  }, [onComplete]);

  return (
    <motion.div
      className="optical-animation"
      animate={{ backgroundColor: bgColor }}
      transition={{ duration: 1.2, ease: [0.16, 1, 0.3, 1] }}
    >
      {/* Phase 1: Startup — glowing dot, rings, beams */}
      {phase === 'startup' && (
        <>
          {/* Central dot */}
          <motion.div
            className="optical-abs"
            initial={{ opacity: 0, scale: 0 }}
            animate={{ opacity: [0, 1, 1, 1], scale: [0, 1, 1, 1] }}
            transition={{ duration: 5, times: [0, 0.2, 0.7, 1], ease: [0.16, 1, 0.3, 1] }}
            style={{
              width: 20, height: 20, borderRadius: '50%', backgroundColor: '#FFFFFF',
              boxShadow: '0 0 60px rgba(255,255,255,1), 0 0 120px rgba(255,255,255,0.8)',
              zIndex: 5,
            }}
          />

          {/* Expanding rings */}
          {[1, 2, 3].map((ring) => (
            <motion.div
              key={ring}
              className="optical-abs"
              initial={{ opacity: 0, scale: 0 }}
              animate={{ opacity: [0, 0.9, 0.6, 0], scale: [0, 1.5, 2.5, 3.5] }}
              transition={{ duration: 3, delay: ring * 0.5, times: [0, 0.3, 0.6, 1], ease: [0.16, 1, 0.3, 1] }}
              style={{
                width: 300, height: 300, borderRadius: '50%',
                border: '3px solid rgba(255,255,255,0.8)',
                boxShadow: '0 0 40px rgba(255,255,255,0.6)',
              }}
            />
          ))}

          {/* Top beam */}
          <motion.div
            className="optical-abs"
            initial={{ scaleY: 0, opacity: 0, rotate: 0, y: -1 }}
            animate={{
              scaleY: [0, 0, 1, 1, 1, 1],
              opacity: [0, 0, 1, 1, 1, 0.8],
              rotate: [0, 0, 0, 0, 90, 90],
              y: [-1, -1, -1, -1, -1, -100],
            }}
            transition={{ duration: 5, times: [0, 0.4, 0.7, 0.85, 0.92, 1], ease: [0.16, 1, 0.3, 1] }}
            style={{
              width: 4, height: 400, transformOrigin: 'center center',
              background: 'linear-gradient(to bottom, transparent, rgba(255,255,255,1) 50%, transparent)',
              boxShadow: '0 0 80px rgba(255,255,255,0.8)',
            }}
          />

          {/* Bottom beam */}
          <motion.div
            className="optical-abs"
            initial={{ scaleY: 0, opacity: 0, rotate: 0, y: 1 }}
            animate={{
              scaleY: [0, 0, 1, 1, 1, 1],
              opacity: [0, 0, 1, 1, 1, 0.8],
              rotate: [0, 0, 0, 0, 90, 90],
              y: [1, 1, 1, 1, 1, 100],
            }}
            transition={{ duration: 5, times: [0, 0.4, 0.7, 0.85, 0.92, 1], ease: [0.16, 1, 0.3, 1] }}
            style={{
              width: 4, height: 400, transformOrigin: 'center center',
              background: 'linear-gradient(to bottom, transparent, rgba(255,255,255,1) 50%, transparent)',
              boxShadow: '0 0 80px rgba(255,255,255,0.8)',
            }}
          />

          {/* Convergence glow */}
          <motion.div
            className="optical-abs"
            initial={{ opacity: 0, scale: 0.5 }}
            animate={{ opacity: [0, 0, 0, 0.8, 0.5], scale: [0.5, 0.5, 0.5, 1.2, 1.5] }}
            transition={{ duration: 3.5, times: [0, 0.5, 0.7, 0.9, 1], ease: 'easeOut' }}
            style={{
              width: 250, height: 250, borderRadius: '50%',
              background: 'radial-gradient(circle, rgba(255,255,255,0.4) 0%, rgba(255,255,255,0.1) 40%, transparent 70%)',
              filter: 'blur(50px)',
            }}
          />

          {/* Outer frame */}
          <motion.div
            className="optical-abs"
            initial={{ opacity: 0, scale: 1.5 }}
            animate={{ opacity: [0, 0, 0, 0.4, 0], scale: [1.5, 1.5, 1.5, 1, 0.8] }}
            transition={{ duration: 3.5, times: [0, 0.6, 0.7, 0.9, 1], ease: [0.16, 1, 0.3, 1] }}
            style={{
              width: 400, height: 400, borderRadius: '50%',
              border: '1px solid rgba(255,255,255,0.3)',
            }}
          />
        </>
      )}

      {/* Phase 2: Transform — "API Secure" */}
      {phase === 'transform' && (
        <div className="optical-center">
          <motion.div
            className="optical-abs"
            initial={{ opacity: 1, scaleX: 1 }}
            animate={{ opacity: [1, 1, 0], scaleX: [1, 1.5, 0] }}
            transition={{ duration: 1.2, times: [0, 0.5, 1], ease: [0.16, 1, 0.3, 1] }}
            style={{
              width: 450, height: 2,
              background: bgColor === '#000000'
                ? 'linear-gradient(to right, transparent, rgba(255,255,255,1) 50%, transparent)'
                : 'linear-gradient(to right, transparent, rgba(0,0,0,1) 50%, transparent)',
              boxShadow: bgColor === '#000000'
                ? '0 0 50px rgba(255,255,255,0.8)'
                : '0 0 30px rgba(0,0,0,0.3)',
            }}
          />
          <motion.h1
            className="optical-title"
            initial={{ opacity: 0 }}
            animate={{ opacity: [0, 0, 1] }}
            transition={{ duration: 1.5, times: [0, 0.5, 1], ease: [0.16, 1, 0.3, 1] }}
            style={{ color: bgColor === '#000000' ? '#FFFFFF' : '#000000' }}
          >
            API Secure
          </motion.h1>
        </div>
      )}

      {/* Phase 3: Subtitle */}
      {phase === 'subtitle' && (
        <div className="optical-center">
          <motion.h2
            className="optical-subtitle"
            initial={{ opacity: 0 }}
            animate={{ opacity: [0, 1] }}
            transition={{ duration: 1.5, ease: [0.16, 1, 0.3, 1] }}
            style={{ color: bgColor === '#000000' ? 'rgba(255,255,255,0.7)' : 'rgba(0,0,0,0.7)' }}
          >
            Engineered by
          </motion.h2>
        </div>
      )}

      {/* Phase 4: Complete */}
      {phase === 'complete' && (
        <div className="optical-center">
          <motion.h2
            className="optical-subtitle"
            initial={{ opacity: 1 }}
            animate={{ opacity: [1, 1, 0] }}
            transition={{ duration: 1.5, times: [0, 0.7, 1], ease: 'easeOut' }}
            style={{ color: bgColor === '#000000' ? 'rgba(255,255,255,0.7)' : 'rgba(0,0,0,0.7)' }}
          >
            Faizan Q & Team
          </motion.h2>
        </div>
      )}
    </motion.div>
  );
}
