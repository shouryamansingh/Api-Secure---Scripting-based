import { Suspense, lazy } from 'react';

const Spline = lazy(() => import('@splinetool/react-spline'));

export default function SplineScene({ scene, className }) {
  return (
    <Suspense
      fallback={
        <div style={{ width: '100%', height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div className="loading-spinner" />
        </div>
      }
    >
      <Spline scene={scene} className={className} />
    </Suspense>
  );
}
