import React, { useEffect } from 'react';

// Shared modal shell: dark backdrop + centered panel. Closes on Escape and on a
// click that lands on the backdrop itself (not the panel). Locks body scroll while open.
export default function Modal({ onClose, children, panelClassName = '', maxWidth = 'max-w-lg' }) {
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') onClose?.();
    };
    document.addEventListener('keydown', onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = prev;
    };
  }, [onClose]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md overflow-y-auto"
      onMouseDown={(e) => {
        // only close when the press starts AND ends on the backdrop
        if (e.target === e.currentTarget) onClose?.();
      }}
    >
      <div
        className={`glass-hi w-full ${maxWidth} overflow-hidden ${panelClassName}`}
        onMouseDown={(e) => e.stopPropagation()}
      >
        {children}
      </div>
    </div>
  );
}
