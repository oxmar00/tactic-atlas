import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import './index.css';

const root = document.getElementById('root');
if (!root) throw new Error('Root element missing');
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);

// Offline support: production builds register a service worker that caches the app's own files.
if (import.meta.env.PROD && 'serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    // Only an update of an already-controlled page is worth announcing, not the first install.
    const hadController = !!navigator.serviceWorker.controller;
    navigator.serviceWorker
      .register(`${import.meta.env.BASE_URL}sw.js`)
      .then((registration) => {
        registration.addEventListener('updatefound', () => {
          const worker = registration.installing;
          worker?.addEventListener('statechange', () => {
            if (worker.state === 'activated' && hadController) window.dispatchEvent(new Event('socnav-update-ready'));
          });
        });
      })
      .catch(() => undefined);
  });
}
