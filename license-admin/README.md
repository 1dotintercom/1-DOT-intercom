# 1 DOT Intercom License Console

This is a separate static web admin panel. It does not belong in the Android app.

1. Deploy the `license-admin` directory to any static host (Render Static Site, Netlify, Cloudflare Pages, or GitHub Pages).
2. Set `mobileIcApi` in browser local storage if the backend URL differs from the default:
   `localStorage.setItem('mobileIcApi', 'https://your-backend.example.com')`
3. Sign in with the private backend administrator account.
4. Generate keys with optional buyer details and optional expiry dates. Revocation is immediate on the next mobile heartbeat.

The panel never contains a database credential or license-generation secret; all license decisions happen in the backend API.
