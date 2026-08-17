# Mobile IC Agent — Mobile Intercom App (React Native + Node.js + LiveKit)

Mobile IC Agent is an internet-wide software intercom system modeled after **ClearCom**, **RTS**, and **Telex** broadcast hardware panels. It connects up to 20 concurrent intercom panels across the globe with server-side media layer permission matrix enforcement on iOS and Android.

---

## 📂 Project Structure

```
/backend    - Node.js + Express + TypeScript API (LiveKit Server SDK, JWT Auth, Audit Logs, Pino)
/web        - React web app (same GUI as mobile — Push-to-Talk Panel, Admin Matrix, Audit Logs)
/mobile     - React Native mobile app (Push-to-Talk Panel, Admin Matrix, Audit Logs, Auth)
/db         - Database schema (schema.sql)
README.md   - Documentation
```

---

## 🌟 Key Features

1. **ClearCom Hardware-Style Mobile GUI (`/mobile`)**:
   - Built with **React Native** for iOS & Android.
   - **4-Color Permission Encoding**:
     - 🔴 **Red (Talk Only)**: Transmit audio to target; cannot hear target.
     - 🟢 **Green (Listen Only)**: Hear target audio; cannot transmit.
     - 🟧 **Amber / Orange (Both / Full Duplex)**: Two-way conversation.
     - 🔘 **Gray (Blocked)**: Inert button.
   - **Push-to-Talk (PTT)**: Press-and-hold button interaction with haptic feedback.
   - **Live Speaker Ring Indicator**: Visual indication when audio is flowing from active speakers.

2. **Admin-Controlled Routing & Permission Matrix**:
   - Interactive 20×20 scrollable matrix grid for System Admins.
   - Tap cell to cycle states: `Blocked` ➔ `Talk` ➔ `Listen` ➔ `Both`.
   - **Live SFU Enforcement**: Permission changes update active calls in under 1 second without reconnecting.

3. **Logging & Immutable Audit Trail**:
   - Structured JSON logs written to console + rotating log files (`pino`).
   - Append-only PostgreSQL `audit_logs` table tracking PTT audio sessions and admin permission edits.
   - Filterable Audit Log Viewer screen.

---

## 🚀 Setup & Launch Instructions

### 1. Database & Backend Setup
1. Set up a PostgreSQL database (e.g., [Supabase](https://supabase.com)) and run the SQL from `db/schema.sql` in the SQL Editor.
2. Set up a free LiveKit project at [cloud.livekit.io](https://cloud.livekit.io).
3. Configure `backend/.env` with your `DATABASE_URL`, `LIVEKIT_HOST`, `LIVEKIT_API_KEY`, and `LIVEKIT_API_SECRET`.
   ```powershell
   cd backend
   npm run db:seed
   npm run dev
   ```

### 2. Run Web App (Recommended)
```powershell
# Start backend (if not already running)
cd backend
npm run dev

# In another terminal — start the web app
cd web
npm install
npm run dev
```
Open **http://localhost:5173** in your browser. The Vite dev server proxies `/api` requests to the backend on port 5000.

For production builds, set `VITE_API_BASE_URL` to your deployed backend URL.

### 3. Run Mobile App (Optional)
```powershell
# Start Metro bundler
cd mobile
npx react-native start

# Run on Android (in another terminal)
cd mobile
npx react-native run-android
```

---



After signing in, open **Stations** to create each operator's station and sign-in. New station-to-station routes are blocked by default. Open **Matrix** to set the permitted talk, listen, or full-duplex paths before operators connect.
