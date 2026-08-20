# 1 DOT Intercom — Mobile Intercom App (React Native + Node.js + LiveKit)

1 DOT Intercom is an internet-wide software intercom system modeled after professional broadcast hardware panels. It connects up to 20 concurrent intercom panels across the globe with server-side media layer permission matrix enforcement on iOS and Android.

---

## 📂 Project Structure

```
/backend    - Node.js + Express + TypeScript API (LiveKit Server SDK, JWT Auth, Audit Logs, Pino)
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
   - **Push-to-Talk (PTT)**: Duplex and talk routes use the original press-and-hold walkie-talkie behavior. A 3.5-second hold locks the microphone; vibration and a circular countdown provide feedback, and `CANCEL / RELEASE` unlocks it.
   - **Listen-only routes**: A permitted listen-only panel shows `TAP TO LISTEN`. Tap once to hear that specific panel and tap again to stop. It never listens unless explicitly selected.
   - **Per-panel volume**: Large `−` and `+` controls adjust each incoming panel independently in 20% steps.
   - **Panel visibility**: Operators see every other station, including blocked/non-assigned stations, but never see their own station. Blocked stations remain disabled.
   - **Live Speaker Ring Indicator**: Visual indication when audio is flowing from active speakers.

2. **Admin-Controlled Routing & Permission Matrix**:
   - Interactive 20×20 scrollable matrix grid for System Admins.
   - Tap cell to cycle states: `Blocked` ➔ `Talk` ➔ `Listen` ➔ `Both`.
   - **Live SFU Enforcement**: Permission changes update active calls in under 1 second without reconnecting.
   - **Operator accounts**: Admins provision stations with a username and a password of at least 4 characters. New routes are blocked until configured.
   - **Named matrix snapshots**: Admins can save, load, blank, and delete named route snapshots locally on the device/browser. Loading a snapshot applies its routes to the server; credentials are never stored in snapshots.

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

### 2. Run Mobile App
```powershell
# Start Metro bundler
cd mobile
npx react-native start

# Run on Android (in another terminal)
cd mobile
npx react-native run-android
```

### 3. Build a standalone Android APK

The release APK bundles the JavaScript application and does not require Metro on the phone:

```powershell
cd mobile/android
.\gradlew.bat assembleRelease --no-daemon
```

The APK is generated at `mobile/android/app/build/outputs/apk/release/app-release.apk`. Before building, set `mobile/src/config.ts` to the public HTTPS backend URL (for example, your Render service URL). The backend must also expose the public LiveKit values: `LIVEKIT_HOST` with `https://` and `LIVEKIT_URL` with `wss://`.

---

After signing in, open **Stations** to create each operator's station and sign-in. New station-to-station routes are blocked by default. Open **Matrix** to set the permitted talk, listen, or full-duplex paths before operators connect.
