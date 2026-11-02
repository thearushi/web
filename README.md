# 🛡️ VigilSec - Cyber Security Web Vulnerability Scanner & HUD

A fast, passive security baseline audit tool featuring a state-of-the-art **Cyber Security HUD Front-End** with active, high-performance 60FPS background animations, real-time telemetry, and automated security posture scoring.

---

## ⚡ Active Cyber Background Animations

The front-end includes an authentic multi-layered HTML5 Canvas animation engine ([background.js](file:///c:/Users/theaa/Desktop/web%20scanner/background.js)):

1. **3D Rotating Wireframe Cyber Globe**:
   - Rotates smoothly on an inclined polar axis with latitude & longitude rings.
   - Orbiting communication telemetry ring with active data satellites.
   - Real-time pulsating coordinate threat nodes representing global cyber telemetry.
2. **Matrix Digital Code Rain**:
   - Dual-color streams (Cyber Crimson `#ff003c` and Neon Cyan `#00f3ff`).
   - Falling Japanese Katakana, hex characters (`0x4F`, `0x8A`), and binary bits.
   - Glowing lead characters with fading phosphor decay tails.
3. **3D Perspective Cyber Grid Floor**:
   - Receding perspective lines converging towards the horizon vanishing point.
   - Moving horizontal grid pulses and glowing horizon scanner beam.
4. **Interactive Particle Constellation Network**:
   - Floating data packets connecting with dynamic laser lines upon proximity.
   - Reactive mouse repulsion physics.
5. **Top-Right Animated ECG Heartbeat Monitor**:
   - Real-time electrocardiogram / telemetry scan line drawing authentic P-Q-R-S-T cardiac pulses with glowing phosphor persistence.
   - Tag: `SECURE SCAN ANALYZE PROTECT`.

---

## 🎨 Front-End HUD Components (Matching User Design)

- **Left Cyber Sidebar**:
  - Dual-tone glowing cyber shield logo SVG + `VigilSec Web Vulnerability Scanner`.
  - Navigation menu: `Scanner` (active with glowing cyan border), `Scan History` (with dynamic counter), `Quick Targets`, `Settings`, and `About`.
  - `Scanner Options`: Range slider for request timeout with neon red track and real-time `8s` indicator.
  - `Quick Scan Targets`: 1-click presets for GitHub, Cloudflare, Example.com, and Insecure HTTP Demo.
  - Watermark: `VIGILSEC // ACTIVE DEFENSE`.
- **Hero Centerpiece**:
  - Hooded cyber hacker operative background visual ([assets/cyber_hero.jpg](file:///c:/Users/theaa/Desktop/web%20scanner/assets/cyber_hero.jpg)).
  - Glowing shield icon & title: **VigilSec Application Scanner**.
  - Subtitle: *Automated baseline security configuration, TLS inspection, and security header auditing*.
- **Target Input Capsule**:
  - Cyan glowing border pill container with link icon `🔗`.
  - Input field with clear button.
  - Glowing red neon CTA button: `▶ Start Scan →` with hover glow and Web Audio API synthesized sound FX.
- **Advanced Network Socket & Audit Controls**:
  - Beveled futuristic cyber HUD panel with collapse toggle.
  - *Audit & Display Controls*: Checkboxes for Reverse DNS, High-Risk Callouts, and Monospace Live Logs.
  - *Network Socket Limits*: Steppers for Thread Pool Workers (`[-] 10 [+]`) and Connection Timeout (`[-] 8 [+]`).
- **Bottom 4 Neon Stat HUD Cards**:
  - 🎯 **Scans Performed** (Neon Red)
  - 🛡️ **Vulnerabilities Found** (Neon Red)
  - 🌐 **Targets Scanned** (Neon Cyan)
  - ⏱️ **Avg. Scan Time** (Neon Cyan)
  - Bottom badge: `[ HACK • DETECT • DEFEND ]`.
- **Dynamic Results Dashboard**:
  - Active scanning radar HUD and monospace socket connection logs stream.
  - Security Posture Score Banner with neon Grade badge (A+, A, B, C, D, F) and score ring.
  - DNS Intelligence strip (Target IP, PTR Reverse DNS, socket worker limits).
  - High-Risk Critical alert callout banner.
  - 5 interactive tabs:
    1. 📋 **Findings & Guidance** (with severity filters: All, High, Medium, Low, Info, evidence & remediation cards).
    2. 🛡️ **Security Headers Matrix** (Configured vs Missing status badges, received server values, recommended OWASP baseline).
    3. 🍪 **Cookies Analysis** (Secure, HttpOnly, SameSite, Domain, Path).
    4. 🌐 **Raw Network & Response Headers** (Full HTTP header table).
    5. 📥 **Export Report** (1-click download as structured JSON, audit Markdown, or Print/PDF).

---

## 🚀 How to Launch

### Option 1: Modern Cyber HUD Application (Recommended)
Double-click `run.bat` or run in terminal:
```bash
python server.py
```
This automatically launches the server and opens your browser at:
👉 **[http://localhost:5000](http://localhost:5000)**

### Option 2: Streamlit Dashboard
```bash
streamlit run app.py
```
Open your browser at:
👉 **[http://localhost:8501](http://localhost:8501)**

### Option 3: Terminal CLI
```bash
python webvulnscanner.py https://example.com
```
