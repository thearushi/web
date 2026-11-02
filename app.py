import sys
import os
import json
import time
import base64
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

# Direct execution auto-launcher: enables running with `python app.py` or VS Code Run button
if __name__ == "__main__" and not st.runtime.exists():
    from streamlit.web import cli as stcli
    sys.argv = ["streamlit", "run", os.path.abspath(__file__), "--server.headless=true", "--browser.gatherUsageStats=false"]
    sys.exit(stcli.main())

# Import the core scanner engine and storage from webvulnscanner.py
from webvulnscanner import scan_url, load_history, calculate_stats, save_history, save_scan_to_history

# ---------------------------------------------------------
# Asset Loading (Relative Paths for local & Cloud deployment)
# ---------------------------------------------------------
base_dir = os.path.dirname(os.path.abspath(__file__))

# 1. Hacker Hero Backdrop Artwork
hacker_bg_path = os.path.join(base_dir, "assets", "hacker_bg.png")
if not os.path.exists(hacker_bg_path):
    hacker_bg_path = os.path.join(base_dir, "assets", "cyber_hero.jpg")

hacker_b64 = ""
if os.path.exists(hacker_bg_path):
    try:
        with open(hacker_bg_path, "rb") as f:
            hacker_b64 = base64.b64encode(f.read()).decode("utf-8")
    except Exception:
        hacker_b64 = ""

# 2. Cyber Background Animation Script (No matrix falling text!)
bg_script_path = os.path.join(base_dir, "background.js")
bg_code = ""
if os.path.exists(bg_script_path):
    try:
        with open(bg_script_path, "r", encoding="utf-8") as f:
            bg_code = f.read()
    except Exception:
        bg_code = ""

# ---------------------------------------------------------
# Streamlit Page Configuration
# ---------------------------------------------------------
st.set_page_config(
    page_title="VigilSec | Web Vulnerability Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------------------------------------------------
# Initialize Session State
# ---------------------------------------------------------
if "active_nav" not in st.session_state:
    st.session_state["active_nav"] = "Dashboard"

if "target_url_input" not in st.session_state:
    st.session_state["target_url_input"] = "https://example.com"

if "trigger_scan" not in st.session_state:
    st.session_state["trigger_scan"] = False

# ---------------------------------------------------------
# Cyber SOC Operations Dashboard CSS
# ---------------------------------------------------------
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&family=Orbitron:wght@600;700;800;900&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');

    :root {
        --bg-main: #050510;
        --bg-secondary: #0A0D1A;
        --electric-blue: #087BFF;
        --neon-purple: #9B30FF;
        --crimson-red: #FF1744;
        --cyber-cyan: #00E5FF;
        --text-primary: #F0F3FF;
        --text-secondary: #AAB4CC;
        --glass-panel: rgba(10, 13, 26, 0.72);
        --glass-border: rgba(8, 123, 255, 0.28);
    }

    html, body {
        font-family: 'Plus Jakarta Sans', 'Inter', -apple-system, sans-serif;
        background-color: #050510 !important;
        color: #F0F3FF !important;
        overflow-x: hidden;
    }

    /* Keep all Streamlit inner containers transparent so background canvas shines through */
    .stApp, [data-testid="stAppViewContainer"], [data-testid="stMain"], 
    [data-testid="stMainBlockContainer"], .main, [data-testid="stHeader"],
    section.main, div[data-testid="stVerticalBlock"] {
        background: transparent !important;
        background-color: transparent !important;
    }

    /* Fixed Full-Screen Background Animation Canvas */
    #cyber-bg-canvas {
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        width: 100vw !important;
        height: 100vh !important;
        z-index: 0 !important;
        pointer-events: none !important;
    }

    div[data-testid="stCustomComponentV1"], div[data-testid="stIFrame"] {
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        width: 100vw !important;
        height: 100vh !important;
        z-index: 0 !important;
        pointer-events: none !important;
        margin: 0 !important;
        padding: 0 !important;
        border: none !important;
    }

    /* Monospace elements */
    code, pre, .mono-font, .mono-url {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Main Container Padding & Max Width */
    .block-container {
        position: relative !important;
        z-index: 1 !important;
        padding-top: 1.2rem !important;
        padding-bottom: 3.5rem !important;
        max-width: 1240px !important;
    }

    /* ----------------------------------------------------- */
    /* Sidebar Styling */
    /* ----------------------------------------------------- */
    section[data-testid="stSidebar"] {
        background: rgba(10, 13, 26, 0.88) !important;
        backdrop-filter: blur(24px) saturate(180%) !important;
        border-right: 1.5px solid rgba(8, 123, 255, 0.22) !important;
        box-shadow: 4px 0 30px rgba(0, 0, 0, 0.6) !important;
        z-index: 10 !important;
    }

    section[data-testid="stSidebar"] div[data-testid="stVerticalBlock"] {
        gap: 0.5rem !important;
    }

    .sidebar-brand-box {
        display: flex;
        align-items: center;
        gap: 14px;
        margin-bottom: 22px;
        padding-bottom: 16px;
        border-bottom: 1px solid rgba(8, 123, 255, 0.25);
    }

    .brand-title {
        font-family: 'Orbitron', sans-serif;
        font-size: 1.4rem;
        font-weight: 800;
        margin: 0;
        color: #F0F3FF;
        letter-spacing: 0.04em;
    }
    .brand-sec {
        color: #FF1744;
        text-shadow: 0 0 14px rgba(255, 23, 68, 0.6);
    }
    .brand-subtitle {
        font-size: 0.74rem;
        color: #AAB4CC;
        margin: 2px 0 0 0;
        font-weight: 500;
        letter-spacing: 0.05em;
    }

    .sidebar-section-title {
        font-size: 0.76rem;
        font-weight: 700;
        color: #00E5FF;
        text-transform: uppercase;
        letter-spacing: 0.12em;
        margin: 18px 0 8px 4px;
    }

    /* Sidebar Buttons */
    section[data-testid="stSidebar"] .stButton > button {
        background: rgba(10, 13, 26, 0.65) !important;
        border: 1px solid rgba(8, 123, 255, 0.22) !important;
        border-radius: 10px !important;
        color: #AAB4CC !important;
        font-family: 'Plus Jakarta Sans', sans-serif !important;
        font-weight: 600 !important;
        font-size: 0.88rem !important;
        text-align: left !important;
        justify-content: flex-start !important;
        padding: 9px 14px !important;
        transition: all 0.22s cubic-bezier(0.4, 0, 0.2, 1) !important;
        width: 100% !important;
        box-shadow: none !important;
    }

    section[data-testid="stSidebar"] .stButton > button:hover {
        border-color: #087BFF !important;
        color: #F0F3FF !important;
        background: rgba(8, 123, 255, 0.15) !important;
        box-shadow: 0 0 16px rgba(8, 123, 255, 0.35) !important;
        transform: translateX(3px) !important;
    }

    /* Active Navigation Item Glowing Border Pill */
    .nav-btn-active button {
        background: linear-gradient(90deg, rgba(8, 123, 255, 0.30) 0%, rgba(155, 48, 255, 0.38) 100%) !important;
        border: 1.5px solid #087BFF !important;
        color: #FFFFFF !important;
        box-shadow: 0 0 18px rgba(155, 48, 255, 0.42), inset 0 0 12px rgba(8, 123, 255, 0.25) !important;
    }

    /* ----------------------------------------------------- */
    /* Top Header HUD & Scanner Ready Badge */
    /* ----------------------------------------------------- */
    .top-hud-row {
        display: flex;
        justify-content: flex-end;
        align-items: center;
        margin-bottom: 8px;
    }

    .scanner-ready-badge {
        display: inline-flex;
        align-items: center;
        gap: 9px;
        background: rgba(5, 15, 28, 0.85);
        border: 1px solid rgba(0, 229, 255, 0.35);
        border-radius: 20px;
        padding: 5px 15px;
        font-family: 'Plus Jakarta Sans', sans-serif;
        font-size: 0.82rem;
        font-weight: 600;
        color: #00E5FF;
        box-shadow: 0 0 16px rgba(0, 229, 255, 0.15), inset 0 0 10px rgba(0, 229, 255, 0.04);
    }

    .scanner-pulse-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: #00ff88;
        box-shadow: 0 0 8px #00ff88;
        animation: pulseAnimation 2s infinite ease-in-out;
    }

    @keyframes pulseAnimation {
        0%, 100% {
            transform: scale(0.9);
            opacity: 0.6;
            box-shadow: 0 0 4px #00ff88;
        }
        50% {
            transform: scale(1.35);
            opacity: 1;
            box-shadow: 0 0 12px #00ff88;
        }
    }

    /* ----------------------------------------------------- */
    /* Top Hacker Hero Backdrop Artwork */
    /* ----------------------------------------------------- */
    .hacker-hero-wrapper {
        position: relative;
        text-align: center;
        margin-bottom: 12px;
    }

    .hacker-hero-artwork {
        display: flex;
        justify-content: center;
        align-items: center;
        margin-bottom: -18px;
        pointer-events: none;
    }

    .hacker-artwork-img {
        max-width: 580px;
        width: 90%;
        height: auto;
        filter: drop-shadow(0 0 25px rgba(8, 123, 255, 0.35)) drop-shadow(0 0 45px rgba(255, 23, 68, 0.25));
        mask-image: linear-gradient(to bottom, rgba(0,0,0,1) 70%, rgba(0,0,0,0) 100%);
        -webkit-mask-image: linear-gradient(to bottom, rgba(0,0,0,1) 70%, rgba(0,0,0,0) 100%);
    }

    /* ----------------------------------------------------- */
    /* Main Hero Banner Container */
    /* ----------------------------------------------------- */
    .hero-container {
        background: rgba(10, 13, 26, 0.78);
        border: 1.5px solid rgba(8, 123, 255, 0.45);
        border-radius: 16px;
        padding: 24px 28px;
        margin-bottom: 22px;
        backdrop-filter: blur(18px);
        box-shadow: 0 0 30px rgba(8, 123, 255, 0.20), inset 0 0 18px rgba(155, 48, 255, 0.10);
        display: flex;
        align-items: center;
        justify-content: space-between;
        position: relative;
        overflow: hidden;
    }

    .hero-center-content {
        display: flex;
        align-items: center;
        gap: 18px;
        flex: 1;
        justify-content: center;
    }

    .circuit-wing {
        width: 95px;
        height: 48px;
        opacity: 0.85;
        flex-shrink: 0;
    }

    .hero-title {
        font-family: 'Orbitron', sans-serif;
        font-size: 2.1rem;
        font-weight: 800;
        margin: 0;
        letter-spacing: 0.03em;
        line-height: 1.2;
    }

    .title-vigil {
        color: #00E5FF;
        text-shadow: 0 0 14px rgba(0, 229, 255, 0.5);
    }
    .title-app {
        color: #F0F3FF;
    }
    .title-scanner {
        color: #FF1744;
        text-shadow: 0 0 16px rgba(255, 23, 68, 0.55);
    }

    .hero-subtitle {
        color: #AAB4CC;
        font-size: 0.95rem;
        margin: 6px 0 0 0;
        font-weight: 500;
        letter-spacing: 0.02em;
    }

    /* ----------------------------------------------------- */
    /* URL Input Section & Start Scan Button */
    /* ----------------------------------------------------- */
    div[data-testid="stTextInput"] input {
        background: rgba(10, 13, 26, 0.82) !important;
        border: 1.5px solid #087BFF !important;
        border-radius: 12px !important;
        color: #F0F3FF !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 1.05rem !important;
        padding: 13px 18px !important;
        box-shadow: 0 0 16px rgba(8, 123, 255, 0.25), inset 0 0 10px rgba(8, 123, 255, 0.08) !important;
        transition: all 0.25s ease !important;
    }

    div[data-testid="stTextInput"] input:focus {
        border-color: #00E5FF !important;
        box-shadow: 0 0 24px rgba(0, 229, 255, 0.45), inset 0 0 12px rgba(0, 229, 255, 0.12) !important;
    }

    /* Start Scan Primary Action Button */
    .stButton > button[kind="primary"] {
        background: linear-gradient(90deg, #FF1744 0%, #9B30FF 100%) !important;
        border: 1.2px solid rgba(255, 23, 68, 0.85) !important;
        border-radius: 12px !important;
        color: #FFFFFF !important;
        font-family: 'Orbitron', 'Plus Jakarta Sans', sans-serif !important;
        font-weight: 700 !important;
        font-size: 1.08rem !important;
        letter-spacing: 0.04em !important;
        padding: 12px 26px !important;
        box-shadow: 0 0 22px rgba(255, 23, 68, 0.48), 0 0 35px rgba(155, 48, 255, 0.25) !important;
        transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1) !important;
        height: 52px !important;
    }

    .stButton > button[kind="primary"]:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 0 32px rgba(255, 23, 68, 0.72), 0 0 50px rgba(155, 48, 255, 0.45) !important;
        border-color: #FF1744 !important;
    }

    /* ----------------------------------------------------- */
    /* Advanced Network Socket & Audit Controls Expander */
    /* ----------------------------------------------------- */
    div[data-testid="stExpander"] {
        background: rgba(10, 13, 26, 0.74) !important;
        border: 1.5px solid rgba(8, 123, 255, 0.35) !important;
        border-radius: 14px !important;
        backdrop-filter: blur(16px) !important;
        box-shadow: 0 6px 24px rgba(0, 0, 0, 0.5) !important;
        margin-bottom: 22px !important;
    }

    div[data-testid="stExpander"] summary {
        color: #F0F3FF !important;
        font-family: 'Plus Jakarta Sans', sans-serif !important;
        font-weight: 700 !important;
        font-size: 1.02rem !important;
        padding: 12px 18px !important;
    }

    div[data-testid="stExpander"] summary:hover {
        color: #00E5FF !important;
    }

    .control-box-header {
        display: flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 12px;
        padding-bottom: 8px;
        border-bottom: 1px solid rgba(8, 123, 255, 0.20);
    }

    .control-box-icon {
        font-size: 1.25rem;
    }

    .control-box-title {
        font-size: 1.02rem;
        font-weight: 700;
        color: #F0F3FF;
        letter-spacing: 0.02em;
    }

    /* ----------------------------------------------------- */
    /* 4 Bottom SOC Statistics Cards */
    /* ----------------------------------------------------- */
    .stat-cards-container {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 16px;
        margin: 20px 0 26px 0;
    }

    .soc-stat-card {
        background: rgba(10, 13, 26, 0.76);
        border-radius: 14px;
        padding: 16px 18px;
        display: flex;
        align-items: center;
        gap: 16px;
        backdrop-filter: blur(14px);
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }

    .soc-stat-card:hover {
        transform: translateY(-3px);
    }

    .card-electric-blue {
        border: 1.5px solid rgba(8, 123, 255, 0.55);
        box-shadow: 0 4px 22px rgba(0, 0, 0, 0.5), inset 0 0 12px rgba(8, 123, 255, 0.12);
    }
    .card-electric-blue:hover {
        box-shadow: 0 6px 28px rgba(8, 123, 255, 0.35), inset 0 0 16px rgba(8, 123, 255, 0.18);
    }

    .card-crimson-red {
        border: 1.5px solid rgba(255, 23, 68, 0.55);
        box-shadow: 0 4px 22px rgba(0, 0, 0, 0.5), inset 0 0 12px rgba(255, 23, 68, 0.12);
    }
    .card-crimson-red:hover {
        box-shadow: 0 6px 28px rgba(255, 23, 68, 0.35), inset 0 0 16px rgba(255, 23, 68, 0.18);
    }

    .card-neon-purple {
        border: 1.5px solid rgba(155, 48, 255, 0.55);
        box-shadow: 0 4px 22px rgba(0, 0, 0, 0.5), inset 0 0 12px rgba(155, 48, 255, 0.12);
    }
    .card-neon-purple:hover {
        box-shadow: 0 6px 28px rgba(155, 48, 255, 0.35), inset 0 0 16px rgba(155, 48, 255, 0.18);
    }

    .card-cyan {
        border: 1.5px solid rgba(0, 229, 255, 0.55);
        box-shadow: 0 4px 22px rgba(0, 0, 0, 0.5), inset 0 0 12px rgba(0, 229, 255, 0.12);
    }
    .card-cyan:hover {
        box-shadow: 0 6px 28px rgba(0, 229, 255, 0.35), inset 0 0 16px rgba(0, 229, 255, 0.18);
    }

    .stat-icon-wrapper {
        width: 52px;
        height: 52px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
    }

    .icon-blue { background: rgba(8, 123, 255, 0.16); box-shadow: 0 0 14px rgba(8, 123, 255, 0.3); }
    .icon-red { background: rgba(255, 23, 68, 0.16); box-shadow: 0 0 14px rgba(255, 23, 68, 0.3); }
    .icon-purple { background: rgba(155, 48, 255, 0.16); box-shadow: 0 0 14px rgba(155, 48, 255, 0.3); }
    .icon-cyan { background: rgba(0, 229, 255, 0.16); box-shadow: 0 0 14px rgba(0, 229, 255, 0.3); }

    .stat-meta {
        display: flex;
        flex-direction: column;
    }

    .stat-number {
        font-family: 'Orbitron', sans-serif;
        font-size: 1.85rem;
        font-weight: 800;
        line-height: 1.1;
    }

    .num-blue { color: #087BFF; text-shadow: 0 0 12px rgba(8, 123, 255, 0.4); }
    .num-red { color: #FF1744; text-shadow: 0 0 12px rgba(255, 23, 68, 0.4); }
    .num-purple { color: #9B30FF; text-shadow: 0 0 12px rgba(155, 48, 255, 0.4); }
    .num-cyan { color: #00E5FF; text-shadow: 0 0 12px rgba(0, 229, 255, 0.4); }

    .stat-label {
        font-size: 0.73rem;
        font-weight: 700;
        color: #AAB4CC;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-top: 4px;
    }

    /* ----------------------------------------------------- */
    /* Scan Results & Vulnerability Report Styling */
    /* ----------------------------------------------------- */
    .score-banner {
        background: radial-gradient(circle at top right, rgba(8, 123, 255, 0.15), rgba(10, 13, 26, 0.95));
        border: 1.5px solid rgba(8, 123, 255, 0.40);
        border-radius: 16px;
        padding: 24px 28px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 20px;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.6), inset 0 0 15px rgba(8, 123, 255, 0.10);
    }

    .grade-badge {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 84px;
        height: 84px;
        border-radius: 20px;
        font-family: 'Orbitron', sans-serif;
        font-size: 2.8rem;
        font-weight: 900;
        color: white;
        text-shadow: 0 2px 10px rgba(0,0,0,0.6);
        box-shadow: 0 8px 24px -4px rgba(0,0,0,0.5), 0 0 24px currentColor;
    }

    /* Severity Indicators */
    .sev-badge {
        display: inline-block;
        font-size: 0.72rem;
        font-weight: 800;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        padding: 3px 10px;
        border-radius: 6px;
        margin-right: 10px;
    }
    .sev-CRITICAL {
        background: rgba(255, 23, 68, 0.22);
        color: #FF1744;
        border: 1px solid #FF1744;
        box-shadow: 0 0 10px rgba(255, 23, 68, 0.35);
    }
    .sev-HIGH {
        background: rgba(225, 29, 72, 0.20);
        color: #fb7185;
        border: 1px solid #e11d48;
    }
    .sev-MEDIUM {
        background: rgba(245, 158, 11, 0.18);
        color: #fbbf24;
        border: 1px solid rgba(245, 158, 11, 0.6);
    }
    .sev-LOW {
        background: rgba(8, 123, 255, 0.18);
        color: #38bdf8;
        border: 1px solid rgba(8, 123, 255, 0.5);
    }
    .sev-INFO {
        background: rgba(155, 48, 255, 0.18);
        color: #c084fc;
        border: 1px solid rgba(155, 48, 255, 0.5);
    }
    .sev-ERROR {
        background: rgba(255, 23, 68, 0.25);
        color: #FF1744;
        border: 1px solid #FF1744;
    }

    /* Glass Cards */
    .glass-card {
        background: rgba(10, 13, 26, 0.75);
        border: 1px solid rgba(8, 123, 255, 0.22);
        border-radius: 12px;
        padding: 16px 20px;
        margin-bottom: 14px;
        backdrop-filter: blur(12px);
        transition: transform 0.18s ease, border-color 0.18s ease;
    }
    .glass-card:hover {
        border-color: rgba(0, 229, 255, 0.5);
        transform: translateY(-2px);
    }

    .status-pill {
        display: inline-block;
        font-size: 0.74rem;
        font-weight: 700;
        padding: 3px 10px;
        border-radius: 12px;
    }
    .status-pass {
        background: rgba(16, 185, 129, 0.18);
        color: #10b981;
        border: 1px solid rgba(16, 185, 129, 0.5);
    }
    .status-missing {
        background: rgba(255, 23, 68, 0.18);
        color: #FF1744;
        border: 1px solid rgba(255, 23, 68, 0.5);
    }

    /* Priority Attention Banner */
    .priority-banner {
        background: rgba(255, 23, 68, 0.12);
        border: 2px solid #FF1744;
        border-radius: 14px;
        padding: 16px 22px;
        margin: 18px 0;
        box-shadow: 0 0 20px rgba(255, 23, 68, 0.25);
        display: flex;
        align-items: center;
        gap: 16px;
    }

    /* Responsive adjustments */
    @media (max-width: 992px) {
        .stat-cards-container {
            grid-template-columns: repeat(2, 1fr) !important;
            gap: 12px !important;
        }
        .hero-title {
            font-size: 1.65rem !important;
        }
        .circuit-wing {
            display: none !important;
        }
        .score-banner {
            flex-direction: column !important;
            text-align: center !important;
            gap: 16px !important;
        }
    }

    @media (max-width: 600px) {
        .stat-cards-container {
            grid-template-columns: 1fr !important;
        }
        .hero-title {
            font-size: 1.35rem !important;
        }
        .hero-container {
            padding: 16px !important;
        }
        .hero-center-content {
            flex-direction: column !important;
            text-align: center !important;
        }
    }

    .footer-soc-note {
        text-align: center;
        font-size: 0.8rem;
        color: #64748b;
        margin-top: 50px;
        padding-top: 20px;
        border-top: 1px solid rgba(255, 255, 255, 0.08);
    }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------
# Cyber Canvas Background Layer (Fixed 60FPS Animation)
# ---------------------------------------------------------
cyber_bg_html = f"""
<canvas id="cyber-bg-canvas"></canvas>
<script>
{bg_code}
</script>
"""
try:
    st.html(cyber_bg_html, unsafe_allow_javascript=True)
except Exception:
    components.html(cyber_bg_html, height=0)


# ---------------------------------------------------------
# Sidebar Navigation & Knowledge Center
# ---------------------------------------------------------
with st.sidebar:
    # Top Branding Header
    st.markdown("""
    <div class="sidebar-brand-box">
        <svg width="42" height="42" viewBox="0 0 100 100" fill="none">
            <path d="M50 8 L85 24 V52 C85 75 50 92 50 92 C50 92 15 75 15 52 V24 L50 8 Z" 
                  stroke="#00E5FF" stroke-width="4.5" fill="rgba(8, 123, 255, 0.2)"/>
            <path d="M50 20 L74 32 V52 C74 68 50 80 50 80 C50 80 26 68 26 52 V32 L50 20 Z" 
                  fill="rgba(5, 8, 17, 0.9)" stroke="#9B30FF" stroke-width="2"/>
            <circle cx="50" cy="50" r="14" stroke="#00E5FF" stroke-width="2" stroke-dasharray="3 2"/>
            <circle cx="50" cy="50" r="5" fill="#FF1744"/>
            <line x1="50" y1="30" x2="50" y2="70" stroke="#00E5FF" stroke-width="1.8"/>
            <line x1="30" y1="50" x2="70" y2="50" stroke="#00E5FF" stroke-width="1.8"/>
        </svg>
        <div>
            <h2 class="brand-title">Vigil<span class="brand-sec">Sec</span></h2>
            <p class="brand-subtitle">Web Vulnerability Scanner</p>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Navigation Menu
    active_nav = st.session_state.get("active_nav", "Dashboard")

    nav_items = [
        ("Dashboard", "🏠 Dashboard"),
        ("New Scan", "🎯 New Scan"),
        ("Scan History", "📊 Scan History"),
        ("Reports", "📋 Reports"),
        ("Settings", "⚙️ Settings"),
    ]

    for nav_id, label in nav_items:
        is_active = (active_nav == nav_id)
        btn_class = "nav-btn-active" if is_active else "nav-btn-normal"
        st.markdown(f'<div class="{btn_class}">', unsafe_allow_html=True)
        if st.button(label, key=f"nav_{nav_id}", use_container_width=True):
            st.session_state["active_nav"] = nav_id
            if nav_id == "New Scan":
                st.session_state["target_url_input"] = ""
                st.session_state["active_nav"] = "Dashboard"
            st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="sidebar-section-title">⚡ Quick Scan</div>', unsafe_allow_html=True)
    presets = [
        ("🐙 GitHub (A+)", "https://github.com"),
        ("☁️ Cloudflare", "https://www.cloudflare.com"),
        ("🌐 Example.com", "https://example.com"),
        ("🧪 Insecure Demo", "http://neverssl.com"),
    ]

    for label, preset_url in presets:
        if st.button(label, key=f"quick_{label}", use_container_width=True):
            st.session_state["target_url_input"] = preset_url
            st.session_state["active_nav"] = "Dashboard"
            st.session_state["trigger_scan"] = True
            st.rerun()

    st.markdown("---")
    with st.expander("🛡️ OWASP Audit Rules"):
        st.markdown("""
        - **HSTS**: Force TLS browser transport.
        - **CSP**: Prevent XSS code injections.
        - **X-Content-Type-Options**: Block MIME sniffing.
        - **X-Frame-Options**: Defeat Clickjacking.
        - **Referrer-Policy**: Stop metadata leakage.
        - **Permissions-Policy**: Restrict camera/geo APIs.
        """)


# =========================================================
# MAIN CONTENT AREA
# =========================================================
active_view = st.session_state.get("active_nav", "Dashboard")

# ---------------------------------------------------------
# VIEW: Scan History
# ---------------------------------------------------------
if active_view == "Scan History":
    st.markdown("## 📊 Scan History & Security Assessment Logs")
    history_data = load_history()
    
    if not history_data:
        st.info("ℹ️ No historical scans recorded yet. Run a scan from the Dashboard to build history.")
    else:
        stats = calculate_stats(history_data)
        st.markdown(f"**Total Scans Stored:** {len(history_data)} &bull; **Unique Targets:** {stats['targets_scanned']} &bull; **Average Latency:** {stats['avg_scan_time']}s")
        
        hist_table = []
        for h in history_data:
            score = h.get("score", {})
            hist_table.append({
                "Timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(h.get("timestamp", time.time()))),
                "Target URL": h.get("url", "N/A"),
                "Grade": score.get("grade", "N/A"),
                "Score": f"{score.get('score', 0)}/100",
                "HTTP Status": h.get("status", "N/A"),
                "Findings": h.get("findings_count", 0),
                "Latency (s)": f"{h.get('elapsed', 0):.2f}"
            })
        
        df_hist = pd.DataFrame(hist_table)
        st.dataframe(df_hist, use_container_width=True, hide_index=True)
        
        col_h1, col_h2 = st.columns([1, 4])
        with col_h1:
            if st.button("🗑️ Clear History", use_container_width=True):
                save_history([])
                st.success("Scan history cleared successfully.")
                st.rerun()

# ---------------------------------------------------------
# VIEW: Reports
# ---------------------------------------------------------
elif active_view == "Reports":
    st.markdown("## 📋 Security Assessment Reports & Export Center")
    history_data = load_history()
    
    if not history_data:
        st.info("ℹ️ No scan assessments available to report. Run a scan on a target URL first.")
    else:
        target_options = [f"{h.get('url')} ({time.strftime('%Y-%m-%d %H:%M', time.localtime(h.get('timestamp', 0)))})" for h in history_data]
        selected_target_str = st.selectbox("Select Target Audit Assessment:", target_options)
        
        idx = target_options.index(selected_target_str)
        report_item = history_data[idx]
        
        st.markdown(f"""
        <div class="glass-card" style="border: 1.5px solid #087BFF; margin-top: 16px;">
            <h3>Security Report: {report_item.get('url')}</h3>
            <p><strong>Grade:</strong> {report_item.get('score', {}).get('grade')} ({report_item.get('score', {}).get('score')}/100) &bull; 
               <strong>Status Code:</strong> {report_item.get('status')} &bull; 
               <strong>Scan Latency:</strong> {report_item.get('elapsed', 0):.2f}s</p>
            <p><strong>Vulnerabilities &amp; Findings:</strong> {report_item.get('findings_count')} total ({report_item.get('high_count', 0)} High/Critical)</p>
        </div>
        """, unsafe_allow_html=True)
        
        report_json = json.dumps(report_item, indent=2)
        st.download_button(
            label="📄 Download Assessment JSON Report",
            data=report_json,
            file_name=f"vigilsec_report_{int(time.time())}.json",
            mime="application/json"
        )

# ---------------------------------------------------------
# VIEW: Settings
# ---------------------------------------------------------
elif active_view == "Settings":
    st.markdown("## ⚙️ Scanner & Network Socket Settings")
    st.markdown("Configure global network defaults, audit thresholds, and scanner headers.")
    
    with st.form("settings_form"):
        st.text_input("Default User-Agent Header", value="Mozilla/5.0 (Windows NT 10.0; Win64; x64) VigilSec/2.0")
        st.number_input("Default Socket Connection Timeout (s)", min_value=1, max_value=60, value=8)
        st.number_input("Maximum Network Threads Pool", min_value=1, max_value=64, value=10)
        st.checkbox("Always Verify SSL Certificates strictly", value=True)
        st.checkbox("Enable Automatic Reverse DNS Lookup by Default", value=True)
        
        saved = st.form_submit_button("Save Scanner Settings")
        if saved:
            st.success("✅ Scanner preferences saved.")

# ---------------------------------------------------------
# VIEW: Main Dashboard (Default)
# ---------------------------------------------------------
else:
    # Top Status Pill & Cyber Hacker Visual
    hacker_img_tag = f'<img src="data:image/png;base64,{hacker_b64}" alt="VigilSec Cyber Shield" class="hacker-artwork-img" />' if hacker_b64 else ""

    st.markdown(f"""
    <div class="hacker-hero-wrapper">
        <div class="top-hud-row">
            <div class="scanner-ready-badge">
                <span class="scanner-pulse-dot"></span> Scanner Ready
            </div>
        </div>
        <div class="hacker-hero-artwork">
            {hacker_img_tag}
        </div>
        <div class="hero-container">
            <div class="circuit-wing circuit-left">
                <svg viewBox="0 0 100 50" fill="none">
                    <path d="M 5 25 H 45 L 65 12 H 95" stroke="#00E5FF" stroke-width="2.2" stroke-linecap="round"/>
                    <circle cx="5" cy="25" r="3.5" fill="#00E5FF"/>
                    <path d="M 20 40 H 50 L 70 48 H 95" stroke="#087BFF" stroke-width="1.8" stroke-linecap="round"/>
                    <circle cx="20" cy="40" r="2.5" fill="#087BFF"/>
                </svg>
            </div>
            <div class="hero-center-content">
                <div class="hero-shield-icon">
                    <svg width="58" height="58" viewBox="0 0 100 100" fill="none">
                        <path d="M 50 8 L 85 24 V 52 C 85 75 50 92 50 92 C 50 92 15 75 15 52 V 24 L 50 8 Z" 
                              stroke="#00E5FF" stroke-width="4.5" fill="rgba(8, 123, 255, 0.2)"/>
                        <circle cx="50" cy="48" r="20" stroke="#00E5FF" stroke-width="2.2" stroke-dasharray="4 2"/>
                        <circle cx="50" cy="48" r="8" fill="#00E5FF"/>
                        <line x1="50" y1="22" x2="50" y2="74" stroke="#00E5FF" stroke-width="2"/>
                        <line x1="24" y1="48" x2="76" y2="48" stroke="#00E5FF" stroke-width="2"/>
                    </svg>
                </div>
                <div>
                    <h1 class="hero-title"><span class="title-vigil">VigilSec</span> <span class="title-app">Application</span> <span class="title-scanner">Scanner</span></h1>
                    <p class="hero-subtitle">Automated web vulnerability analysis &amp; security assessment</p>
                </div>
            </div>
            <div class="circuit-wing circuit-right">
                <svg viewBox="0 0 100 50" fill="none">
                    <path d="M 5 12 H 35 L 55 25 H 95" stroke="#FF1744" stroke-width="2.2" stroke-linecap="round"/>
                    <circle cx="95" cy="25" r="3.5" fill="#FF1744"/>
                    <path d="M 5 48 H 30 L 50 40 H 80" stroke="#9B30FF" stroke-width="1.8" stroke-linecap="round"/>
                    <circle cx="80" cy="40" r="2.5" fill="#9B30FF"/>
                </svg>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # -----------------------------------------------------
    # Website Scan Input Row
    # -----------------------------------------------------
    current_target = st.session_state.get("target_url_input", "https://example.com")

    col_input, col_btn = st.columns([4, 1.2], vertical_alignment="center")

    with col_input:
        target_url = st.text_input(
            "Target URL",
            value=current_target,
            placeholder="https://example.com",
            label_visibility="collapsed",
            key="main_target_input"
        )

    with col_btn:
        scan_clicked = st.button("▷ Start Scan", type="primary", use_container_width=True, key="start_scan_btn")

    # -----------------------------------------------------
    # Advanced Network Socket & Audit Controls
    # -----------------------------------------------------
    with st.expander("⚙️ Advanced Network Socket & Audit Controls", expanded=True):
        col_c1, col_c2 = st.columns(2)
        with col_c1:
            st.markdown("""
            <div class="control-box-header">
                <span class="control-box-icon">🛡️</span>
                <span class="control-box-title">Audit & Display Controls</span>
            </div>
            """, unsafe_allow_html=True)
            enable_reverse_dns = st.checkbox("Enable Automatic Reverse DNS Lookup", value=True, key="adv_rdns")
            highlight_high_risk = st.checkbox("Highlight High-Risk & Critical Findings", value=True, key="adv_highlight")
            show_monospace_urls = st.checkbox("Show Monospace URLs for Clarity", value=True, key="adv_monospace")
            show_terminal_feed = st.checkbox("Show Monospace Live Terminal Socket Feed", value=True, key="adv_term")

        with col_c2:
            st.markdown("""
            <div class="control-box-header">
                <span class="control-box-icon">🖧</span>
                <span class="control-box-title">Network Socket Limits</span>
            </div>
            """, unsafe_allow_html=True)
            max_threads = st.number_input("Maximum Network Threads", min_value=1, max_value=64, value=10, step=1, key="adv_threads")
            socket_timeout = st.number_input("Socket Timeout (seconds)", min_value=1, max_value=60, value=8, step=1, key="adv_timeout")

    # -----------------------------------------------------
    # Dynamic Statistics Calculated from Real Data
    # -----------------------------------------------------
    stats = calculate_stats(load_history())
    scans_val = stats["total_scans"]
    vulns_val = stats["total_vulns"]
    targets_val = stats["targets_scanned"]
    avg_time_val = f"{stats['avg_scan_time']}s"

    st.markdown(f"""
    <div class="stat-cards-container">
        <div class="soc-stat-card card-electric-blue">
            <div class="stat-icon-wrapper icon-blue">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#087BFF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="10"></circle>
                    <line x1="22" y1="12" x2="18" y2="12"></line>
                    <line x1="6" y1="12" x2="2" y2="12"></line>
                    <line x1="12" y1="6" x2="12" y2="2"></line>
                    <line x1="12" y1="22" x2="12" y2="18"></line>
                    <circle cx="12" cy="12" r="3"></circle>
                </svg>
            </div>
            <div class="stat-meta">
                <span class="stat-number num-blue">{scans_val}</span>
                <span class="stat-label">SCANS PERFORMED</span>
            </div>
        </div>

        <div class="soc-stat-card card-crimson-red">
            <div class="stat-icon-wrapper icon-red">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#FF1744" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                    <line x1="12" y1="8" x2="12" y2="12"></line>
                    <line x1="12" y1="16" x2="12.01" y2="16"></line>
                </svg>
            </div>
            <div class="stat-meta">
                <span class="stat-number num-red">{vulns_val}</span>
                <span class="stat-label">VULNERABILITIES FOUND</span>
            </div>
        </div>

        <div class="soc-stat-card card-neon-purple">
            <div class="stat-icon-wrapper icon-purple">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#9B30FF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="10"></circle>
                    <circle cx="12" cy="12" r="6"></circle>
                    <circle cx="12" cy="12" r="2"></circle>
                </svg>
            </div>
            <div class="stat-meta">
                <span class="stat-number num-purple">{targets_val}</span>
                <span class="stat-label">TARGETS SCANNED</span>
            </div>
        </div>

        <div class="soc-stat-card card-cyan">
            <div class="stat-icon-wrapper icon-cyan">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#00E5FF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="10"></circle>
                    <polyline points="12 6 12 12 16 14"></polyline>
                </svg>
            </div>
            <div class="stat-meta">
                <span class="stat-number num-cyan">{avg_time_val}</span>
                <span class="stat-label">AVG. SCAN TIME</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # -----------------------------------------------------
    # Execute Scan Logic
    # -----------------------------------------------------
    if st.session_state.get("trigger_scan", False):
        st.session_state["trigger_scan"] = False
        scan_clicked = True
        target_url = st.session_state.get("target_url_input", target_url)

    if scan_clicked:
        clean_url = target_url.strip()
        if not clean_url:
            st.error("⚠️ Please enter a valid website URL or hostname.")
        else:
            with st.spinner(f"🔍 Auditing security configuration & network socket for {clean_url}..."):
                try:
                    scan_result = scan_url(
                        clean_url,
                        timeout=int(socket_timeout),
                        enable_reverse_dns=enable_reverse_dns,
                        max_threads=int(max_threads)
                    )
                    st.session_state["last_result"] = scan_result
                    st.session_state["target_url_input"] = clean_url
                    st.rerun()
                except ValueError as ve:
                    st.error(f"⚠️ Validation Error: {ve}")
                except Exception as e:
                    st.error(f"❌ Scan Failed: {e}")

    # -----------------------------------------------------
    # Scan Results Section
    # -----------------------------------------------------
    result = st.session_state.get("last_result", None)

    if result:
        score_info = result.get("score", {"score": 0, "grade": "F", "color": "#FF1744"})
        grade = score_info.get("grade", "N/A")
        score_num = score_info.get("score", 0)
        grade_color = score_info.get("color", "#087BFF")

        findings = result.get("findings", [])
        crit_count = sum(1 for f in findings if f.get("severity") in ("CRITICAL", "ERROR"))
        high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
        med_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")
        low_count = sum(1 for f in findings if f.get("severity") == "LOW")
        info_count = sum(1 for f in findings if f.get("severity") == "INFO")

        url_font_class = "mono-url" if show_monospace_urls else ""

        # 1. Security Overview Banner
        st.markdown(f"""
        <div class="score-banner">
            <div style="flex: 1;">
                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                    <span style="color: #00E5FF; font-size: 0.82rem; text-transform: uppercase; letter-spacing: 0.12em; font-weight: 700;">Security Posture</span>
                    <span class="status-pill status-pass">PASSIVE AUDIT</span>
                </div>
                <div style="font-size: 1.6rem; font-weight: 700; color: #F0F3FF; margin-bottom: 6px;">
                    Target: <span style="color: #00E5FF;" class="{url_font_class}">{result['url']}</span>
                </div>
                <div style="color: #AAB4CC; font-size: 0.92rem;">
                    Resolved: <span class="mono-font" style="color: #F0F3FF;">{result.get('final_url') or 'N/A'}</span> &bull; 
                    Status: <strong style="color: #00E5FF;">{result.get('status') or 'Failed'}</strong> &bull; 
                    Latency: <strong style="color: #38bdf8;">{result.get('elapsed', 0):.2f}s</strong>
                </div>
            </div>
            <div style="text-align: center; margin-left: 20px;">
                <div class="grade-badge" style="background: {grade_color};">
                    {grade}
                </div>
                <div style="color: #F0F3FF; font-size: 0.9rem; font-weight: 700; margin-top: 8px; font-family: 'Orbitron', sans-serif;">
                    Score: {score_num}/100
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # 2. Network Socket & DNS Intelligence Bar
        dns_info = result.get("dns_info", {})
        if dns_info and (dns_info.get("ip") or dns_info.get("reverse_dns")):
            st.markdown(f"""
            <div style="background: rgba(10, 13, 26, 0.75); border: 1px solid rgba(8, 123, 255, 0.3); border-radius: 12px; padding: 14px 20px; margin-bottom: 18px; display: flex; flex-wrap: wrap; gap: 24px; align-items: center; justify-content: space-between;">
                <div>
                    <span style="color: #AAB4CC; font-size: 0.74rem; text-transform: uppercase; font-weight: 700; letter-spacing: 0.08em;">Target Host IP</span>
                    <div style="color: #00E5FF; font-family: 'JetBrains Mono', monospace; font-size: 0.98rem; font-weight: 600;">{dns_info.get('ip') or 'N/A'}</div>
                </div>
                <div>
                    <span style="color: #AAB4CC; font-size: 0.74rem; text-transform: uppercase; font-weight: 700; letter-spacing: 0.08em;">Reverse DNS (PTR Record)</span>
                    <div style="color: #F0F3FF; font-family: 'JetBrains Mono', monospace; font-size: 0.95rem;">{dns_info.get('reverse_dns') or 'No PTR record'}</div>
                </div>
                <div>
                    <span style="color: #AAB4CC; font-size: 0.74rem; text-transform: uppercase; font-weight: 700; letter-spacing: 0.08em;">Thread Pool Limit</span>
                    <div style="color: #34d399; font-family: 'JetBrains Mono', monospace; font-size: 0.95rem;">{max_threads} Concurrent Workers</div>
                </div>
                <div>
                    <span style="color: #AAB4CC; font-size: 0.74rem; text-transform: uppercase; font-weight: 700; letter-spacing: 0.08em;">Socket Connection Timeout</span>
                    <div style="color: #fbbf24; font-family: 'JetBrains Mono', monospace; font-size: 0.95rem;">{socket_timeout}s</div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        # 3. Monospace Live Terminal Socket Feed (Toggleable)
        if show_terminal_feed and result.get("logs"):
            with st.expander("💻 Monospace Live Terminal Socket & Probe Feed", expanded=False):
                st.code("\n".join(result["logs"]), language="bash")

        # 4. Vulnerability Summary Metrics Row
        m1, m2, m3, m4, m5 = st.columns(5)
        with m1:
            st.metric("Total Findings", len(findings))
        with m2:
            st.metric("Critical / High", crit_count + high_count, delta=f"-{crit_count + high_count}" if (crit_count + high_count) > 0 else "0", delta_color="inverse")
        with m3:
            st.metric("Medium Severity", med_count, delta=f"-{med_count}" if med_count > 0 else "0", delta_color="inverse")
        with m4:
            st.metric("Low Severity", low_count)
        with m5:
            st.metric("Response Time", f"{result.get('elapsed', 0):.2f}s")

        # 5. Priority Attention Alert Callout
        high_critical = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH", "ERROR")]
        if highlight_high_risk and high_critical:
            st.markdown(f"""
            <div class="priority-banner">
                <span style="font-size: 1.8rem;">🚨</span>
                <div>
                    <strong style="color: #FF1744; font-size: 1.08rem; letter-spacing: 0.02em;">PRIORITY ATTENTION: {len(high_critical)} High-Risk / Critical Items Flagged</strong>
                    <div style="color: #fca5a5; font-size: 0.9rem; margin-top: 3px;">
                        Immediate defensive configuration required. Review the flagged findings below to remediate transport security or defensive header gaps.
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        # 6. Structured Assessment Tabs
        tab_findings, tab_headers, tab_tls, tab_cookies, tab_raw, tab_export = st.tabs([
            f"📋 Detailed Findings ({len(findings)})",
            "🛡️ Security Headers Matrix",
            "🔒 TLS/SSL Analysis",
            f"🍪 Cookies Analysis ({len(result.get('cookie_checks', []))})",
            "🌐 Raw Network Headers",
            "📥 Export Assessment"
        ])

        # TAB 1: Detailed Findings
        with tab_findings:
            col_filter, _ = st.columns([2.5, 3.5])
            with col_filter:
                filter_sev = st.selectbox(
                    "Filter findings by severity",
                    ["All", "Critical / High", "Medium", "Low", "Informational"],
                    index=0
                )

            filtered_findings = findings
            if filter_sev == "Critical / High":
                filtered_findings = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH", "ERROR")]
            elif filter_sev == "Medium":
                filtered_findings = [f for f in findings if f.get("severity") == "MEDIUM"]
            elif filter_sev == "Low":
                filtered_findings = [f for f in findings if f.get("severity") == "LOW"]
            elif filter_sev == "Informational":
                filtered_findings = [f for f in findings if f.get("severity") == "INFO"]

            if not filtered_findings:
                st.success("🎉 No vulnerabilities or configuration flaws detected for this category!")
            else:
                for idx, finding in enumerate(filtered_findings, start=1):
                    sev = finding.get("severity", "INFO")
                    sev_class = f"sev-{sev}"
                    border_style = "border: 1.5px solid #FF1744; box-shadow: 0 0 16px rgba(255, 23, 68, 0.25);" if (highlight_high_risk and sev in ("CRITICAL", "HIGH", "ERROR")) else ""

                    st.markdown(f"""
                    <div class="glass-card" style="{border_style}">
                        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
                            <div style="display: flex; align-items: center;">
                                <span class="sev-badge {sev_class}">{sev}</span>
                                <span style="font-weight: 700; font-size: 1.05rem; color: #F0F3FF;">{finding['title']}</span>
                            </div>
                        </div>
                        <div style="margin-bottom: 10px; color: #AAB4CC; font-size: 0.94rem;">
                            <strong style="color: #00E5FF;">Evidence:</strong> {finding['evidence']}
                        </div>
                        <div style="background: rgba(10, 13, 26, 0.65); padding: 12px 16px; border-radius: 8px; border-left: 3px solid #087BFF;">
                            <span style="color: #087BFF; font-weight: 700; font-size: 0.86rem; text-transform: uppercase; letter-spacing: 0.05em;">Remediation Guidance:</span>
                            <div style="color: #F0F3FF; font-size: 0.92rem; margin-top: 3px;">{finding['advice']}</div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

        # TAB 2: Security Headers Matrix
        with tab_headers:
            st.markdown("#### Baseline Defensive Security Headers Audit")
            st.markdown("Modern web browsers enforce strict origin isolation and defensive controls based on these server response headers.")

            header_checks = result.get("header_checks", {})
            if not header_checks:
                st.info("No header information was obtained for this target endpoint.")
            else:
                for header_name, details in header_checks.items():
                    is_present = details["present"]
                    badge_html = '<span class="status-pill status-pass">✔ CONFIGURED</span>' if is_present else '<span class="status-pill status-missing">✖ MISSING</span>'

                    with st.expander(f"{header_name} - {'Present' if is_present else 'Missing'}", expanded=not is_present):
                        col_h1, col_h2 = st.columns([1.2, 2.5])
                        with col_h1:
                            st.markdown(f"**Status:** {badge_html}", unsafe_allow_html=True)
                            st.markdown(f"**Severity if Missing:** `{details['severity_if_missing']}`")
                            st.markdown(f"**Purpose:** {details['description']}")
                        with col_h2:
                            if is_present:
                                st.markdown("**Received Server Value:**")
                                st.code(details["value"] or "(empty)", language="http")
                            else:
                                st.markdown("**Recommended Hardening Directive:**")
                                st.code(f"{header_name}: {details['recommended']}", language="http")

        # TAB 3: TLS/SSL Analysis
        with tab_tls:
            st.markdown("#### Transport Layer Security (TLS/SSL) Inspection")
            parsed_final = result.get("final_url", "")
            is_secure_https = parsed_final.startswith("https://") if parsed_final else result["url"].startswith("https://")

            col_t1, col_t2 = st.columns(2)
            with col_t1:
                st.markdown(f"""
                <div class="glass-card">
                    <h4>HTTPS Transport Encryption</h4>
                    <p>Status: {'<span class="status-pill status-pass">✔ ENCRYPTED (HTTPS)</span>' if is_secure_https else '<span class="status-pill status-missing">✖ INSECURE (HTTP)</span>'}</p>
                    <p style="color: #AAB4CC; font-size: 0.9rem;">
                        Transport layer encryption defends credentials, cookies, and payloads against passive eavesdropping and active MITM tampering.
                    </p>
                </div>
                """, unsafe_allow_html=True)
            with col_t2:
                hsts_info = result.get("header_checks", {}).get("Strict-Transport-Security", {})
                hsts_present = hsts_info.get("present", False)
                st.markdown(f"""
                <div class="glass-card">
                    <h4>HSTS (HTTP Strict Transport Security)</h4>
                    <p>Status: {'<span class="status-pill status-pass">✔ ENFORCED</span>' if hsts_present else '<span class="status-pill status-missing">✖ NOT CONFIGURED</span>'}</p>
                    <p style="color: #AAB4CC; font-size: 0.9rem;">
                        HSTS commands browsers to automatically convert all HTTP links to HTTPS before making network requests.
                    </p>
                </div>
                """, unsafe_allow_html=True)

        # TAB 4: Cookie Security Analysis
        with tab_cookies:
            st.markdown("#### Cookie Security & Attribute Inspection")
            cookie_checks = result.get("cookie_checks", [])

            if not cookie_checks:
                st.info("ℹ️ No `Set-Cookie` directives were returned in this response.")
            else:
                cookie_data = []
                for c in cookie_checks:
                    cookie_data.append({
                        "Name": c["name"],
                        "Secure Flag": "✅ True" if c["secure"] else "❌ Missing",
                        "HttpOnly Flag": "✅ True" if c["httponly"] else "❌ Missing",
                        "SameSite Policy": c["samesite"],
                        "Domain": c["domain"],
                        "Path": c["path"],
                    })

                df_cookies = pd.DataFrame(cookie_data)
                st.dataframe(df_cookies, use_container_width=True, hide_index=True)

                st.markdown("""
                **Defensive Cookie Guidelines:**
                - `Secure`: Restricts cookie transmission exclusively over encrypted HTTPS connections.
                - `HttpOnly`: Disallows client JavaScript (`document.cookie`) access, stopping XSS token theft.
                - `SameSite`: Controls cross-site request inclusion, defusing CSRF attack vectors.
                """)

        # TAB 5: Raw Network Headers
        with tab_raw:
            st.markdown("#### Complete HTTP Response Headers")
            raw_headers = result.get("raw_headers_list", [])

            if raw_headers:
                df_headers = pd.DataFrame(raw_headers, columns=["Header Name", "Header Value"])
                st.dataframe(df_headers, use_container_width=True, hide_index=True)
            else:
                st.write("No raw response headers recorded.")

            with st.expander("🔍 Connection & Socket Metadata"):
                st.json({
                    "Target Input URL": result.get("url"),
                    "Final Redirected URL": result.get("final_url"),
                    "HTTP Status Code": result.get("status"),
                    "Latency": f"{result.get('elapsed', 0):.4f} seconds",
                    "Reverse DNS": result.get("dns_info", {}).get("reverse_dns"),
                    "Host IP": result.get("dns_info", {}).get("ip")
                })

        # TAB 6: Export Assessment Report
        with tab_export:
            st.markdown("#### Export Security Assessment Report")
            st.markdown("Download a comprehensive assessment summary in JSON or Markdown format.")

            report_json = json.dumps(result, indent=2, default=str)

            # Build Markdown executive report
            md_report = f"""# VigilSec Security Assessment Report
- **Target URL**: {result['url']}
- **Final URL**: {result.get('final_url')}
- **Scan Timestamp**: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}
- **HTTP Code**: {result.get('status')}
- **Elapsed Latency**: {result.get('elapsed', 0):.2f}s
- **Security Score**: {score_num}/100 (Grade: {grade})

## Summary of Findings ({len(findings)})
"""
            for i, f in enumerate(findings, 1):
                md_report += f"\n### {i}. [{f.get('severity')}] {f.get('title')}\n"
                md_report += f"- **Evidence**: {f.get('evidence')}\n"
                md_report += f"- **Remediation**: {f.get('advice')}\n"

            col_d1, col_d2 = st.columns(2)
            with col_d1:
                st.download_button(
                    label="📄 Download Assessment JSON",
                    data=report_json,
                    file_name=f"vigilsec_report_{int(time.time())}.json",
                    mime="application/json",
                    use_container_width=True
                )
            with col_d2:
                st.download_button(
                    label="📝 Download Executive Markdown",
                    data=md_report,
                    file_name=f"vigilsec_report_{int(time.time())}.md",
                    mime="text/markdown",
                    use_container_width=True
                )

            st.markdown("##### Preview Raw Assessment JSON")
            st.code(report_json[:1200] + "\n...", language="json")

    # -----------------------------------------------------
    # Footer
    # -----------------------------------------------------
    st.markdown("""
    <div class="footer-soc-note">
        <strong>VigilSec SOC Operations Dashboard</strong> &bull; Automated Web Vulnerability &amp; Transport Layer Security Scanner &bull; Passive Configuration Auditing Engine
    </div>
    """, unsafe_allow_html=True)
