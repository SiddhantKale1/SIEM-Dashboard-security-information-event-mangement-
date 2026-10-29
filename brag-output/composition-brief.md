# Hyperframes Composition Brief: SENTINEL SIEM

## Objective
Create a short launch-style brag video for SENTINEL SIEM & Telemetry Dashboard.

## Output
- Composition directory: `brag-output/composition/`
- Rendered video: `brag-output/brag.mp4`
- Format: landscape — 1920x1080
- Duration: 20 seconds (30 fps)

## Source Material
- Project root: `/home/sidd/SIEM-Dashboard-security-information-event-mangement-`
- Primary files read: `frontend/src/pages/Dashboard.tsx`, `frontend/src/layouts/MainLayout.tsx`, `frontend/src/index.css`
- Product name: SENTINEL
- Tagline / strongest claim: "Autonomous threat correlation & zero-trust host isolation across distributed endpoints in milliseconds."
- Key UI or visual moment to recreate: Real-time telemetry ingestion chart, 4 KPI cards, MITRE ATT&CK brute force alert, and the one-click endpoint isolation state.
- Copy that must appear verbatim:
  - "SENTINEL"
  - "CENTRALIZED SIEM & TELEMETRY PLATFORM"
  - "12,450 Normalized Security Logs"
  - "CRITICAL ALERT: T1110 SSH Brute-Force Flood"
  - "PRIMARY-SOC-SRV • HOST QUARANTINED"
  - "Your SOC, autonomous in milliseconds."

## Creative Direction
- Tone preset: `polished`
- Creative direction: Modern high-performance SOC command center
- Interpretation: Ultra-crisp typography, confident high-tech aesthetic, perfectly timed cards, high contrast, and refined interface audio.
- Angle: Enterprise security operations without the bloated complexity.
- Hook: Obsidian shield glint opening into bright modern command center.
- Outro / punchline: "Your SOC, autonomous in milliseconds."
- Avoid:
  - Generic SaaS language
  - Abstract 3D filler shapes
  - Clunky alarms or cartoonish hacker skulls

## Visual Identity
- Background: `#f4f5f7` (canvas), `#ffffff` (cards), `#0b0f19` (dark intro/outro)
- Text: `#0b0f19` (obsidian body), `#64748b` (subtle labels)
- Accent: `#82c341` (Sentinel lime green), `#ef4444` (critical alert red), `#3b82f6` (blue informational)
- Display font: `Inter, system-ui, -apple-system, sans-serif`
- Body font: `Inter, system-ui, -apple-system, sans-serif`
- Visual references from the project: 24px rounded card corners, subtle `#f0f2f5` borders, MITRE attack badges, green posture gauge dial.

## Storyboard
Scene summary:
1. The Command Hook (0.0s – 3.5s) — Deep obsidian intro transitions to bright Sentinel SOC header and brand emblem.
2. Live Telemetry Stream (3.5s – 8.5s) — Cascade of 4 KPI cards (12,450 logs, 15,000 today, 6,700 anomalies, 88% posture score) and live EPS stream chart.
3. MITRE ATT&CK Alert (8.5s – 13.5s) — Red incident alert card fires: SSH Brute-Force (T1110) targeting `PRIMARY-SOC-SRV` with 6,400 attempts.
4. Host Isolation & Quarantine (13.5s – 17.5s) — Click trigger on "ISOLATE HOST", status switches to "ISOLATED & QUARANTINED", network sockets severed, green security restore banner.
5. Outro & Call to Action (17.5s – 20.0s) — Sentinel shield logo lockup with punchline: "Your SOC, autonomous in milliseconds."

## Audio
- Audio role: Sleek rhythmic electronic bed with crisp interface SFX
- Audio arc: Confident start, driving rhythm during telemetry cascade, sharp alert ping during incident, decisive switch on isolation, smooth resolution.
- Music: `assets/music/happy-beats-business-moves-vol-1-by-ende-dot-app.mp3`
- Music treatment: Volume at 0.60, fade-out starting at 18.5s to 20.0s.
- SFX files:
  - `assets/sfx/interface/switch_001.ogg`
  - `assets/sfx/interface/click_001.ogg`
  - `assets/sfx/interface/bong_001.ogg`
  - `assets/sfx/keyboard/keypress-001.wav`
- Restraint rule: Audio sits subtly behind the visuals; no harsh screeching.

## Hyperframes Instructions
- Composition directory: `brag-output/composition/`
- Register `window.__timelines["main"] = tl;` with `paused: true`.
- Use deterministic animations with GSAP 3.
- Mark all timed elements with `class="clip"`, `data-start`, and `data-duration`.
- Ensure all WCAG contrast checks pass.
