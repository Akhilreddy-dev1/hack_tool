# hack_tool
# 🛡️ NexusAudit 3D — Advanced Web Vulnerability & Loophole Scanner

> A futuristic, 3D-accelerated cybersecurity auditing tool designed to detect website mistakes, inspect security misconfigurations, simulate live exploit vectors, and provide an embedded AI assistant guide.

![NexusAudit Banner](https://img.shields.io/badge/Status-Active-emerald?style=for-the-badge) ![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge) ![Tech Stack](https://img.shields.io/badge/Stack-HTML5%20%7C%20TailwindCSS%20%7C%20Three.js-cyan?style=for-the-badge)

---

## 🚀 Key Features

* **🌌 Immersive 3D Cyber UI:** Powered by **Three.js**, featuring an interactive particle network and floating geometric wireframe background that responds to user cursor movement.
* **🔍 Deep Probe Simulation Engine:** Simulates real-world penetration testing steps (DNS resolution, header probing, dependency scanning, and injection checks).
* **⚠️ Vulnerability & Mistake Matrix:** Categorizes flaws by severity (`Critical`, `Medium`, `Low`) including missing CSP headers, outdated JS libraries, exposed `.env` files, and CORS misconfigurations.
* **⚡ Exploit Simulation Lab:** Interactive console windows showing exactly how attackers leverage discovered loopholes against a target asset.
* **🛡️ Actionable Remediation Guides:** Provides clear, developer-friendly fixes for every detected security mistake.
* **🤖 NexusAI Assistant Integration:** Embedded chat guide (`ai-assistant.html`) to help users navigate features, interpret security flaws, and answer technical doubts.

---

## 📂 Project Structure

```text
nexus-audit/
├── index.html         # Main 3D Scanner Dashboard & Exploit Lab
└── ai-assistant.html  # Interactive AI Guide & Technical Chat Assistant
```

## Run locally

Python 3.10+ is required. Start the application from the repository root:

```bash
python app.py
```

Open <http://127.0.0.1:8000/>. The scanner sends one request to an authorized
public HTTP(S) target and checks its response headers. Private, loopback, and
non-public addresses are blocked. This is a defensive configuration check, not
an exploit or crawler.

The API accepts `POST /api/scan` with a JSON body such as
`{"target":"https://example.com"}`. Use `GET /api/health` for a health check.
