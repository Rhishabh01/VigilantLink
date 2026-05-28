# VigilantLink

<p align="center" >Real-time, privacy-preserving phishing detection and deep link analysis for modern browsing.</p>
<p align="center">If this project helped you in any manner , consider starring the repo ⭐</p>
<p align="center">

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Backend-green.svg)](https://fastapi.tiangolo.com/)
[![Playwright](https://img.shields.io/badge/Playwright-DeepScan-purple.svg)](https://playwright.dev/)
[![Railway](https://img.shields.io/badge/Railway-Deployed-black.svg)](https://railway.app/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</p>

<p align="center">
  <img src="assets/newsafegif.gif" width="500" height="500" alt="VigilantLink Main Demo"/>
</p>

<p align="center">
  <strong>
    Detect phishing, malicious redirects, typosquatting, and suspicious websites before you click.
  </strong>
</p>

---

# Overview

VigilantLink is a browser extension designed to provide real-time phishing protection through progressive multi-phase security analysis.

Instead of relying on a single detection method, VigilantLink combines:

*   **Fast heuristic scanning**
*   **Threat intelligence APIs** (Google Safe Browsing, PhishTank, OpenPhish)
*   **Browser-based deep inspection** (Playwright)
*   **Redirect chain analysis**
*   **Domain reputation checks** (RDAP)
*   **Multi-source risk scoring**

The extension analyzes links directly on hover and provides instant security insights without interrupting the browsing experience.

---

# Features

*   **Real-time hover-based link analysis**
*   **Google Safe Browsing integration**
*   **Domain age intelligence (RDAP)**
*   **Redirect chain analysis**
*   **Multi-source heuristic scoring**
*   **Typosquatting detection**
*   **Playwright-powered deep scanning**
*   **Progressive Phase 1 → Phase 2 architecture**
*   **Privacy-focused logging and analysis**
*   **Railway-ready production deployment**
*   **Local standalone deployment support**

---

# Documentation

Detailed technical documentation is available in the [docs/](docs/) directory:

*   [Architecture](docs/architecture.md) — System design and request lifecycle.
*   [Backend](docs/backend.md) — FastAPI structure and service modules.
*   [Extension](docs/extension.md) — Chrome MV3 architecture and messaging.
*   [Scoring Engine](docs/scoring-engine.md) — Risk methodology and signal weights.
*   [API Reference](docs/api-reference.md) — Endpoint schemas and JSON examples.
*   [Deployment](docs/deployment.md) — Railway, Docker, and production setup.
*   [Troubleshooting](docs/troubleshooting.md) — Common issues and recovery steps.

---

# Demo

## Safe Website Detection

<p align="center">
  <img src="assets/newsafegif.gif" width="900" alt="Safe Website Detection Demo"/>
</p>

Fast real-time analysis of trusted domains using heuristic scanning, domain intelligence, and threat reputation checks.

---

## Malicious Website Detection

<p align="center">
  <img src="assets/newunsafegif.gif" width="900" alt="Malicious Website Detection Demo"/>
</p>

Detection of phishing indicators, malicious redirects, and suspicious browser behavior using the progressive deep-scan engine.

*Testing source (in Demo): [badssl.com](https://badssl.com/)*

---

# Architecture

<p align="center">
  <img src="assets/New Architecture.png" width="1000" alt="VigilantLink Architecture Diagram"/>
</p>

### Architecture Overview

VigilantLink uses a progressive multi-phase security pipeline.

#### Phase 1 — Fast Heuristic Engine
*   URL pattern analysis
*   DNS & SSL validation
*   Domain age intelligence
*   Suspicious keyword detection
*   Threat intelligence aggregation

#### Phase 2 — Deep Scan Sandbox
When a URL appears suspicious:
*   Playwright launches a browser sandbox
*   Redirect chains are analyzed
*   Dynamic page behavior is inspected
*   DOM phishing indicators are evaluated
*   Final risk scoring is generated

#### Final Verdict Engine
The system aggregates all security signals and produces one of:
*   🟢 **Safe**
*   🟡 **Suspicious**
*   🔴 **Dangerous**

---

# Screenshots

## Extension Options Popup

<p align="center">
  <img src="./assets/Extensionopt.png" width="500" alt="Extension Popup"/>
</p>

---

---
## Extension Settings Popup

<p align="center">
  <img src="./assets/ExtensionSet.png" width="500" alt="Extension Settings Popup"/>
</p>

---

## Safe Website Result

<p align="center">
  <img src="assets/safess.png" width="350" height="400" alt="Safe Website Scan"/>
</p>

---

## Safe Website Result

<p align="center">
  <img src="assets/safess.png" width="350" height="400" alt="Safe Website Scan"/>
</p>

---
## Dangerous Website Detection

<p align="center">
  <img src="assets/unsafess.png" width="300" height="400" alt="Dangerous Website Detection"/>
</p>

---

# Installation

## Backend Setup (Railway Deployment)

To deploy the backend to Railway:
1. Connect your GitHub repository to **Railway** and create a new project.
2. Set the **Root Directory** to `backend/` in your service settings.
3. Add a **Redis** service to your Railway project (Railway automatically configures the `REDIS_URL` environment variable).
4. Set the `GOOGLE_SAFE_BROWSING_API_KEY` environment variable in your Railway service settings.
5. Deploy. Railway will automatically build and run the backend using the provided `Dockerfile`.

*For local development setup instructions, please refer to [docs/deployment.md](docs/deployment.md).*

---

## Extension Setup

1. Open Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer Mode** in the top-right corner.
3. Click **Load unpacked** and select the `extension/` directory of this repository.

> [!TIP]
> By default, the extension is configured to use the production Railway backend (`https://vigilantlink-production.up.railway.app`). If you want to connect it to your own deployed Railway backend, update the `BACKEND_URL` variable at the top of `extension/scripts/background.js` to your service URL (e.g., `https://your-app-name.up.railway.app`).

---

# Contributing

We welcome contributions! Please see our [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to get started.

# Security

For reporting vulnerabilities, please refer to our [SECURITY.md](SECURITY.md).

# License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

# Disclaimer

VigilantLink is a security assistance tool and should not be considered a guaranteed replacement for enterprise-grade endpoint protection or safe browsing practices. Always verify sensitive websites manually when possible.
