# WebShield: Advanced AI-Powered Security

![WebShield Banner](https://img.shields.io/badge/WebShield-Security-blue?style=for-the-badge&logo=shield)
[![CI/CD](https://github.com/deepspsd  /webshield.official/actions/workflows/ci.yml/badge.svg)](https://github.com/deepspsd/webshield.official/actions)
[![Code Quality](https://img.shields.io/badge/Quality-A%2B-green)](https://github.com/deepspsd/webshield.official)
[![Security Status](https://img.shields.io/badge/Security-High-green)](https://github.com/deepspsd/webshield.official)

WebShield is a state-of-the-art URL scanning and phishing detection system powered by multi-engine analysis, including VirusTotal, Machine Learning (Random Forest/Gradient Boosting), and Large Language Models (LLMs).

## Quick Start

### Run locally 

1. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start the server**
   ```bash
   python -m uvicorn app:app --host 0.0.0.0 --port 8000
   ```
   or
   ```bash
   uvicorn app:app --host 127.0.0.1 --port 8000
   ```

3. **Open the Web UI (served from `frontend/`)**
   - `http://localhost:8000/`
   - `http://localhost:8000/index.html`
   - Dashboard: `http://localhost:8000/dashboard.html`

### Verify the backend is running

- Health:
  - `http://localhost:8000/api/health`
  - (fallback) `http://localhost:8000/health`


- **Database**
  - History/Reports (folders, saved reports) require MySQL credentials in `.env`.

- **External APIs**
  - If `GROQ_API_KEY` is not set, the system uses fast rule-based fallbacks for LLM steps.
  - If VirusTotal is not configured/available, scans still run with local engines + fallbacks.

### Browser Extension

1. Open Chrome → `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** → select the `extension/` folder
4. Visit any URL and observe:
   - Real-time scan + status icon
   - Alerts/overlays for risky pages

## 🚀 Key Features

- **Multi-Engine Detection**: Combines VirusTotal API, Google Gemini, and custom ML models.
- **Real-time Protection**: Sub-millisecond URL pattern analysis.
- **AI-Powered Analysis**: Deep content inspection using LLMs for context-aware threat detection.
- **Browser Extension**: Real-time protection while you browse.
- **Comprehensive API**: Full RESTful API for integration.

## 🛠️ Technology Stack

- **Backend**: Python 3.11+, FastAPI, Uvicorn
- **ML/AI**: Scikit-learn, Numpy, Scipy, Groq API,Virus Total API 
- **Database**: MySQL (Aiven Cloud)
- **Infrastructure**: Docker, Redis, Nginx

### Prerequisites

- Python 3.11+
- Docker & Docker Compose
- MySQL Database

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/deepspsdwebshield.official.git
   cd webshield.official
   ```

2. **Run Locally**
   ```bash
   # Install dependencies
   pip install -r requirements.txt
   
   # Start server
   python start_server.py or 
   uvicorn app:app --host 127.0.0.1 --port 8000 or
   python -m uvicorn app:app --host 0.0.0.0 --port 8000
   ```

## 📖 Documentation

- [**API Reference**](documentation/API_REFERENCE.md): Detailed API endpoints and usage.
- [**Deployment Guide**](DEPLOYMENT_CHECKLIST.md): Production deployment checklist.
- [**Security Report**](SECURITY_AUDIT_REPORT.md): Security audit and improvements.

## 🧪 Testing & Quality

Run the comprehensive test suite:
```bash
pytest tests/
```

Run security scans:
```bash
bandit -r backend/
```

## 🔐 Security

This project follows strict security guidelines:
- **Secrets Management**: No hardcoded secrets (validated by CI).
- **SSL/TLS**: Enforced for all external connections.
- **Input Validation**: Strict sanitization of all inputs.
- **Dependencies**: Regular vulnerability scanning.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.
