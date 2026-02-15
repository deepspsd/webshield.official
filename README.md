# WebShield: Advanced AI-Powered Security

![WebShield Banner](https://img.shields.io/badge/WebShield-Security-blue?style=for-the-badge&logo=shield)
[![CI/CD](https://github.com/deepspsd  /webshield.official/actions/workflows/ci.yml/badge.svg)](https://github.com/deepspsd/webshield.official/actions)
[![Code Quality](https://img.shields.io/badge/Quality-A%2B-green)](https://github.com/deepspsd/webshield.official)
[![Security Status](https://img.shields.io/badge/Security-High-green)](https://github.com/deepspsd/webshield.official)

WebShield is a state-of-the-art URL scanning and phishing detection system powered by multi-engine analysis, including VirusTotal, Machine Learning (Random Forest/Gradient Boosting), and Large Language Models (LLMs).

## Quick Start

### Manual Setup

1. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure environment**
   ```bash
   # Copy .env.example to .env (already done in your case)
   # Verify these settings in .env:
   # - GROQ_API_KEY (for AI responses)
   # - GOOGLE_CLIENT_ID (for Gmail OAuth)
   # - Database credentials (if using MySQL)
   ```

3. **Start the server**
   ```bash
   # Option 1: Use the startup script (recommended)
   python start_server.py
   
   # Option 2: Direct uvicorn
   python -m uvicorn backend.server:app --host 0.0.0.0 --port 8000
   ```

4. **Verify backend is running**
   ```bash
   # Test health endpoint
   curl http://localhost:8000/api/health
   ```

5. **Open the Web UI**
   - Main: `http://localhost:8000/`
   - Dashboard: `http://localhost:8000/dashboard.html`
   - Health: `http://localhost:8000/api/health`

### Gmail Extension Setup

1. **Start the backend first** (see above)

2. **Load Gmail Extension**
   - Open Chrome → `chrome://extensions/`
   - Enable **Developer mode** (top right)
   - Click **Load unpacked**
   - Select `gmail-extension/` folder
   - Extension should load with WebShield icon

3. **Test in Gmail**
   - Open Gmail (https://mail.google.com)
   - Open any email
   - Look for WebShield scan button
   - Click to scan email for threats

4. **Connect Gmail (OAuth)**
   - Click extension icon
   - Click "Connect Gmail"
   - Grant permissions
   - Extension will verify token with backend

### Regular Extension Setup

1. **Load Regular Extension**
   - Chrome → `chrome://extensions/`
   - Enable **Developer mode**
   - Click **Load unpacked**
   - Select `extension/` folder

2. **Test URL Scanning**
   - Visit any website
   - Extension will analyze in real-time
   - Click extension icon to see results

### ✅ Verify Everything Works

**Test Backend:**
```bash
# Windows
TEST_BACKEND.bat

# All platforms
curl http://localhost:8000/api/health
```

**Test Groq AI:**
```bash
# Windows
TEST_GROQ_API.bat

# All platforms
curl -X POST https://api.groq.com/openai/v1/chat/completions \
  -H "Authorization: Bearer YOUR_GROQ_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"llama-3.1-8b-instant","messages":[{"role":"user","content":"test"}],"max_tokens":10}'
```

**Test Email Scanning:**
```bash
curl -X POST http://localhost:8000/api/email/scan-metadata \
  -H "Content-Type: application/json" \
  -d '{"email_metadata":{"sender_email":"test@example.com","sender_name":"Test","subject":"Test","links":[],"attachment_hashes":[],"attachment_names":[],"attachments":[],"has_dangerous_attachments":false},"scan_type":"quick"}'
```

### 🐛 Troubleshooting

**Backend not starting:**
- Check if port 8000 is in use: `netstat -ano | findstr :8000`
- Install dependencies: `pip install -r requirements.txt`
- Check logs: `tail -f webshield.log`

**Extensions not connecting:**
- Verify backend is running: `curl http://localhost:8000/api/health`
- Check extension console (F12) for errors
- Verify CORS settings in `.env`

**AI responses not working:**
- Test Groq API: Run `TEST_GROQ_API.bat`
- Check `GROQ_API_KEY` in `.env`
- Backend will use fallback analysis if Groq fails

**OAuth errors:**
- Verify `GOOGLE_CLIENT_ID` in `.env` matches manifest
- Check backend logs for token verification errors
- Try removing and re-granting permissions

### 📋 Configuration Notes


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
