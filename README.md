# WebShield: Advanced AI-Powered Security

![WebShield Banner](https://img.shields.io/badge/WebShield-Security-blue?style=for-the-badge&logo=shield)
[![CI/CD](https://github.com/deepugangadhar46/webshield.official/actions/workflows/ci.yml/badge.svg)](https://github.com/deepugangadhar46/webshield.official/actions)
[![Code Quality](https://img.shields.io/badge/Quality-A%2B-green)](https://github.com/deepugangadhar46/webshield.official)
[![Security Status](https://img.shields.io/badge/Security-High-green)](https://github.com/deepugangadhar46/webshield.official)

WebShield is a state-of-the-art URL scanning and phishing detection system powered by multi-engine analysis, including VirusTotal, Machine Learning (Random Forest/Gradient Boosting), and Large Language Models (LLMs).

## 🚀 Key Features

- **Multi-Engine Detection**: Combines VirusTotal API, Google Gemini, and custom ML models.
- **Real-time Protection**: Sub-millisecond URL pattern analysis.
- **AI-Powered Analysis**: Deep content inspection using LLMs for context-aware threat detection.
- **Browser Extension**: Real-time protection while you browse.
- **Comprehensive API**: Full RESTful API for integration.

## 🛠️ Technology Stack

- **Backend**: Python 3.11+, FastAPI, Uvicorn
- **ML/AI**: Scikit-learn, TensorFlow, Google Gemini API, HuggingFace
- **Database**: MySQL (Aiven Cloud)
- **Infrastructure**: Docker, Redis, Nginx

## 🏁 Quick Start

### Prerequisites

- Python 3.11+
- Docker & Docker Compose
- MySQL Database

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/deepugangadhar46/webshield.official.git
   cd webshield.official
   ```

2. **Set up environment**
   ```bash
   cp .env.example .env
   # Edit .env with your credentials
   ```

3. **Run with Docker (Recommended)**
   ```bash
   docker-compose up --build
   ```

4. **Run Locally**
   ```bash
   # Install dependencies
   pip install -r requirements.txt
   
   # Start server
   python start_server.py
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
