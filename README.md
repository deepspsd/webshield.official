# WebShield

WebShield is a web security platform for URL scanning and threat detection with a web UI, REST API, and browser extension.

## Features

- **URL scanning API** (async scans + polling by `scan_id`)
- **Multi-engine detection**
  - URL pattern/heuristic analysis
  - SSL/TLS certificate checks
  - Content phishing analysis
  - VirusTotal integration (optional)
  - ML-based URL + content classification
- **Machine learning**
  - URL threat classifier
  - Content phishing detector
  - Model caching and low-CPU runtime settings (`n_jobs=1`)
- **Reports & dashboard**
  - Detailed scan report view
  - PDF/CSV export
- **Admin + history**
  - Recent scans and basic statistics
- **Browser extension**
  - On-demand URL scanning
  - Real-time protection hooks

## Components

- **Backend:** `backend/` (FastAPI)
- **Frontend:** `frontend/` (HTML/CSS/JS)
- **Extension:** `extension/` (Chrome/Chromium)
- **ML Models:** `backend/ml_models/` (joblib models + training scripts)

## Run (local)

- **Backend**
  - `python start_server.py`

- **Frontend**
  - Open `frontend/index.html` in a browser (or serve it via any static server)

- **Extension**
  - Load `extension/` as an unpacked extension in Chrome

## Configuration

- **MySQL**
  - Configure DB settings via environment variables used by the backend.

- **VirusTotal**
  - Set `VT_API_KEY` to enable VirusTotal checks.

## License

MIT (see `LICENSE`).
