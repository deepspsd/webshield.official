# WebShield Architecture Documentation

## 🏗️ System Architecture Overview

WebShield is built on a modern, scalable microservices-inspired architecture with clear separation of concerns.

```
┌─────────────────────────────────────────────────────────────┐
│                    CLIENT LAYER                              │
├─────────────────────────────────────────────────────────────┤
│  Browser Extension  │  Web Frontend  │  Mobile App (Future) │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   API GATEWAY (Nginx)                        │
│  - Rate Limiting    - SSL Termination    - Load Balancing   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              APPLICATION LAYER (FastAPI)                     │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Auth Service │  │ Scan Service │  │ API Service  │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
                            │
                ┌───────────┼───────────┐
                ▼           ▼           ▼
┌──────────────────┐ ┌──────────────┐ ┌──────────────┐
│  ML ENGINE       │ │  DETECTION   │ │  EXTERNAL    │
│  - URL Classifier│ │  - SSL Check │ │  - VirusTotal│
│  - Content Det.  │ │  - Pattern   │ │  - Threat DB │
│  - Ensemble Vote │ │  - Heuristics│ │              │
└──────────────────┘ └──────────────┘ └──────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   DATA LAYER                                 │
├─────────────────────────────────────────────────────────────┤
│  MySQL Database  │  Redis Cache  │  File Storage           │
└─────────────────────────────────────────────────────────────┘
```

## 🔧 Component Details

### 1. Frontend Layer
- **Technology**: Vanilla JavaScript, HTML5, CSS3
- **Features**: 
  - Glassmorphism UI with dark theme
  - Real-time updates via polling
  - Progressive Web App capabilities
  - Responsive design (mobile-first)
- **Files**: `frontend/*.html`, `frontend/*.js`, `frontend/*.css`

### 2. Browser Extension
- **Technology**: Chrome Extension API (Manifest V3)
- **Features**:
  - Real-time URL scanning
  - Smart caching (1-hour TTL)
  - Offline mode support
  - Dynamic endpoint detection
- **Files**: `extension/*`

### 3. API Gateway (Nginx)
- **Purpose**: Reverse proxy, SSL termination, rate limiting
- **Features**:
  - HTTP/2 support
  - Gzip compression
  - Rate limiting (100 req/min)
  - Security headers
- **Config**: `nginx.conf`

### 4. Application Server (FastAPI)
- **Technology**: Python 3.11+, FastAPI, Uvicorn
- **Architecture Pattern**: Async/Await with background tasks
- **Key Modules**:
  - `server.py`: Main application entry point
  - `api_routes.py`: Admin and stats endpoints
  - `scan.py`: Core scanning logic
  - `auth.py`: Authentication & authorization
  - `utils.py`: Detection utilities

### 5. ML Engine
- **Models**:
  - **URL Threat Classifier**: Ensemble (RF + GB + SVM + NN)
  - **Content Phishing Detector**: TF-IDF + Random Forest
- **Training Data**: 450,000 URLs from Kaggle dataset
- **Accuracy**: 95%+ on validation set
- **Features**:
  - 50+ URL features extracted
  - 30+ content features analyzed
  - Real-time prediction caching
  - Incremental learning support

### 6. Detection Engines

#### A. URL Pattern Analysis
- Length analysis (URL, domain, path, query)
- Entropy calculation (Shannon entropy)
- Character distribution analysis
- Suspicious TLD detection
- IP address detection
- Port analysis
- Typosquatting detection
- Brand impersonation scoring

#### B. SSL/TLS Analysis
- Certificate validation
- Expiration date checking
- Issuer verification
- Self-signed certificate detection
- Certificate chain validation
- Encryption strength assessment

#### C. Content Analysis
- HTML structure parsing
- Form detection
- Input field analysis
- External link counting
- JavaScript analysis
- Phishing keyword detection
- Urgency pattern recognition
- Brand logo detection

#### D. VirusTotal Integration
- 90+ antivirus engines
- URL reputation scoring
- Historical scan data
- Cached result retrieval
- Fallback to local analysis

### 7. Database Layer
- **Technology**: MySQL 8.0+
- **Connection**: Pooling with retry logic
- **Tables**:
  - `users`: User accounts and profiles
  - `scans`: Scan history and results
  - `reports`: User-reported URLs
  - `ml_training_stats`: ML model metadata
- **Indexes**: Optimized for query performance

### 8. Caching Layer
- **In-Memory**: LRU cache (1000 entries, 5-min TTL)
- **Redis** (Optional): Distributed caching
- **Strategy**: Cache-aside pattern

## 🔄 Request Flow

### Scan Request Flow
```
1. User submits URL → Frontend/Extension
2. POST /api/scan/scan → API Gateway (Nginx)
3. Rate limiting check → FastAPI middleware
4. Generate scan_id → Insert DB (status: processing)
5. Background task spawned → Async scan execution
6. Return scan_id immediately → Client polls for results
7. Parallel execution:
   ├─ URL pattern analysis (ML + rules)
   ├─ SSL certificate check
   ├─ Content fetching & analysis (ML + rules)
   └─ VirusTotal API call
8. Aggregate results → Calculate threat score
9. Update DB (status: completed) → Cache result
10. Client retrieves via GET /api/scan/{scan_id}
```

### Authentication Flow
```
1. User registers → POST /api/auth/register
2. Password hashed (bcrypt) → Store in DB
3. User logs in → POST /api/auth/login
4. Verify credentials → Generate JWT tokens
5. Return access_token + refresh_token
6. Client stores tokens → Include in Authorization header
7. Protected endpoints verify JWT → Extract user info
8. Token refresh → POST /api/auth/refresh
```

## 🚀 Performance Optimizations

### 1. Async Operations
- All I/O operations use async/await
- Concurrent execution of detection engines
- Non-blocking database queries

### 2. Connection Pooling
- MySQL connection pool (10-50 connections)
- Automatic connection recycling
- Health checks and reconnection

### 3. Caching Strategy
- LRU cache for scan results (5-min TTL)
- Prediction caching in ML engine
- Static asset caching (1-year)

### 4. Rate Limiting
- Per-IP rate limiting (100 req/min)
- Scan-specific limits (10 scans/min)
- Exponential backoff on failures

### 5. Timeouts
- SSL check: 3 seconds
- Content fetch: 5 seconds
- VirusTotal: 2 seconds
- Total scan: 15 seconds max

## 🔒 Security Architecture

### Defense in Depth
1. **Network Layer**: Nginx with rate limiting
2. **Transport Layer**: TLS 1.2+ encryption
3. **Application Layer**: Input validation, SQL injection protection
4. **Data Layer**: Encrypted passwords, parameterized queries
5. **Session Layer**: JWT tokens with expiration

### Security Headers
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- X-XSS-Protection

### Authentication & Authorization
- Bcrypt password hashing (12 rounds)
- JWT tokens (HS256 algorithm)
- Refresh token rotation
- Session management
- Role-based access control (RBAC)

## 📊 Scalability

### Horizontal Scaling
- Stateless application design
- Shared database and cache
- Load balancing with Nginx
- Docker containerization

### Vertical Scaling
- Multi-worker support (4+ workers)
- Connection pooling
- Async I/O operations
- Efficient memory usage

### Database Scaling
- Read replicas (future)
- Sharding by user_id (future)
- Partitioning by date (future)
- Query optimization with indexes

## 🧪 Testing Strategy

### Unit Tests
- ML model testing
- API endpoint testing
- Authentication testing
- Utility function testing

### Integration Tests
- End-to-end scan flow
- Database operations
- External API integration
- Cache behavior

### Performance Tests
- Load testing (1000+ concurrent users)
- Stress testing
- Endurance testing
- Spike testing

## 📈 Monitoring & Observability

### Metrics (Prometheus)
- Request count and duration
- Scan count by threat level
- ML prediction accuracy
- System resources (CPU, memory, disk)
- Cache hit/miss ratio
- Database connection pool status

### Logging
- Structured JSON logging
- Log levels: ERROR, WARNING, INFO, DEBUG
- Request tracing with unique IDs
- Performance logging for slow requests

### Alerting
- High CPU/memory usage
- Database connection failures
- ML model errors
- Scan timeout alerts
- Rate limit violations

## 🔮 Future Enhancements

### Phase 1 (Q1 2025)
- [ ] Deep learning models (LSTM, BERT)
- [ ] Real-time threat intelligence feeds
- [ ] Advanced analytics dashboard
- [ ] API v2 with GraphQL

### Phase 2 (Q2 2025)
- [ ] Mobile applications (iOS, Android)
- [ ] Enterprise features (SSO, team management)
- [ ] Kubernetes deployment
- [ ] Multi-region support

### Phase 3 (Q3 2025)
- [ ] AI-powered threat hunting
- [ ] Automated incident response
- [ ] Threat intelligence sharing
- [ ] Advanced reporting & compliance

---

**Last Updated**: January 2025  
**Version**: 2.0.0  
**Maintainer**: WebShield Team
