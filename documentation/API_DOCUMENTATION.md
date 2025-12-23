# WebShield API Documentation v2.0

## 🌐 Base URL
```
Production: https://api.webshield.com
Development: http://localhost:8000
```

## 🔐 Authentication

WebShield supports two authentication methods:

### 1. JWT Bearer Token
```http
Authorization: Bearer <access_token>
```

### 2. API Key
```http
X-API-Key: <your_api_key>
```

---

## 📡 Core Endpoints

### 1. URL Scanning

#### POST `/api/scan/scan`
Submit a URL for comprehensive threat analysis.

**Request:**
```json
{
  "url": "https://example.com",
  "user_email": "user@example.com"  // Optional
}
```

**Response:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "url": "https://example.com",
  "status": "processing",
  "results": null
}
```

**Status Codes:**
- `200`: Scan initiated successfully
- `400`: Invalid URL format
- `429`: Rate limit exceeded
- `500`: Server error

---

#### GET `/api/scan/scan/{scan_id}`
Retrieve scan results by scan ID.

**Response (Processing):**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "url": "https://example.com",
  "status": "processing",
  "results": null
}
```

**Response (Completed):**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "url": "https://example.com",
  "status": "completed",
  "results": {
    "url": "https://example.com",
    "is_malicious": false,
    "threat_level": "low",
    "malicious_count": 0,
    "suspicious_count": 0,
    "total_engines": 90,
    "detection_details": {
      "url_analysis": {
        "suspicious_score": 0,
        "detected_issues": ["No suspicious patterns"],
        "domain": "example.com",
        "is_suspicious": false,
        "ml_enabled": true,
        "ml_confidence": 0.95
      },
      "ssl_analysis": {
        "valid": true,
        "issuer": "Let's Encrypt",
        "expires": "2025-12-31",
        "threat_score": 0
      },
      "content_analysis": {
        "phishing_score": 0,
        "detected_indicators": [],
        "is_suspicious": false,
        "ml_enabled": true,
        "ml_confidence": 0.92
      },
      "virustotal_analysis": {
        "malicious_count": 0,
        "suspicious_count": 0,
        "harmless_count": 88,
        "undetected_count": 2,
        "total_engines": 90
      },
      "ml_analysis": {
        "ml_enabled": true,
        "ml_models_used": ["URL Threat Classifier", "Content Phishing Detector"],
        "ml_confidence": 0.95
      }
    },
    "ssl_valid": true,
    "domain_reputation": "clean",
    "scan_timestamp": "2025-01-07T18:00:00"
  }
}
```

**Threat Levels:**
- `low`: Safe, no threats detected
- `medium`: 1-3 engines flagged, moderate risk
- `high`: 4+ engines flagged, high risk

---

### 2. Authentication

#### POST `/api/auth/register`
Register a new user account.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "full_name": "John Doe"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Registration successful! Please sign in.",
  "redirect": "/login.html"
}
```

---

#### POST `/api/auth/login`
Authenticate user and receive JWT tokens.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Response:**
```json
{
  "success": true,
  "name": "John Doe",
  "email": "user@example.com",
  "user_id": 123,
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

#### GET `/api/auth/profile`
Get user profile information.

**Query Parameters:**
- `email`: User email address

**Headers:**
```http
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "id": 123,
  "email": "user@example.com",
  "name": "John Doe",
  "profile_picture": "/uploads/profile_pictures/user.jpg",
  "created_at": "2025-01-01T00:00:00",
  "last_login": "2025-01-07T18:00:00"
}
```

---

### 3. Dashboard & Statistics

#### GET `/api/admin/dashboard-stats`
Get comprehensive dashboard statistics.

**Response:**
```json
{
  "urls_scanned": 615234,
  "threats_blocked": 250123,
  "users": 1523,
  "uptime": "99.99 %",
  "actual_scanned": 234,
  "actual_threats": 23,
  "ml_training_urls": 615000,
  "ml_training_threats": 250000,
  "kaggle_dataset": {
    "total_urls": 615000,
    "malicious_urls": 400000,
    "high_threat_urls": 250000,
    "benign_urls": 215000
  }
}
```

---

#### GET `/api/admin/ml-training-stats`
Get ML model training statistics.

**Response:**
```json
{
  "success": true,
  "ml_models": [
    {
      "model_name": "URL Threat Classifier",
      "dataset_name": "Kaggle Malicious URLs Dataset",
      "total_urls_trained": 450000,
      "malicious_urls_count": 225000,
      "benign_urls_count": 225000,
      "model_version": "1.0",
      "accuracy_score": 0.95,
      "training_date": "2025-01-01T00:00:00"
    },
    {
      "model_name": "Content Phishing Detector",
      "dataset_name": "Kaggle Malicious URLs Dataset",
      "total_urls_trained": 450000,
      "malicious_urls_count": 225000,
      "benign_urls_count": 225000,
      "model_version": "1.0",
      "accuracy_score": 0.92,
      "training_date": "2025-01-01T00:00:00"
    }
  ],
  "total_models": 2
}
```

---

#### GET `/api/admin/user_scans`
Get recent scans for a user.

**Query Parameters:**
- `email`: User email (optional, returns global scans if omitted)
- `limit`: Number of scans to return (default: 6, max: 50)

**Response:**
```json
[
  {
    "scan_id": "550e8400-e29b-41d4-a716-446655440000",
    "url": "https://example.com",
    "status": "completed",
    "is_malicious": false,
    "threat_level": "low",
    "malicious_count": 0,
    "suspicious_count": 0,
    "total_engines": 90,
    "ssl_valid": true,
    "domain_reputation": "clean",
    "created_at": "2025-01-07T18:00:00"
  }
]
```

---

### 4. Health & Monitoring

#### GET `/api/health`
Basic health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-01-07T18:00:00",
  "database": "connected",
  "database_test": "passed",
  "database_type": "MySQL",
  "ml_models": {
    "url_classifier_trained": true,
    "content_detector_trained": true,
    "models_available": true
  }
}
```

---

#### GET `/monitoring/health/detailed`
Detailed health check with system metrics.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-01-07T18:00:00",
  "system": {
    "cpu_percent": 25.5,
    "memory_percent": 45.2,
    "memory_available_gb": 8.5,
    "disk_percent": 35.0,
    "disk_free_gb": 120.5
  },
  "application": {
    "uptime_seconds": 86400,
    "total_requests": 15234,
    "total_scans": 1523,
    "avg_request_time": 0.125,
    "avg_scan_time": 2.345
  },
  "services": {
    "database": "healthy",
    "ml_models": "healthy",
    "cache": "healthy"
  }
}
```

---

#### GET `/monitoring/metrics`
Prometheus metrics endpoint.

**Response Format:** Prometheus text format

---

## 🔄 Rate Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| `/api/scan/scan` | 10 requests | 1 minute |
| `/api/auth/login` | 5 requests | 5 minutes |
| `/api/auth/register` | 3 requests | 10 minutes |
| `/api/*` (general) | 100 requests | 1 minute |

**Rate Limit Headers:**
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1704643200
Retry-After: 60
```

---

## 🚨 Error Responses

### Standard Error Format
```json
{
  "detail": "Error message",
  "status_code": 400,
  "timestamp": "2025-01-07T18:00:00"
}
```

### Common Error Codes
- `400`: Bad Request - Invalid input
- `401`: Unauthorized - Invalid credentials
- `403`: Forbidden - Insufficient permissions
- `404`: Not Found - Resource doesn't exist
- `429`: Too Many Requests - Rate limit exceeded
- `500`: Internal Server Error - Server issue
- `503`: Service Unavailable - Temporary outage

---

## 📊 Webhook Integration (Future)

### Scan Completion Webhook
```json
POST https://your-webhook-url.com/webhook

{
  "event": "scan.completed",
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "url": "https://example.com",
  "is_malicious": false,
  "threat_level": "low",
  "timestamp": "2025-01-07T18:00:00"
}
```

---

## 🔧 SDK Examples

### Python
```python
import requests

# Scan URL
response = requests.post(
    'http://localhost:8000/api/scan/scan',
    json={'url': 'https://example.com', 'user_email': None}
)
scan_data = response.json()
scan_id = scan_data['scan_id']

# Get results
import time
time.sleep(3)  # Wait for scan to complete

result = requests.get(f'http://localhost:8000/api/scan/scan/{scan_id}')
print(result.json())
```

### JavaScript
```javascript
// Scan URL
const scanResponse = await fetch('http://localhost:8000/api/scan/scan', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ url: 'https://example.com', user_email: null })
});
const scanData = await scanResponse.json();

// Poll for results
const pollResults = async (scanId) => {
  const response = await fetch(`http://localhost:8000/api/scan/scan/${scanId}`);
  const data = await response.json();
  
  if (data.status === 'completed') {
    console.log('Scan results:', data.results);
  } else {
    setTimeout(() => pollResults(scanId), 1000);
  }
};

pollResults(scanData.scan_id);
```

### cURL
```bash
# Scan URL
curl -X POST http://localhost:8000/api/scan/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com","user_email":null}'

# Get results
curl http://localhost:8000/api/scan/scan/550e8400-e29b-41d4-a716-446655440000
```

---

## 📈 Performance Metrics

- **Average Scan Time**: < 2 seconds
- **Throughput**: 1000+ scans/minute
- **Accuracy**: 95%+ threat detection
- **Uptime**: 99.9% SLA
- **API Latency**: < 100ms (p95)

---

## 🎯 Best Practices

### 1. Polling Strategy
```javascript
// Exponential backoff polling
async function pollWithBackoff(scanId, maxAttempts = 10) {
  for (let i = 0; i < maxAttempts; i++) {
    const response = await fetch(`/api/scan/scan/${scanId}`);
    const data = await response.json();
    
    if (data.status === 'completed') {
      return data.results;
    }
    
    // Exponential backoff: 1s, 2s, 4s, 8s...
    await new Promise(resolve => setTimeout(resolve, Math.min(1000 * Math.pow(2, i), 10000)));
  }
  
  throw new Error('Scan timeout');
}
```

### 2. Error Handling
```javascript
try {
  const response = await fetch('/api/scan/scan', {
    method: 'POST',
    body: JSON.stringify({ url: 'https://example.com' })
  });
  
  if (!response.ok) {
    if (response.status === 429) {
      // Rate limited - wait and retry
      const retryAfter = response.headers.get('Retry-After');
      await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
      // Retry request
    } else {
      throw new Error(`HTTP ${response.status}`);
    }
  }
  
  const data = await response.json();
  // Process data
} catch (error) {
  console.error('Scan failed:', error);
}
```

### 3. Batch Scanning
```python
import asyncio
import aiohttp

async def scan_multiple_urls(urls):
    async with aiohttp.ClientSession() as session:
        tasks = []
        for url in urls:
            task = session.post(
                'http://localhost:8000/api/scan/scan',
                json={'url': url, 'user_email': None}
            )
            tasks.append(task)
        
        responses = await asyncio.gather(*tasks)
        scan_ids = [await r.json() for r in responses]
        
        # Wait and collect results
        await asyncio.sleep(5)
        
        results = []
        for scan_data in scan_ids:
            result_response = await session.get(
                f'http://localhost:8000/api/scan/scan/{scan_data["scan_id"]}'
            )
            results.append(await result_response.json())
        
        return results

# Usage
urls = ['https://google.com', 'https://example.com', 'https://github.com']
results = asyncio.run(scan_multiple_urls(urls))
```

---

## 🔒 Security Considerations

### 1. API Key Management
- Store API keys securely (environment variables, secrets manager)
- Rotate keys every 90 days
- Never commit keys to version control
- Use different keys for dev/staging/production

### 2. Rate Limiting
- Implement client-side rate limiting
- Cache scan results when possible
- Use exponential backoff on errors
- Monitor rate limit headers

### 3. Data Privacy
- Don't log sensitive URLs
- Use HTTPS for all requests
- Implement request signing for webhooks
- Comply with GDPR/privacy regulations

---

## 📞 Support

- **API Status**: https://status.webshield.com
- **Documentation**: https://docs.webshield.com
- **Support Email**: api-support@webshield.com
- **GitHub Issues**: https://github.com/deepspsd/webshield.official/issues

---

**API Version**: 2.0.0  
**Last Updated**: January 2025  
**Changelog**: See [CHANGELOG.md](CHANGELOG.md)
