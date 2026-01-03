# Production Deployment Checklist

## 🔐 Security Checklist

### Critical Security Fixes
- [ ] **Remove .env from Git history**
  ```bash
  # Install git-filter-repo
  pip install git-filter-repo
  
  # Remove .env from entire history
  git filter-repo --path .env --invert-paths --force
  
  # Force push (WARNING: Coordinate with team first)
  git push origin --force --all
  ```

- [ ] **Revoke ALL exposed API keys**
  - [ ] VirusTotal API Key → https://www.virustotal.com/gui/user/YOUR_USER/apikey
  - [ ] Google Gemini API Key → https://makersuite.google.com/app/apikey 
  - [ ] HuggingFace Token → https://huggingface.co/settings/tokens
  - [ ] Groq API Key → https://console.groq.com/keys

- [ ] **Rotate database credentials**
  - [ ] Change MySQL password in Aiven console
  - [ ] Update connection strings
  - [ ] Verify no hardcoded passwords remain

- [ ] **Generate new application secrets**
  ```bash
  # Generate new JWT secret
  python -c "import secrets; print(secrets.token_hex(32))"
  
  # Generate new SECRET_KEY
  python -c "import secrets; print(secrets.token_hex(32))"
  ```

- [ ] **Implement secrets management**
  - Option 1: AWS Secrets Manager
  - Option 2: HashiCorp Vault
  - Option 3: Azure Key Vault
  - Option 4: GCP Secret Manager

### Application Security
- [ ] Enable SSL verification in content fetcher (utils.py:528)
- [ ] Add API authentication
- [ ] Implement rate limiting on all endpoints
- [ ] Add CORS restrictions (remove `allow_origins=["*"]`)
- [ ] Add CSP headers
- [ ] Enable HSTS
- [ ] Validate all user inputs
- [ ] Sanitize all database queries
- [ ] Add request signing for extension communication

### Infrastructure Security
- [ ] Use HTTPS only
- [ ] Configure firewall rules
- [ ] Use managed database with SSL
- [ ] Enable database backups
- [ ] Set up VPC/private network
- [ ] Use load balancer with WAF
- [ ] Configure DDoS protection
- [ ] Set up intrusion detection

## 🚀 Deployment Checklist

### Pre-Deployment
- [ ] Run security scan: `bandit -r backend/`
- [ ] Run dependency audit: `pip-audit`
- [ ] Run tests: `pytest`
- [ ] Check code coverage: `pytest --cov`
- [ ] Lint code: `ruff check .`
- [ ] Type check: `mypy backend/`
- [ ] Build Docker image
- [ ] Test Docker container locally
- [ ] Load test (k6, Locust, or Apache Bench)

### Environment Setup
- [ ] Set up production database
- [ ] Configure Redis cache
- [ ] Set up CDN for frontend
- [ ] Configure DNS
- [ ] Get SSL certificates (Let's Encrypt)
- [ ] Set up monitoring (Datadog/New Relic)
- [ ] Set up logging (ELK/CloudWatch)
- [ ] Set up error tracking (Sentry)
- [ ] Configure backups
- [ ] Set up CI/CD pipeline

### Configuration
- [ ] Set `API_DEBUG=False` in production
- [ ] Set `ENVIRONMENT=production`
- [ ] Configure proper `LOG_LEVEL`
- [ ] Set `ENABLE_DOCS=false` for security
- [ ] Configure email SMTP properly
- [ ] Set appropriate rate limits
- [ ] Configure cache TTL values
- [ ] Set appropriate timeout values

### Monitoring & Alerts
- [ ] Health check endpoint (`/health`)
- [ ] Readiness endpoint (`/ready`)
- [ ] Metrics endpoint (`/metrics`)
- [ ] Database connection monitoring
- [ ] API latency monitoring
- [ ] Error rate monitoring
- [ ] Disk space alerts
- [ ] Memory usage alerts
- [ ] CPU usage alerts
- [ ] API key usage alerts

## 📊 Performance Checklist

### Database Optimization
- [ ] Add database indexes
- [ ] Enable connection pooling
- [ ] Configure query caching
- [ ] Set up read replicas (if needed)
- [ ] Optimize slow queries
- [ ] Set up database monitoring

### Caching Strategy
- [ ] Enable Redis caching
- [ ] Cache VirusTotal results (✅ already done)
- [ ] Cache ML predictions (✅ already done)
- [ ] Cache static assets (CDN)
- [ ] Implement cache warming
- [ ] Set appropriate TTL values

### Application Performance
- [ ] Enable gzip compression
- [ ] Minimize database queries
- [ ] Use async where possible (✅ already done)
- [ ] Optimize ML model loading (✅ already done)
- [ ] Use connection pooling
- [ ] Enable HTTP/2

## 🧪 Testing Checklist

### Functional Testing
- [ ] Test all API endpoints
- [ ] Test browser extension functionality
- [ ] Test ML model predictions
- [ ] Test VirusTotal integration
- [ ] Test SSL validation
- [ ] Test content analysis
- [ ] Test error handling
- [ ] Test rate limiting

### Security Testing
- [ ] SQL injection testing
- [ ] XSS testing
- [ ] CSRF testing
- [ ] Authentication bypass testing
- [ ] Authorization testing
- [ ] Input validation testing
- [ ] API security testing

### Performance Testing
- [ ] Load testing (concurrent users)
- [ ] Stress testing (breaking point)
- [ ] Spike testing (sudden traffic)
- [ ] Endurance testing (sustained load)
- [ ] Database performance testing
- [ ] API response time testing

### Integration Testing
- [ ] Database integration
- [ ] Redis integration
- [ ] VirusTotal API integration
- [ ] ML model integration
- [ ] Email service integration
- [ ] Browser extension integration

## 📚 Documentation Checklist

- [ ] API documentation (OpenAPI/Swagger)
- [ ] Architecture documentation
- [ ] Deployment documentation
- [ ] User guide
- [ ] Admin guide
- [ ] Troubleshooting guide
- [ ] Security documentation
- [ ] Incident response plan

## 🔄 Post-Deployment

### Monitoring
- [ ] Monitor error rates
- [ ] Monitor API latency
- [ ] Monitor database performance
- [ ] Monitor ML model accuracy
- [ ] Monitor false positive rate
- [ ] Monitor false negative rate
- [ ] Monitor API usage
- [ ] Monitor costs

### Maintenance
- [ ] Set up automated backups
- [ ] Set up log rotation
- [ ] Schedule dependency updates
- [ ] Schedule security audits
- [ ] Plan model retraining
- [ ] Monitor API key usage limits
- [ ] Review and update whitelists

### Incident Response
- [ ] Document incident response plan
- [ ] Set up on-call rotation
- [ ] Create runbooks for common issues
- [ ] Test disaster recovery
- [ ] Document rollback procedures
- [ ] Set up status page

## 🎯 Success Metrics

### Performance Metrics
- API response time < 200ms (p95)
- Uptime > 99.9%
- Error rate < 0.1%
- Database query time < 50ms (p95)
- ML prediction time < 100ms

### Accuracy Metrics
- True positive rate > 90%
- False positive rate < 5%
- True negative rate > 95%
- User satisfaction > 4.5/5

### Business Metrics
- Daily active users
- Scans per day
- Threats detected per day
- API usage growth
- Cost per scan

---

**Remember**: Security is not a one-time task. Continuously monitor, test, and improve your security posture.

**Next Steps**:
1. Fix all security issues listed in SECURITY_AUDIT_REPORT.md
2. Complete this checklist
3. Deploy to staging environment
4. Conduct thorough testing
5. Deploy to production
6. Monitor closely for first 48 hours
