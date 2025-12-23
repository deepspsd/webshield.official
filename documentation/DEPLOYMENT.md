# WebShield Deployment Guide

## 🚀 Production Deployment

### Prerequisites
- Docker & Docker Compose
- Domain name with DNS configured
- SSL certificate (Let's Encrypt recommended)
- VirusTotal API key
- MySQL 8.0+ or Docker

---

## 📦 Docker Deployment (Recommended)

### 1. Clone Repository
```bash
git clone https://github.com/deepspsd/webshield.official.git
cd webshield.official
```

### 2. Configure Environment
```bash
cp .env.example .env
nano .env  # Edit with your values
```

**Required Variables:**
```env
DB_PASSWORD=your_secure_password
VT_API_KEY=your_virustotal_api_key
JWT_SECRET=generate_random_secret_key
ALLOWED_ORIGINS=https://yourdomain.com
ALLOWED_HOSTS=yourdomain.com
```

### 3. Build and Start
```bash
# Build images
docker-compose build

# Start services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f webshield
```

### 4. Initialize Database
```bash
# Run migrations
docker-compose exec webshield alembic upgrade head

# Verify database
docker-compose exec mysql mysql -u root -p webshield -e "SHOW TABLES;"
```

### 5. Access Application
- **Web Interface**: https://yourdomain.com
- **API Docs**: https://yourdomain.com/docs
- **Health Check**: https://yourdomain.com/api/health
- **Metrics**: https://yourdomain.com/monitoring/metrics

---

## 🖥️ Manual Deployment

### 1. System Requirements
- Ubuntu 20.04+ or CentOS 8+
- Python 3.11+
- MySQL 8.0+
- Nginx
- 2GB+ RAM
- 20GB+ disk space

### 2. Install Dependencies
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python
sudo apt install python3.11 python3.11-venv python3-pip -y

# Install MySQL
sudo apt install mysql-server -y

# Install Nginx
sudo apt install nginx -y

# Install Redis (optional)
sudo apt install redis-server -y
```

### 3. Setup Application
```bash
# Create application directory
sudo mkdir -p /opt/webshield
cd /opt/webshield

# Clone repository
git clone https://github.com/deepspsd/webshield.official.git .

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

### 4. Configure Database
```bash
# Login to MySQL
sudo mysql -u root -p

# Create database and user
CREATE DATABASE webshield CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'webshield'@'localhost' IDENTIFIED BY 'your_secure_password';
GRANT ALL PRIVILEGES ON webshield.* TO 'webshield'@'localhost';
FLUSH PRIVILEGES;
EXIT;

# Run migrations
alembic upgrade head
```

### 5. Configure Nginx
```bash
# Copy nginx config
sudo cp nginx.conf /etc/nginx/sites-available/webshield
sudo ln -s /etc/nginx/sites-available/webshield /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Restart Nginx
sudo systemctl restart nginx
```

### 6. Setup SSL with Let's Encrypt
```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx -y

# Obtain certificate
sudo certbot --nginx -d yourdomain.com

# Auto-renewal
sudo systemctl enable certbot.timer
```

### 7. Create Systemd Service
```bash
# Create service file
sudo nano /etc/systemd/system/webshield.service
```

```ini
[Unit]
Description=WebShield Security Platform
After=network.target mysql.service

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/webshield
Environment="PATH=/opt/webshield/venv/bin"
ExecStart=/opt/webshield/venv/bin/python start_server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable webshield
sudo systemctl start webshield

# Check status
sudo systemctl status webshield
```

---

## 🔧 Configuration

### Environment Variables

#### Database
```env
DB_HOST=localhost
DB_PORT=3306
DB_USER=webshield
DB_PASSWORD=your_password
DB_NAME=webshield
DB_POOL_SIZE=20
```

#### Security
```env
JWT_SECRET=your_jwt_secret_key_min_32_chars
ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com
```

#### External Services
```env
VT_API_KEY=your_virustotal_api_key
GOOGLE_AI_API_KEY=your_google_ai_key
```

#### Performance
```env
SERVER_WORKERS=4
CACHE_TTL=300
RATE_LIMIT_REQUESTS=100
```

---

## 📊 Monitoring Setup

### 1. Prometheus
```bash
# Install Prometheus
wget https://github.com/prometheus/prometheus/releases/download/v2.45.0/prometheus-2.45.0.linux-amd64.tar.gz
tar xvfz prometheus-*.tar.gz
cd prometheus-*

# Configure prometheus.yml
cat > prometheus.yml <<EOF
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'webshield'
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: '/monitoring/metrics'
EOF

# Start Prometheus
./prometheus --config.file=prometheus.yml
```

### 2. Grafana
```bash
# Install Grafana
sudo apt-get install -y software-properties-common
sudo add-apt-repository "deb https://packages.grafana.com/oss/deb stable main"
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
sudo apt-get update
sudo apt-get install grafana

# Start Grafana
sudo systemctl start grafana-server
sudo systemctl enable grafana-server

# Access: http://localhost:3000 (admin/admin)
```

---

## 🔍 Health Checks

### Application Health
```bash
curl http://localhost:8000/api/health
```

### Database Health
```bash
curl http://localhost:8000/api/admin/pool-status
```

### ML Models Health
```bash
curl http://localhost:8000/api/admin/ml-training-stats
```

### System Metrics
```bash
curl http://localhost:8000/monitoring/performance
```

---

## 🐛 Troubleshooting

### Service Won't Start
```bash
# Check logs
sudo journalctl -u webshield -n 50 --no-pager

# Check Python errors
tail -f /opt/webshield/webshield.log

# Test manually
cd /opt/webshield
source venv/bin/activate
python start_server.py
```

### Database Connection Issues
```bash
# Test MySQL connection
mysql -u webshield -p webshield

# Check MySQL status
sudo systemctl status mysql

# View MySQL logs
sudo tail -f /var/log/mysql/error.log
```

### High Memory Usage
```bash
# Check process memory
ps aux | grep python

# Restart service
sudo systemctl restart webshield

# Adjust worker count in .env
SERVER_WORKERS=2
```

### Slow Scans
```bash
# Check VirusTotal API
curl -H "x-apikey: YOUR_KEY" https://www.virustotal.com/api/v3/urls/google.com

# Increase timeouts in .env
SCAN_CONTENT_TIMEOUT=10.0
SCAN_VIRUSTOTAL_TIMEOUT=5.0

# Check network latency
ping www.virustotal.com
```

---

## 🔄 Updates & Maintenance

### Update Application
```bash
cd /opt/webshield
git pull origin main
source venv/bin/activate
pip install -r requirements.txt
alembic upgrade head
sudo systemctl restart webshield
```

### Backup Database
```bash
# Backup
mysqldump -u webshield -p webshield > backup_$(date +%Y%m%d).sql

# Restore
mysql -u webshield -p webshield < backup_20250107.sql
```

### Clean Logs
```bash
# Rotate logs
sudo logrotate /etc/logrotate.d/webshield

# Manual cleanup
find /opt/webshield -name "*.log" -mtime +30 -delete
```

---

## 🌐 Multi-Server Deployment

### Load Balancer Setup
```nginx
upstream webshield_cluster {
    least_conn;
    server server1.example.com:8000 max_fails=3 fail_timeout=30s;
    server server2.example.com:8000 max_fails=3 fail_timeout=30s;
    server server3.example.com:8000 max_fails=3 fail_timeout=30s;
}
```

### Database Replication
```sql
-- Master server
CHANGE MASTER TO
  MASTER_HOST='master.example.com',
  MASTER_USER='replication_user',
  MASTER_PASSWORD='password',
  MASTER_LOG_FILE='mysql-bin.000001',
  MASTER_LOG_POS=107;

START SLAVE;
```

---

## 📞 Support

- **Documentation**: Full docs at `/docs`
- **Issues**: GitHub Issues
- **Email**: support@webshield.com
- **Status**: status.webshield.com

---

**Last Updated**: January 2025  
**Version**: 2.0.0
