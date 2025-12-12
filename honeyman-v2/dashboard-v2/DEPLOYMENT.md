# Honeyman V2 Dashboard - Deployment Guide

Complete deployment guide for Honeyman V2 Dashboard Backend.

## Quick Start with Docker Compose

### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- 4GB+ RAM
- 20GB+ disk space

### Deployment Steps

```bash
# 1. Clone repository
git clone https://github.com/yourusername/honeyman.git
cd honeyman/honeyman-v2/dashboard-v2

# 2. Configure environment
cp .env.example .env
vim .env  # Edit passwords and secrets

# 3. Generate secret key
openssl rand -hex 32
# Copy output to SECRET_KEY in .env

# 4. Start services
docker-compose up -d

# 5. Wait for services to be healthy
docker-compose ps

# 6. Run database migrations
docker-compose exec backend alembic upgrade head

# 7. Create admin user
docker-compose exec backend python3 << EOF
import asyncio
from app.db.base import AsyncSessionLocal
from app.models.user import User, UserRole
from app.core.security import get_password_hash

async def create_admin():
    async with AsyncSessionLocal() as db:
        admin = User(
            username="admin",
            email="admin@honeyman.io",
            password_hash=get_password_hash("ChangeThisPassword"),
            full_name="Admin User",
            role=UserRole.ADMIN,
            is_active=True,
            is_verified=True
        )
        db.add(admin)
        await db.commit()
        print("Admin user created")

asyncio.run(create_admin())
EOF

# 8. Setup MQTT passwords
docker-compose exec mqtt mosquitto_passwd -c /mosquitto/config/password.txt dashboard
# Enter password when prompted

# For each sensor (replace sensor-001 with actual sensor ID)
docker-compose exec mqtt mosquitto_passwd /mosquitto/config/password.txt sensor_sensor-001

# 9. Restart MQTT to apply password changes
docker-compose restart mqtt

# 10. Verify deployment
curl http://localhost:8000/health
# Should return: {"status":"ok","service":"Honeyman Dashboard API","version":"2.0.0"}
```

### Access Points

- **API Documentation**: http://localhost:8000/api/v2/docs
- **Health Check**: http://localhost:8000/health
- **PostgreSQL**: localhost:5432
- **Redis**: localhost:6379
- **MQTT**: localhost:1883
- **MQTT WebSocket**: localhost:9001

## Production Deployment

### VPS Requirements

**Minimum Specs:**
- 2 vCPU
- 4GB RAM
- 40GB SSD
- Ubuntu 22.04 LTS

**Recommended Specs:**
- 4 vCPU
- 8GB RAM
- 80GB SSD
- Ubuntu 22.04 LTS

### Production Setup

```bash
# 1. Update system
sudo apt-get update && sudo apt-get upgrade -y

# 2. Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# 3. Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# 4. Setup firewall
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 8883/tcp  # MQTT TLS
sudo ufw enable

# 5. Clone and deploy
git clone https://github.com/yourusername/honeyman.git
cd honeyman/honeyman-v2/dashboard-v2

# 6. Configure production environment
cp .env.example .env
nano .env  # Set strong passwords!

# 7. Deploy with Docker Compose
docker-compose up -d

# 8. Setup SSL/TLS with Let's Encrypt (nginx reverse proxy)
# See SSL_SETUP.md for details
```

### SSL/TLS Configuration

For production, use nginx as reverse proxy with Let's Encrypt:

```nginx
# /etc/nginx/sites-available/honeyman-api

server {
    listen 443 ssl http2;
    server_name api.honeyman.io;

    ssl_certificate /etc/letsencrypt/live/api.honeyman.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.honeyman.io/privkey.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;

    # Backend proxy
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket proxy
    location /api/v2/ws {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name api.honeyman.io;
    return 301 https://$host$request_uri;
}
```

## Monitoring & Maintenance

### Service Status

```bash
# Check all services
docker-compose ps

# View logs
docker-compose logs -f backend
docker-compose logs -f postgres
docker-compose logs -f mqtt
docker-compose logs -f redis

# Restart services
docker-compose restart backend
```

### Database Maintenance

```bash
# Backup database
docker-compose exec postgres pg_dump -U honeyman honeyman_v2 > backup_$(date +%Y%m%d).sql

# Restore database
docker-compose exec -T postgres psql -U honeyman honeyman_v2 < backup_20251130.sql

# Check database size
docker-compose exec postgres psql -U honeyman -d honeyman_v2 -c "SELECT pg_size_pretty(pg_database_size('honeyman_v2'));"

# Vacuum database (optimize)
docker-compose exec postgres psql -U honeyman -d honeyman_v2 -c "VACUUM ANALYZE;"
```

### TimescaleDB Maintenance

```bash
# Check chunk status
docker-compose exec postgres psql -U honeyman -d honeyman_v2 -c "SELECT * FROM timescaledb_information.chunks WHERE hypertable_name = 'threats';"

# Check compression status
docker-compose exec postgres psql -U honeyman -d honeyman_v2 -c "SELECT * FROM timescaledb_information.compression_settings WHERE hypertable_name = 'threats';"

# Manual compression
docker-compose exec postgres psql -U honeyman -d honeyman_v2 -c "CALL run_job((SELECT id FROM timescaledb_information.jobs WHERE proc_name = 'policy_compression'));"
```

### MQTT Maintenance

```bash
# View MQTT logs
docker-compose logs -f mqtt

# Check connected clients
docker-compose exec mqtt mosquitto_sub -t '$SYS/broker/clients/connected' -C 1

# Test MQTT connection
docker-compose exec mqtt mosquitto_pub -t 'test' -m 'hello' -u dashboard -P your-password
docker-compose exec mqtt mosquitto_sub -t 'test' -u dashboard -P your-password
```

## Scaling

### Horizontal Scaling

For high load, scale backend API:

```yaml
# docker-compose.override.yml
services:
  backend:
    deploy:
      replicas: 4
```

### Load Balancing

Use nginx for load balancing:

```nginx
upstream backend {
    least_conn;
    server localhost:8001;
    server localhost:8002;
    server localhost:8003;
    server localhost:8004;
}

server {
    listen 443 ssl;
    server_name api.honeyman.io;

    location / {
        proxy_pass http://backend;
    }
}
```

## Troubleshooting

### Backend won't start

```bash
# Check logs
docker-compose logs backend

# Common issues:
# 1. Database not ready - wait for postgres to be healthy
# 2. Redis connection failed - check redis is running
# 3. MQTT connection failed - check mqtt broker

# Restart in correct order
docker-compose up -d postgres redis mqtt
sleep 10
docker-compose up -d backend
```

### Database connection errors

```bash
# Test database connection
docker-compose exec postgres psql -U honeyman -d honeyman_v2 -c "SELECT 1;"

# Check if TimescaleDB extension is enabled
docker-compose exec postgres psql -U honeyman -d honeyman_v2 -c "SELECT * FROM pg_extension WHERE extname = 'timescaledb';"
```

### MQTT authentication failures

```bash
# Recreate password file
docker-compose exec mqtt mosquitto_passwd -c /mosquitto/config/password.txt dashboard

# Restart MQTT
docker-compose restart mqtt

# Test authentication
mosquitto_sub -h localhost -p 1883 -t 'test' -u dashboard -P your-password
```

## Backup Strategy

### Automated Backups

```bash
# Create backup script
cat > backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/backup/honeyman"
DATE=$(date +%Y%m%d_%H%M%S)

# Backup database
docker-compose exec -T postgres pg_dump -U honeyman honeyman_v2 | gzip > "$BACKUP_DIR/db_$DATE.sql.gz"

# Backup MQTT config
tar -czf "$BACKUP_DIR/mqtt_$DATE.tar.gz" mosquitto/config/

# Keep only last 30 days
find "$BACKUP_DIR" -name "*.gz" -mtime +30 -delete

echo "Backup completed: $DATE"
EOF

chmod +x backup.sh

# Add to crontab (daily at 2 AM)
echo "0 2 * * * /path/to/backup.sh" | crontab -
```

## Security Checklist

- [ ] Change default passwords in `.env`
- [ ] Generate strong SECRET_KEY
- [ ] Enable SSL/TLS for MQTT (port 8883)
- [ ] Use nginx reverse proxy with SSL
- [ ] Enable firewall (UFW)
- [ ] Restrict database access to localhost
- [ ] Enable fail2ban for SSH
- [ ] Regular security updates: `sudo apt-get update && sudo apt-get upgrade`
- [ ] Monitor logs for suspicious activity
- [ ] Backup encryption keys and passwords securely

## Performance Tuning

### PostgreSQL

```bash
# Edit postgresql.conf
docker-compose exec postgres bash -c 'echo "shared_buffers = 2GB" >> /var/lib/postgresql/data/postgresql.conf'
docker-compose exec postgres bash -c 'echo "effective_cache_size = 6GB" >> /var/lib/postgresql/data/postgresql.conf'
docker-compose restart postgres
```

### Redis

```bash
# Edit redis.conf
docker-compose exec redis redis-cli CONFIG SET maxmemory 1gb
docker-compose exec redis redis-cli CONFIG SET maxmemory-policy allkeys-lru
```

## Support

For issues:
- GitHub: https://github.com/yourusername/honeyman/issues
- Email: support@honeyman.io
- Documentation: https://docs.honeyman.io
