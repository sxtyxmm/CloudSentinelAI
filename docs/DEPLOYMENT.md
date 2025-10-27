# Deployment Guide

## Production Deployment

### Prerequisites

- Docker & Docker Compose
- PostgreSQL 15+
- Redis 7+
- Elasticsearch 8+
- SSL/TLS certificates
- Domain name (optional)

### Step 1: Environment Configuration

1. Copy the example environment file:
```bash
cp .env.example .env
```

2. Update production values:
```bash
# Security
SECRET_KEY=<generate-strong-random-key>

# Database (use managed service in production)
DATABASE_URL=postgresql://user:password@db-host:5432/cloudsentinel

# API Keys
VIRUSTOTAL_API_KEY=<your-key>
SHODAN_API_KEY=<your-key>

# Cloud Credentials
AWS_ACCESS_KEY_ID=<your-key>
AWS_SECRET_ACCESS_KEY=<your-secret>

# Notifications
SLACK_WEBHOOK_URL=<your-webhook>
```

### Step 2: SSL/TLS Setup

1. Obtain SSL certificates (Let's Encrypt recommended):
```bash
sudo certbot certonly --standalone -d api.yourdomain.com
sudo certbot certonly --standalone -d app.yourdomain.com
```

2. Configure nginx reverse proxy:
```nginx
server {
    listen 443 ssl;
    server_name api.yourdomain.com;
    
    ssl_certificate /etc/letsencrypt/live/api.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.yourdomain.com/privkey.pem;
    
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}

server {
    listen 443 ssl;
    server_name app.yourdomain.com;
    
    ssl_certificate /etc/letsencrypt/live/app.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/app.yourdomain.com/privkey.pem;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Step 3: Database Setup

1. Create PostgreSQL database:
```sql
CREATE DATABASE cloudsentinel;
CREATE USER cloudsentinel_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE cloudsentinel TO cloudsentinel_user;
```

2. Run migrations (if using Alembic):
```bash
cd backend
alembic upgrade head
```

### Step 4: Docker Deployment

1. Build production images:
```bash
docker-compose -f docker-compose.prod.yml build
```

2. Start services:
```bash
docker-compose -f docker-compose.prod.yml up -d
```

3. Verify services are running:
```bash
docker-compose ps
docker-compose logs -f
```

### Step 5: Initial Setup

1. Create admin user:
```bash
curl -X POST "https://api.yourdomain.com/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@yourdomain.com",
    "password": "secure_password",
    "role": "admin"
  }'
```

2. Test the API:
```bash
curl https://api.yourdomain.com/health
```

### Step 6: Monitoring Setup

1. Configure Prometheus for metrics:
```yaml
scrape_configs:
  - job_name: 'cloudsentinel'
    static_configs:
      - targets: ['localhost:8000']
```

2. Set up log aggregation:
```bash
# Configure Elasticsearch for centralized logging
docker-compose exec elasticsearch curl -X PUT "localhost:9200/cloudsentinel-logs"
```

## Kubernetes Deployment

### Step 1: Create Namespace

```bash
kubectl create namespace cloudsentinel
```

### Step 2: Create Secrets

```bash
kubectl create secret generic cloudsentinel-secrets \
  --from-literal=database-url='postgresql://...' \
  --from-literal=secret-key='...' \
  -n cloudsentinel
```

### Step 3: Deploy Services

```bash
kubectl apply -f k8s/postgres.yaml
kubectl apply -f k8s/redis.yaml
kubectl apply -f k8s/elasticsearch.yaml
kubectl apply -f k8s/backend.yaml
kubectl apply -f k8s/frontend.yaml
kubectl apply -f k8s/ingress.yaml
```

### Step 4: Configure Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cloudsentinel-ingress
  namespace: cloudsentinel
spec:
  rules:
  - host: api.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: backend
            port:
              number: 8000
  - host: app.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend
            port:
              number: 3000
```

## AWS ECS Deployment

### Step 1: Create ECR Repositories

```bash
aws ecr create-repository --repository-name cloudsentinel/backend
aws ecr create-repository --repository-name cloudsentinel/frontend
```

### Step 2: Build and Push Images

```bash
# Login to ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account-id>.dkr.ecr.us-east-1.amazonaws.com

# Build and push backend
cd backend
docker build -t cloudsentinel/backend .
docker tag cloudsentinel/backend:latest <account-id>.dkr.ecr.us-east-1.amazonaws.com/cloudsentinel/backend:latest
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/cloudsentinel/backend:latest

# Build and push frontend
cd ../frontend
docker build -t cloudsentinel/frontend .
docker tag cloudsentinel/frontend:latest <account-id>.dkr.ecr.us-east-1.amazonaws.com/cloudsentinel/frontend:latest
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/cloudsentinel/frontend:latest
```

### Step 3: Create ECS Task Definition

```json
{
  "family": "cloudsentinel-backend",
  "networkMode": "awsvpc",
  "containerDefinitions": [
    {
      "name": "backend",
      "image": "<account-id>.dkr.ecr.us-east-1.amazonaws.com/cloudsentinel/backend:latest",
      "portMappings": [
        {
          "containerPort": 8000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "DATABASE_URL",
          "value": "postgresql://..."
        }
      ]
    }
  ]
}
```

## Scaling Considerations

### Horizontal Scaling

1. Backend API:
```bash
# Docker Compose
docker-compose up -d --scale backend=3

# Kubernetes
kubectl scale deployment backend --replicas=3 -n cloudsentinel
```

2. Configure load balancer for backend instances

### Vertical Scaling

Update resource limits:
```yaml
resources:
  limits:
    cpu: "2"
    memory: "4Gi"
  requests:
    cpu: "1"
    memory: "2Gi"
```

## Backup and Recovery

### Database Backup

```bash
# Daily backup script
#!/bin/bash
BACKUP_DIR="/backups/cloudsentinel"
DATE=$(date +%Y%m%d_%H%M%S)

pg_dump -h localhost -U cloudsentinel_user cloudsentinel > "$BACKUP_DIR/backup_$DATE.sql"
gzip "$BACKUP_DIR/backup_$DATE.sql"

# Keep only last 30 days
find $BACKUP_DIR -name "backup_*.sql.gz" -mtime +30 -delete
```

### Model Backup

```bash
# Backup trained models
tar -czf models_backup_$(date +%Y%m%d).tar.gz data/models/
aws s3 cp models_backup_*.tar.gz s3://your-bucket/backups/
```

## Monitoring and Alerts

### Health Checks

Configure health check endpoints:
- `/health` - Basic health check
- `/health/db` - Database connectivity
- `/health/redis` - Redis connectivity

### Metrics Collection

Key metrics to monitor:
- API response time
- Detection latency
- Alert generation rate
- False positive rate
- Database query performance
- Memory usage
- CPU utilization

### Log Aggregation

Configure centralized logging:
```bash
# Forward logs to Elasticsearch
docker-compose logs -f | logstash -f logstash.conf
```

## Security Hardening

1. Enable firewall rules:
```bash
ufw allow 443/tcp
ufw allow 80/tcp
ufw enable
```

2. Configure fail2ban for SSH protection

3. Enable audit logging:
```python
# Log all API requests
@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info(f"Request: {request.method} {request.url}")
    response = await call_next(request)
    return response
```

4. Regular security updates:
```bash
# Update all packages
apt update && apt upgrade -y

# Update Docker images
docker-compose pull
docker-compose up -d
```

## Troubleshooting

### Common Issues

1. **Database connection errors**
   - Check DATABASE_URL configuration
   - Verify database is running
   - Check network connectivity

2. **High memory usage**
   - Reduce batch size for log processing
   - Enable pagination for large queries
   - Configure memory limits in Docker

3. **Slow API responses**
   - Add database indexes
   - Enable Redis caching
   - Optimize database queries

### Debug Mode

Enable debug logging:
```bash
export LOG_LEVEL=DEBUG
docker-compose restart backend
```

### Performance Profiling

```python
# Add profiling middleware
from fastapi.middleware.profiler import ProfilerMiddleware
app.add_middleware(ProfilerMiddleware)
```
