# �� Deployment Guide

Comprehensive deployment guide for the AWS KMS Web UI platform.

## 📋 **Deployment Overview**

This guide covers deploying the AWS KMS Web UI platform in various environments, from development to production. The platform supports multiple deployment models and can be scaled to meet enterprise requirements.

### **Deployment Models**
- **Local Development** - Single machine for development
- **Docker Container** - Containerized deployment
- **Cloud Deployment** - AWS, Azure, GCP deployment
- **Kubernetes** - Container orchestration
- **Serverless** - AWS Lambda deployment
- **Enterprise** - Multi-region, high-availability deployment

---

## 🛠️ **Prerequisites**

### **System Requirements**
- **CPU**: 2+ cores (4+ recommended for production)
- **RAM**: 4GB minimum (8GB+ recommended)
- **Storage**: 20GB minimum (SSD recommended)
- **Network**: Stable internet connection for AWS API access

### **Software Requirements**
- **Python**: 3.8 or higher
- **Docker**: 20.10+ (for containerized deployment)
- **AWS CLI**: Latest version
- **Git**: For source code management

### **AWS Requirements**
- **AWS Account** with appropriate permissions
- **IAM User/Role** with KMS access
- **VPC** (for production deployment)
- **Security Groups** configured
- **CloudTrail** enabled (recommended)

---

## 🏠 **Local Development Deployment**

### **Step 1: Environment Setup**
```bash
# Clone the repository
git clone https://github.com/yourusername/aws-kms-web-ui.git
cd aws-kms-web-ui

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### **Step 2: AWS Configuration**
```bash
# Configure AWS credentials
aws configure

# Verify AWS access
aws kms list-keys --region us-east-1
```

### **Step 3: Environment Variables**
```bash
# Create .env file
cat > .env << EOF
FLASK_ENV=development
SECRET_KEY=your-super-secret-key-here
DATABASE_URL=sqlite:///kms_platform.db
AWS_DEFAULT_REGION=us-east-1
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=tinyllama
ENABLE_AI_FEATURES=true
ENABLE_SECURITY_MONITORING=true
EOF
```

### **Step 4: AI Setup (Optional)**
```bash
# Install Ollama (if not already installed)
curl -fsSL https://ollama.ai/install.sh | sh

# Pull the TinyLlama model
ollama pull tinyllama

# Start Ollama service
ollama serve
```

### **Step 5: Run the Application**
```bash
# Start the Flask application
python app.py

# Access the application
open http://localhost:5000
```

---

## 🐳 **Docker Deployment**

### **Single Container Deployment**

#### **Step 1: Build the Image**
```bash
# Build Docker image
docker build -t aws-kms-web-ui .

# Verify image creation
docker images | grep aws-kms-web-ui
```

#### **Step 2: Run the Container**
```bash
# Run with basic configuration
docker run -d \
  --name kms-web-ui \
  -p 5000:5000 \
  -e AWS_ACCESS_KEY_ID=your-access-key \
  -e AWS_SECRET_ACCESS_KEY=your-secret-key \
  -e AWS_DEFAULT_REGION=us-east-1 \
  -v $(pwd)/data:/app/data \
  aws-kms-web-ui
```

#### **Step 3: Verify Deployment**
```bash
# Check container status
docker ps

# View logs
docker logs kms-web-ui

# Access application
curl http://localhost:5000
```

### **Docker Compose Deployment**

#### **Step 1: Create docker-compose.yml**
```yaml
version: '3.8'

services:
  kms-web-ui:
    build: .
    ports:
      - "5000:5000"
    environment:
      - FLASK_ENV=production
      - SECRET_KEY=${SECRET_KEY}
      - AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
      - AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
      - AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}
      - OLLAMA_HOST=http://ollama:11434
      - ENABLE_AI_FEATURES=true
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
    depends_on:
      - ollama
    restart: unless-stopped

  ollama:
    image: ollama/ollama:latest
    ports:
      - "11434:11434"
    volumes:
      - ollama_data:/root/.ollama
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - kms-web-ui
    restart: unless-stopped

volumes:
  ollama_data:
```

#### **Step 2: Create nginx.conf**
```nginx
events {
    worker_connections 1024;
}

http {
    upstream kms_app {
        server kms-web-ui:5000;
    }

    server {
        listen 80;
        server_name your-domain.com;
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name your-domain.com;

        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;

        location / {
            proxy_pass http://kms_app;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
```

#### **Step 3: Deploy with Docker Compose**
```bash
# Create environment file
cat > .env << EOF
SECRET_KEY=your-super-secret-key-here
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_DEFAULT_REGION=us-east-1
EOF

# Deploy services
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f
```

---

## ☁️ **Cloud Deployment**

### **AWS Deployment**

#### **EC2 Deployment**

##### **Step 1: Launch EC2 Instance**
```bash
# Launch Ubuntu 22.04 instance
aws ec2 run-instances \
  --image-id ami-0c02fb55956c7d316 \
  --instance-type t3.medium \
  --key-name your-key-pair \
  --security-group-ids sg-12345678 \
  --subnet-id subnet-12345678 \
  --user-data file://user-data.sh
```

##### **Step 2: Create user-data.sh**
```bash
#!/bin/bash
apt-get update
apt-get install -y python3 python3-pip git nginx

# Clone repository
git clone https://github.com/yourusername/aws-kms-web-ui.git
cd aws-kms-web-ui

# Install dependencies
pip3 install -r requirements.txt

# Configure environment
cat > .env << EOF
FLASK_ENV=production
SECRET_KEY=your-super-secret-key-here
AWS_DEFAULT_REGION=us-east-1
EOF

# Create systemd service
cat > /etc/systemd/system/kms-web-ui.service << EOF
[Unit]
Description=AWS KMS Web UI
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/aws-kms-web-ui
Environment=PATH=/home/ubuntu/aws-kms-web-ui/venv/bin
ExecStart=/home/ubuntu/aws-kms-web-ui/venv/bin/python app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Start service
systemctl enable kms-web-ui
systemctl start kms-web-ui
```

#### **ECS Deployment**

##### **Step 1: Create ECS Cluster**
```bash
# Create cluster
aws ecs create-cluster --cluster-name kms-web-ui-cluster

# Create task definition
aws ecs register-task-definition --cli-input-json file://task-definition.json
```

##### **Step 2: Create task-definition.json**
```json
{
  "family": "kms-web-ui",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::123456789012:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::123456789012:role/kms-web-ui-task-role",
  "containerDefinitions": [
    {
      "name": "kms-web-ui",
      "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/kms-web-ui:latest",
      "portMappings": [
        {
          "containerPort": 5000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "FLASK_ENV",
          "value": "production"
        },
        {
          "name": "AWS_DEFAULT_REGION",
          "value": "us-east-1"
        }
      ],
      "secrets": [
        {
          "name": "SECRET_KEY",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789012:secret:kms-web-ui-secret"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/kms-web-ui",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

#### **Lambda Deployment (Serverless)**

##### **Step 1: Create Lambda Function**
```bash
# Create deployment package
pip install -r requirements.txt -t package/
cp app.py package/
cd package && zip -r ../lambda-deployment.zip .

# Create Lambda function
aws lambda create-function \
  --function-name kms-web-ui \
  --runtime python3.9 \
  --role arn:aws:iam::123456789012:role/lambda-execution-role \
  --handler app.lambda_handler \
  --zip-file fileb://lambda-deployment.zip \
  --timeout 30 \
  --memory-size 512
```

##### **Step 2: Create API Gateway**
```bash
# Create REST API
aws apigateway create-rest-api \
  --name "KMS Web UI API" \
  --description "API for KMS Web UI"

# Create resources and methods
# (Detailed API Gateway setup omitted for brevity)
```

### **Multi-Region Deployment**

#### **Step 1: Deploy to Multiple Regions**
```bash
# Deploy to primary region
./deploy.sh us-east-1

# Deploy to secondary region
./deploy.sh us-west-2

# Deploy to tertiary region
./deploy.sh eu-west-1
```

#### **Step 2: Configure Global Load Balancer**
```bash
# Create Route 53 health checks
aws route53 create-health-check \
  --health-check-config file://health-check-config.json

# Create Route 53 records
aws route53 create-hosted-zone --name yourdomain.com
```

#### **Step 3: Cross-Region Replication**
```bash
# Configure cross-region key replication
aws kms create-replica-key \
  --replica-region us-west-2 \
  --key-id arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ef-ghij-klmnopqrstuv
```

---

## ☸️ **Kubernetes Deployment**

### **Step 1: Create Namespace**
```bash
kubectl create namespace kms-web-ui
```

### **Step 2: Create ConfigMap**
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kms-web-ui-config
  namespace: kms-web-ui
data:
  FLASK_ENV: "production"
  AWS_DEFAULT_REGION: "us-east-1"
  OLLAMA_HOST: "http://ollama-service:11434"
```

### **Step 3: Create Secret**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: kms-web-ui-secret
  namespace: kms-web-ui
type: Opaque
data:
  SECRET_KEY: <base64-encoded-secret>
  AWS_ACCESS_KEY_ID: <base64-encoded-access-key>
  AWS_SECRET_ACCESS_KEY: <base64-encoded-secret-key>
```

### **Step 4: Create Deployment**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kms-web-ui
  namespace: kms-web-ui
spec:
  replicas: 3
  selector:
    matchLabels:
      app: kms-web-ui
  template:
    metadata:
      labels:
        app: kms-web-ui
    spec:
      containers:
      - name: kms-web-ui
        image: aws-kms-web-ui:latest
        ports:
        - containerPort: 5000
        envFrom:
        - configMapRef:
            name: kms-web-ui-config
        - secretRef:
            name: kms-web-ui-secret
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 5000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 5000
          initialDelaySeconds: 5
          periodSeconds: 5
```

### **Step 5: Create Service**
```yaml
apiVersion: v1
kind: Service
metadata:
  name: kms-web-ui-service
  namespace: kms-web-ui
spec:
  selector:
    app: kms-web-ui
  ports:
  - protocol: TCP
    port: 80
    targetPort: 5000
  type: LoadBalancer
```

### **Step 6: Create Ingress**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: kms-web-ui-ingress
  namespace: kms-web-ui
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - your-domain.com
    secretName: kms-web-ui-tls
  rules:
  - host: your-domain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: kms-web-ui-service
            port:
              number: 80
```

### **Step 7: Deploy to Kubernetes**
```bash
# Apply all configurations
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -n kms-web-ui

# Check service status
kubectl get svc -n kms-web-ui

# Check ingress status
kubectl get ingress -n kms-web-ui
```

---

## 🔧 **Production Configuration**

### **Environment Variables**
```bash
# Production environment variables
FLASK_ENV=production
SECRET_KEY=your-super-secret-production-key
DATABASE_URL=postgresql://user:pass@host:port/db
AWS_DEFAULT_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key

# AI Configuration
OLLAMA_HOST=http://ollama-service:11434
OLLAMA_MODEL=tinyllama
ENABLE_AI_FEATURES=true

# Security Configuration
ENABLE_RATE_LIMITING=true
ENABLE_AUDIT_LOGGING=true
ENABLE_SECURITY_MONITORING=true
ENABLE_AI_SECURITY=true

# Email Configuration
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email
SMTP_PASSWORD=your-password

# Slack Configuration
SLACK_WEBHOOK_URL=your-webhook-url

# Monitoring Configuration
ENABLE_METRICS=true
METRICS_PORT=9090
```

### **Security Configuration**
```python
# Production security settings
SECURITY_CONFIG = {
    "rate_limiting": {
        "enabled": True,
        "default": "100 per minute",
        "auth": "10 per minute"
    },
    "cors": {
        "enabled": True,
        "origins": ["https://yourdomain.com"],
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "headers": ["Content-Type", "Authorization"]
    },
    "ssl": {
        "enabled": True,
        "cert_file": "/path/to/cert.pem",
        "key_file": "/path/to/key.pem"
    }
}
```

### **Monitoring Configuration**
```python
# Monitoring settings
MONITORING_CONFIG = {
    "metrics": {
        "enabled": True,
        "port": 9090,
        "path": "/metrics"
    },
    "logging": {
        "level": "INFO",
        "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        "file": "/var/log/kms-web-ui/app.log"
    },
    "health_checks": {
        "enabled": True,
        "endpoint": "/health",
        "interval": 30
    }
}
```

---

## 📊 **Scaling & Performance**

### **Horizontal Scaling**
```bash
# Scale Docker Compose services
docker-compose up -d --scale kms-web-ui=3

# Scale Kubernetes deployment
kubectl scale deployment kms-web-ui --replicas=5

# Scale ECS service
aws ecs update-service \
  --cluster kms-web-ui-cluster \
  --service kms-web-ui-service \
  --desired-count 5
```

### **Load Balancing**
```nginx
# Nginx load balancer configuration
upstream kms_app {
    least_conn;
    server kms-web-ui-1:5000;
    server kms-web-ui-2:5000;
    server kms-web-ui-3:5000;
    keepalive 32;
}
```

### **Caching Strategy**
```python
# Redis caching configuration
CACHE_CONFIG = {
    "type": "redis",
    "host": "redis-service",
    "port": 6379,
    "db": 0,
    "ttl": 3600
}
```

---

## 🔍 **Monitoring & Logging**

### **Application Monitoring**
```python
# Prometheus metrics
from prometheus_client import Counter, Histogram, generate_latest

# Define metrics
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP requests')
REQUEST_LATENCY = Histogram('http_request_duration_seconds', 'HTTP request latency')

# Export metrics endpoint
@app.route('/metrics')
def metrics():
    return generate_latest()
```

### **Logging Configuration**
```python
# Structured logging
import structlog

logger = structlog.get_logger()

# Log format
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)
```

### **Health Checks**
```python
@app.route('/health')
def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.0.0",
        "services": {
            "database": check_database(),
            "aws_kms": check_aws_kms(),
            "ai_service": check_ai_service()
        }
    }
```

---

## 🔄 **Backup & Recovery**

### **Database Backup**
```bash
# SQLite backup
sqlite3 kms_platform.db ".backup backup/kms_platform_$(date +%Y%m%d_%H%M%S).db"

# PostgreSQL backup
pg_dump -h host -U user -d database > backup/database_$(date +%Y%m%d_%H%M%S).sql

# Automated backup script
#!/bin/bash
BACKUP_DIR="/backup/kms-web-ui"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup database
sqlite3 kms_platform.db ".backup $BACKUP_DIR/database_$DATE.db"

# Backup configuration
cp .env $BACKUP_DIR/config_$DATE.env

# Backup logs
tar -czf $BACKUP_DIR/logs_$DATE.tar.gz logs/

# Clean old backups (keep 30 days)
find $BACKUP_DIR -name "*.db" -mtime +30 -delete
find $BACKUP_DIR -name "*.env" -mtime +30 -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete
```

### **Disaster Recovery**
```bash
# Recovery script
#!/bin/bash
BACKUP_DIR="/backup/kms-web-ui"
LATEST_BACKUP=$(ls -t $BACKUP_DIR/database_*.db | head -1)

# Stop application
systemctl stop kms-web-ui

# Restore database
cp $LATEST_BACKUP kms_platform.db

# Restore configuration
cp $BACKUP_DIR/config_*.env .env

# Start application
systemctl start kms-web-ui

# Verify recovery
curl -f http://localhost:5000/health
```

---

## 🚨 **Troubleshooting**

### **Common Issues**

#### **Application Won't Start**
```bash
# Check logs
docker logs kms-web-ui
kubectl logs -f deployment/kms-web-ui

# Check environment variables
docker exec kms-web-ui env
kubectl exec deployment/kms-web-ui -- env

# Check port availability
netstat -tulpn | grep 5000
```

#### **AWS Connection Issues**
```bash
# Verify AWS credentials
aws sts get-caller-identity

# Test KMS access
aws kms list-keys --region us-east-1

# Check IAM permissions
aws iam get-user
aws iam list-attached-user-policies --user-name your-user
```

#### **AI Service Issues**
```bash
# Check Ollama service
curl http://localhost:11434/api/tags

# Test AI model
curl -X POST http://localhost:11434/api/generate \
  -d '{"model": "tinyllama", "prompt": "Hello"}'

# Restart Ollama service
docker restart ollama
systemctl restart ollama
```

### **Performance Issues**
```bash
# Check resource usage
docker stats kms-web-ui
kubectl top pods -n kms-web-ui

# Check database performance
sqlite3 kms_platform.db "PRAGMA integrity_check;"

# Monitor network connections
netstat -an | grep :5000 | wc -l
```

---

## 📞 **Support & Maintenance**

### **Maintenance Schedule**
- **Daily**: Log rotation and cleanup
- **Weekly**: Security updates and patches
- **Monthly**: Performance optimization
- **Quarterly**: Security assessments
- **Annually**: Major version upgrades

### **Support Contacts**
- **Technical Support**: support@yourcompany.com
- **Security Issues**: security@yourcompany.com
- **Emergency**: +1-555-0123 (24/7)

### **Documentation**
- **[API Documentation](api.md)** - Complete API reference
- **[Security Guide](security.md)** - Security best practices
- **[Troubleshooting Guide](troubleshooting.md)** - Common issues
- **[User Guide](user-guide.md)** - End-user documentation

---

**This deployment guide is continuously updated. For the latest information, always refer to the current version in the repository.** 