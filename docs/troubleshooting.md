# 🔧 Troubleshooting Guide

Comprehensive troubleshooting guide for the AWS KMS Web UI platform.

## 📋 **Quick Troubleshooting**

### **Common Issues & Solutions**

| Issue | Quick Fix | Detailed Solution |
|-------|-----------|-------------------|
| **App won't start** | Check port 5000 | [Application Startup Issues](#application-startup-issues) |
| **AWS connection failed** | Verify credentials | [AWS Connection Issues](#aws-connection-issues) |
| **AI features not working** | Check Ollama service | [AI Service Issues](#ai-service-issues) |
| **Navigation not working** | Clear browser cache | [UI/UX Issues](#uiux-issues) |
| **Analytics not loading** | Check authentication | [Analytics Issues](#analytics-issues) |
| **Performance problems** | Check system resources | [Performance Issues](#performance-issues) |

---

## 🚀 **Application Startup Issues**

### **Port Already in Use**
```bash
# Check what's using port 5000
netstat -tulpn | grep :5000
lsof -i :5000

# Kill the process
sudo kill -9 $(lsof -t -i:5000)

# Or use a different port
export FLASK_RUN_PORT=5001
python app.py
```

### **Permission Denied**
```bash
# Check file permissions
ls -la app.py
chmod +x app.py

# Check directory permissions
ls -la .
chmod 755 .

# Run with proper user
sudo -u your-user python app.py
```

### **Missing Dependencies**
```bash
# Check Python version
python --version

# Reinstall dependencies
pip uninstall -r requirements.txt -y
pip install -r requirements.txt

# Check for conflicts
pip check
```

### **Database Issues**
```bash
# Check database file
ls -la kms_platform.db

# Reset database
rm kms_platform.db
python -c "from app import init_db; init_db()"

# Check database integrity
sqlite3 kms_platform.db "PRAGMA integrity_check;"
```

### **Environment Variables**
```bash
# Check environment variables
env | grep -E "(FLASK|AWS|SECRET)"

# Create .env file if missing
cat > .env << EOF
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
AWS_DEFAULT_REGION=us-east-1
EOF
```

---

## ☁️ **AWS Connection Issues**

### **Invalid Credentials**
```bash
# Test AWS credentials
aws sts get-caller-identity

# Configure AWS CLI
aws configure

# Check credentials file
cat ~/.aws/credentials

# Set environment variables
export AWS_ACCESS_KEY_ID=your-access-key
export AWS_SECRET_ACCESS_KEY=your-secret-key
export AWS_DEFAULT_REGION=us-east-1
```

### **Insufficient Permissions**
```bash
# Test KMS access
aws kms list-keys --region us-east-1

# Check IAM permissions
aws iam get-user
aws iam list-attached-user-policies --user-name your-user

# Required permissions
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "kms:*",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "cloudwatch:GetMetricStatistics"
            ],
            "Resource": "*"
        }
    ]
}
```

### **Network Connectivity**
```bash
# Test internet connectivity
ping 8.8.8.8

# Test AWS API connectivity
curl -I https://kms.us-east-1.amazonaws.com

# Check proxy settings
echo $http_proxy
echo $https_proxy

# Configure proxy if needed
export http_proxy=http://proxy:port
export https_proxy=http://proxy:port
```

### **Region Issues**
```bash
# List available regions
aws ec2 describe-regions --query 'Regions[].RegionName' --output table

# Set correct region
export AWS_DEFAULT_REGION=us-east-1

# Test region-specific access
aws kms list-keys --region us-east-1
```

---

## 🤖 **AI Service Issues**

### **Ollama Not Running**
```bash
# Check Ollama service status
systemctl status ollama
docker ps | grep ollama

# Start Ollama service
systemctl start ollama
docker run -d --name ollama -p 11434:11434 ollama/ollama:latest

# Check Ollama API
curl http://localhost:11434/api/tags
```

### **Model Not Available**
```bash
# List available models
ollama list
curl http://localhost:11434/api/tags

# Pull TinyLlama model
ollama pull tinyllama

# Check model status
curl -X POST http://localhost:11434/api/generate \
  -d '{"model": "tinyllama", "prompt": "Hello"}'
```

### **AI Response Issues**
```bash
# Test AI endpoint
curl -X POST http://localhost:5000/api/ai/query \
  -H "Content-Type: application/json" \
  -d '{"query": "Hello"}'

# Check AI configuration
echo $OLLAMA_HOST
echo $OLLAMA_MODEL

# Restart AI service
docker restart ollama
systemctl restart ollama
```

### **Memory Issues**
```bash
# Check available memory
free -h

# Check Ollama memory usage
docker stats ollama

# Increase swap if needed
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

---

## 🎨 **UI/UX Issues**

### **Navigation Not Working**
```bash
# Clear browser cache
# Chrome: Ctrl+Shift+Delete
# Firefox: Ctrl+Shift+Delete

# Check JavaScript console
# F12 -> Console tab

# Test navigation manually
curl http://localhost:5000/
```

### **Styling Issues**
```bash
# Check CSS loading
curl -I http://localhost:5000/static/css/style.css

# Clear browser cache
# Hard refresh: Ctrl+F5

# Check for CSS conflicts
# Disable browser extensions
```

### **Responsive Design Issues**
```bash
# Test different screen sizes
# Chrome DevTools -> Toggle device toolbar

# Check viewport meta tag
# Should be: <meta name="viewport" content="width=device-width, initial-scale=1.0">

# Test on different browsers
# Chrome, Firefox, Safari, Edge
```

### **Animation Issues**
```bash
# Check browser support
# Modern browsers required for CSS animations

# Disable animations if needed
# Add CSS: * { animation: none !important; }

# Check for performance issues
# Monitor CPU usage during animations
```

---

## 📊 **Analytics Issues**

### **Charts Not Loading**
```bash
# Check Chart.js loading
curl -I https://cdn.jsdelivr.net/npm/chart.js

# Check JavaScript errors
# F12 -> Console tab

# Test chart data endpoint
curl http://localhost:5000/api/key-stats
```

### **Real-time Updates Not Working**
```bash
# Check WebSocket connection
# F12 -> Network tab -> WS

# Test polling endpoints
curl http://localhost:5000/api/key-stats
curl http://localhost:5000/api/recent-key-activity

# Check for rate limiting
# Monitor network requests
```

### **Data Not Refreshing**
```bash
# Check cache headers
curl -I http://localhost:5000/api/key-stats

# Clear browser cache
# Hard refresh: Ctrl+F5

# Check for stale data
# Verify AWS data is current
```

---

## ⚡ **Performance Issues**

### **Slow Loading**
```bash
# Check system resources
htop
df -h
free -h

# Monitor application performance
docker stats kms-web-ui
kubectl top pods -n kms-web-ui

# Check network latency
ping google.com
```

### **High Memory Usage**
```bash
# Check memory usage
free -h
docker stats

# Optimize Python memory
export PYTHONOPTIMIZE=1

# Restart application
docker restart kms-web-ui
systemctl restart kms-web-ui
```

### **Database Performance**
```bash
# Check database size
ls -lh kms_platform.db

# Optimize database
sqlite3 kms_platform.db "VACUUM;"
sqlite3 kms_platform.db "ANALYZE;"

# Check for slow queries
# Monitor database access patterns
```

### **Network Performance**
```bash
# Check bandwidth usage
iftop
nethogs

# Optimize AWS API calls
# Implement caching
# Batch requests where possible
```

---

## 🔐 **Security Issues**

### **Authentication Problems**
```bash
# Check JWT token
# F12 -> Application tab -> Local Storage

# Clear authentication data
# Clear browser storage

# Test login endpoint
curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

### **Rate Limiting**
```bash
# Check rate limit headers
curl -I http://localhost:5000/api/keys

# Monitor rate limiting
# Check application logs

# Adjust rate limits if needed
# Modify configuration
```

### **CORS Issues**
```bash
# Check CORS headers
curl -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: GET" \
  -H "Access-Control-Request-Headers: X-Requested-With" \
  -X OPTIONS http://localhost:5000/api/keys
```

---

## 🐳 **Docker Issues**

### **Container Won't Start**
```bash
# Check container logs
docker logs kms-web-ui

# Check container status
docker ps -a

# Remove and recreate container
docker rm -f kms-web-ui
docker run -d --name kms-web-ui -p 5000:5000 aws-kms-web-ui
```

### **Image Build Issues**
```bash
# Check Dockerfile
cat Dockerfile

# Build with verbose output
docker build --no-cache -t aws-kms-web-ui .

# Check for build context issues
# Ensure all files are in build context
```

### **Volume Mount Issues**
```bash
# Check volume mounts
docker inspect kms-web-ui | grep -A 10 "Mounts"

# Test volume access
docker exec kms-web-ui ls -la /app/data

# Fix permissions
chmod 755 data/
chown 1000:1000 data/
```

---

## ☸️ **Kubernetes Issues**

### **Pod Not Starting**
```bash
# Check pod status
kubectl get pods -n kms-web-ui

# Check pod logs
kubectl logs -f deployment/kms-web-ui -n kms-web-ui

# Check pod events
kubectl describe pod kms-web-ui-xxx -n kms-web-ui
```

### **Service Not Accessible**
```bash
# Check service status
kubectl get svc -n kms-web-ui

# Test service connectivity
kubectl port-forward svc/kms-web-ui-service 5000:80 -n kms-web-ui

# Check ingress
kubectl get ingress -n kms-web-ui
```

### **ConfigMap/Secret Issues**
```bash
# Check ConfigMap
kubectl get configmap kms-web-ui-config -n kms-web-ui -o yaml

# Check Secret
kubectl get secret kms-web-ui-secret -n kms-web-ui -o yaml

# Update configuration
kubectl apply -f k8s/configmap.yaml
```

---

## 🔄 **Backup & Recovery Issues**

### **Backup Failed**
```bash
# Check backup script permissions
chmod +x backup.sh

# Check disk space
df -h

# Test backup manually
sqlite3 kms_platform.db ".backup backup/test.db"
```

### **Restore Failed**
```bash
# Check backup file integrity
sqlite3 backup/latest.db "PRAGMA integrity_check;"

# Test restore to temporary location
sqlite3 backup/latest.db ".backup restore_test.db"

# Verify backup file
ls -la backup/
```

---

## 📝 **Logging Issues**

### **No Logs Generated**
```bash
# Check log directory
ls -la logs/

# Check log permissions
chmod 755 logs/
chown your-user:your-group logs/

# Enable debug logging
export FLASK_DEBUG=1
export LOG_LEVEL=DEBUG
```

### **Log Rotation Issues**
```bash
# Check logrotate configuration
cat /etc/logrotate.d/kms-web-ui

# Manual log rotation
logrotate -f /etc/logrotate.d/kms-web-ui

# Check disk space
df -h /var/log
```

---

## 🔧 **Configuration Issues**

### **Environment Variables**
```bash
# Check all environment variables
env | sort

# Validate configuration
python -c "import os; print('SECRET_KEY:', bool(os.getenv('SECRET_KEY')))"

# Test configuration loading
python -c "from app import app; print('App loaded successfully')"
```

### **Feature Flags**
```bash
# Check feature flags
echo $ENABLE_AI_FEATURES
echo $ENABLE_SECURITY_MONITORING

# Enable/disable features
export ENABLE_AI_FEATURES=true
export ENABLE_SECURITY_MONITORING=true
```

---

## 🚨 **Emergency Procedures**

### **Application Crash**
```bash
# Stop application
docker stop kms-web-ui
systemctl stop kms-web-ui

# Check system resources
htop
df -h
free -h

# Restart application
docker start kms-web-ui
systemctl start kms-web-ui
```

### **Data Loss**
```bash
# Stop application immediately
systemctl stop kms-web-ui

# Check for recent backups
ls -la backup/

# Restore from backup
cp backup/latest.db kms_platform.db

# Verify data integrity
sqlite3 kms_platform.db "PRAGMA integrity_check;"
```

### **Security Breach**
```bash
# Stop application
systemctl stop kms-web-ui

# Change all passwords
# Update AWS credentials
# Review access logs

# Contact security team
# security@yourcompany.com
```

---

## 📞 **Getting Help**

### **Self-Service Resources**
- **[Documentation](README.md)** - Complete project documentation
- **[API Reference](api.md)** - API documentation
- **[Security Guide](security.md)** - Security best practices
- **[Deployment Guide](deployment.md)** - Deployment instructions

### **Community Support**
- **[GitHub Issues](https://github.com/yourusername/aws-kms-web-ui/issues)** - Report bugs
- **[GitHub Discussions](https://github.com/yourusername/aws-kms-web-ui/discussions)** - Ask questions
- **[Wiki](https://github.com/yourusername/aws-kms-web-ui/wiki)** - Community knowledge base

### **Professional Support**
- **Technical Support**: support@yourcompany.com
- **Security Issues**: security@yourcompany.com
- **Emergency**: +1-555-0123 (24/7)

### **Before Contacting Support**
1. **Check this troubleshooting guide**
2. **Search existing issues**
3. **Collect relevant information**:
   - Error messages
   - Log files
   - System information
   - Steps to reproduce
4. **Test with minimal configuration**
5. **Document your findings**

---

## 📊 **Diagnostic Commands**

### **System Information**
```bash
# OS information
uname -a
cat /etc/os-release

# Python information
python --version
pip list

# Docker information
docker --version
docker info

# Kubernetes information
kubectl version
kubectl cluster-info
```

### **Network Diagnostics**
```bash
# Network connectivity
ping google.com
curl -I https://google.com

# DNS resolution
nslookup google.com
dig google.com

# Port availability
netstat -tulpn | grep :5000
ss -tulpn | grep :5000
```

### **Application Diagnostics**
```bash
# Application status
curl http://localhost:5000/health

# API endpoints
curl http://localhost:5000/api/keys

# Database status
sqlite3 kms_platform.db "SELECT COUNT(*) FROM users;"

# Log analysis
tail -f logs/app.log | grep ERROR
```

---

**This troubleshooting guide is continuously updated. For the latest information, always refer to the current version in the repository.** 