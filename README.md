# 🔐 AWS KMS Platform - Enterprise Key Management Solution

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.1+-green.svg)](https://flask.palletsprojects.com)
[![AWS KMS](https://img.shields.io/badge/AWS-KMS-orange.svg)](https://aws.amazon.com/kms/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI/CD](https://img.shields.io/badge/CI/CD-GitHub%20Actions-blue.svg)](.github/workflows/ci.yml)

> **Enterprise-grade AWS Key Management Service (KMS) platform with AI-powered insights, real-time monitoring, and comprehensive security features.**

## 🌟 Features

### 🔑 **Core KMS Management**
- **Key Lifecycle Management** - Create, enable, disable, and delete KMS keys
- **Envelope Encryption** - Advanced encryption with data key generation
- **Key Rotation** - Automated and manual key rotation capabilities
- **Multi-Region Support** - Manage keys across AWS regions
- **Policy Management** - Granular IAM policies for key access

### 🤖 **AI-Powered Features**
- **AI Assistant** - Natural language queries about KMS operations
- **Predictive Analytics** - Usage forecasting and cost optimization
- **Security Insights** - AI-driven security posture analysis
- **Smart Recommendations** - Automated best practice suggestions

### 📊 **Advanced Analytics & Monitoring**
- **Real-time Dashboard** - Live metrics and performance indicators
- **Usage Analytics** - Comprehensive usage patterns and trends
- **Cost Optimization** - Detailed cost analysis and recommendations
- **Performance Metrics** - Latency, throughput, and error tracking
- **3D Visualizations** - Interactive charts and graphs

### 🔒 **Security & Compliance**
- **Multi-Factor Authentication (MFA)** - Enhanced security for admin users
- **Session Management** - Secure session handling and tracking
- **Audit Logging** - Comprehensive activity logging and export
- **Compliance Reporting** - Regulatory compliance documentation
- **Security Headers** - Modern security headers and best practices

### ⚡ **Automation & Integration**
- **Automated Key Rotation** - Scheduled and event-driven rotation
- **Backup & Recovery** - Automated key backup and restoration
- **Cross-Region Replication** - Automated key replication
- **Email & Slack Alerts** - Real-time notifications
- **Elasticsearch Integration** - Advanced logging and search

## 🚀 Quick Start

### Prerequisites
- **Python 3.8+** with pip
- **AWS CLI** configured with KMS permissions
- **Modern web browser** (Chrome, Firefox, Safari, Edge)
- **4GB RAM** minimum (8GB recommended for AI features)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/aws-kms-platform.git
cd aws-kms-platform

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
# Edit .env with your AWS credentials and settings

# Initialize the database
python -c "from app import init_db; init_db()"

# Start the application
python app.py
```

### Access the Platform
- **URL**: http://localhost:5000
- **Default Admin**: `admin` / `admin123`
- **Default User**: `user` / `user123`

## 🏗️ Architecture

### System Components
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web UI        │    │   Flask API     │    │   AWS KMS       │
│   (React/HTML)  │◄──►│   (Python)      │◄──►│   (AWS)         │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │              ┌─────────────────┐              │
         └──────────────►│   AI Assistant  │◄─────────────┘
                        │   (Ollama)      │
                        └─────────────────┘
```

### Key Technologies
- **Backend**: Flask (Python) with RESTful API
- **Frontend**: Modern HTML/CSS/JavaScript with glassmorphism design
- **Database**: SQLite with SQLAlchemy ORM
- **AI Integration**: Ollama for local AI processing
- **Security**: JWT tokens, MFA, secure headers
- **Monitoring**: CloudWatch integration with custom metrics
- **Infrastructure**: Terraform for AWS resource management

## 📁 Project Structure

```
AWS_KMS_PROJECT_V1/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── templates/
│   └── index.html        # Main web interface
├── scripts/
│   ├── envelope_encryption.py  # KMS encryption utilities
│   ├── monitoring.py           # Monitoring and alerting
│   └── create_kms_key.py      # Key creation utilities
├── terraform/            # Infrastructure as Code
│   ├── kms.tf           # KMS key configuration
│   ├── variables.tf     # Terraform variables
│   └── outputs.tf       # Output values
├── config/              # Configuration files
│   ├── dev/            # Development policies
│   └── prod/           # Production policies
├── docs/               # Documentation
├── tests/              # Test suite
└── docker-compose.yml  # Container orchestration
```

## 🔧 Configuration

### Environment Variables
```bash
# AWS Configuration
AWS_DEFAULT_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key

# Application Configuration
FLASK_ENV=development
SECRET_KEY=your_secret_key
DATABASE_URL=sqlite:///kms_platform.db

# AI Configuration
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=tinyllama

# Email Configuration (Optional)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email
SMTP_PASSWORD=your_password

# Slack Configuration (Optional)
SLACK_WEBHOOK_URL=your_webhook_url
```

### AWS Permissions Required
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "kms:*",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "cloudwatch:GetMetricStatistics",
                "logs:CreateLogGroup",
                "logs:PutLogEvents"
            ],
            "Resource": "*"
        }
    ]
}
```

## 🎯 Usage Examples

### Key Management
```python
# Create a new KMS key
POST /api/create-key
{
    "description": "Production encryption key",
    "key_usage": "ENCRYPT_DECRYPT",
    "customer_master_key_spec": "SYMMETRIC_DEFAULT"
}

# List all keys
GET /api/keys

# Enable key rotation
POST /api/enable-rotation
{
    "key_id": "arn:aws:kms:us-east-1:123456789012:key/abcd1234-..."
}
```

### Encryption Operations
```python
# Encrypt data
POST /api/encrypt
{
    "key_id": "alias/my-app-key",
    "plaintext": "sensitive-data",
    "encryption_context": {
        "environment": "production",
        "service": "user-data"
    }
}

# Decrypt data
POST /api/decrypt
{
    "ciphertext": "base64-encoded-ciphertext",
    "encryption_context": {
        "environment": "production",
        "service": "user-data"
    }
}
```

### AI Assistant
```python
# Query AI assistant
POST /api/ai/query
{
    "query": "How can I optimize my KMS key usage for cost efficiency?",
    "context": "production environment with high volume"
}
```

## 🧪 Testing

```bash
# Run unit tests
pytest tests/

# Run with coverage
pytest --cov=app tests/

# Run specific test file
pytest tests/test_encryption.py
```

## 🐳 Docker Deployment

```bash
# Build and run with Docker Compose
docker-compose up --build

# Or build manually
docker build -t aws-kms-platform .
docker run -p 5000:5000 aws-kms-platform
```

## 🚀 Production Deployment

### Using Terraform
```bash
cd terraform
terraform init
terraform plan
terraform apply
```

### Environment-Specific Configuration
- **Development**: Uses development KMS policies
- **Production**: Enhanced security policies with monitoring
- **Staging**: Mirrors production with reduced permissions

## 📊 Monitoring & Analytics

### Key Metrics Tracked
- **Request Count**: Number of KMS operations
- **Error Rate**: Failed operations percentage
- **Latency**: Average and maximum response times
- **Cost Analysis**: Usage-based cost optimization
- **Security Events**: Failed authentication attempts

### Alerting
- **CloudWatch Alarms**: Automated AWS monitoring
- **Email Notifications**: Critical security events
- **Slack Integration**: Real-time team notifications
- **Custom Dashboards**: Visual monitoring interface

## 🔒 Security Features

### Authentication & Authorization
- **JWT Token Management**: Secure session handling
- **Role-Based Access Control**: Admin and user roles
- **Multi-Factor Authentication**: Enhanced admin security
- **Session Tracking**: Comprehensive session management

### Data Protection
- **Envelope Encryption**: Industry-standard encryption
- **Secure Headers**: Modern security headers
- **Input Validation**: Comprehensive input sanitization
- **Audit Logging**: Complete activity tracking

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Set up pre-commit hooks
pre-commit install

# Run linting
flake8 .
black .
isort .
```

## 📚 Documentation

- **[API Documentation](docs/api.md)** - Complete API reference
- **[Deployment Guide](docs/deployment.md)** - Production deployment
- **[Security Best Practices](docs/security.md)** - Security guidelines
- **[Troubleshooting](docs/troubleshooting.md)** - Common issues and solutions

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **AWS KMS Team** for the robust key management service
- **Flask Community** for the excellent web framework
- **Ollama Team** for local AI processing capabilities
- **Open Source Contributors** for various dependencies

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/aws-kms-platform/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/aws-kms-platform/discussions)
- **Documentation**: [Project Wiki](https://github.com/yourusername/aws-kms-platform/wiki)

---

**Built with ❤️ for the AWS community** 
