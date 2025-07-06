# 🤝 Contributing to AWS KMS Web UI

Thank you for your interest in contributing to the AWS KMS Web UI! This guide will help you get started with contributing to our project.

## 🌟 **Project Overview**

The AWS KMS Web UI is the most advanced KMS management platform available, featuring:
- **Enterprise-grade security** with AI-powered monitoring
- **Futuristic UI** with glassmorphism design and advanced animations
- **Multi-region management** and intelligent automation
- **Real-time analytics** and predictive insights
- **Comprehensive API** with Postman-like testing interface

## 📋 **Table of Contents**

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Code Style & Standards](#code-style--standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Feature Development](#feature-development)
- [Bug Reports](#bug-reports)
- [Documentation](#documentation)
- [Community Guidelines](#community-guidelines)
- [Release Process](#release-process)

---

## 🚀 **Getting Started**

### **Prerequisites**
- Python 3.8 or higher
- Git
- AWS CLI (for testing)
- Modern web browser
- Docker (optional)

### **Quick Start**
```bash
# Fork and clone the repository
git clone https://github.com/yourusername/aws-kms-web-ui.git
cd aws-kms-web-ui

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Set up pre-commit hooks
pre-commit install

# Run the application
python app.py
```

### **First Contribution**
1. **Pick an issue** from the [Good First Issues](https://github.com/yourusername/aws-kms-web-ui/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) label
2. **Comment on the issue** to let us know you're working on it
3. **Create a branch** for your work
4. **Make your changes** following our coding standards
5. **Test your changes** thoroughly
6. **Submit a pull request**

---

## 🛠️ **Development Setup**

### **Environment Configuration**
```bash
# Create development environment file
cat > .env.development << EOF
FLASK_ENV=development
FLASK_DEBUG=true
SECRET_KEY=dev-secret-key-change-in-production
DATABASE_URL=sqlite:///kms_platform_dev.db
AWS_DEFAULT_REGION=us-east-1
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=tinyllama
ENABLE_AI_FEATURES=true
ENABLE_SECURITY_MONITORING=true
ENABLE_RATE_LIMITING=false
LOG_LEVEL=DEBUG
EOF
```

### **AI Development Setup**
```bash
# Install Ollama for AI features
curl -fsSL https://ollama.ai/install.sh | sh

# Pull development model
ollama pull tinyllama

# Start Ollama service
ollama serve
```

### **Database Setup**
```bash
# Initialize development database
python -c "from app import init_db; init_db()"

# Create test data
python scripts/create_test_data.py
```

### **Development Tools**
```bash
# Install development tools
pip install -r requirements-dev.txt

# Set up pre-commit hooks
pre-commit install

# Install additional tools
npm install -g prettier
npm install -g markdownlint-cli
```

---

## 📝 **Code Style & Standards**

### **Python Code Style**
We follow **PEP 8** with some modifications:

```python
# Good example
def create_kms_key(description: str, key_usage: str = "ENCRYPT_DECRYPT") -> dict:
    """Create a new KMS key with the specified parameters.
    
    Args:
        description: Human-readable description of the key
        key_usage: Key usage (ENCRYPT_DECRYPT or SIGN_VERIFY)
        
    Returns:
        Dictionary containing key information
        
    Raises:
        ValueError: If key_usage is invalid
        AWSException: If AWS API call fails
    """
    if key_usage not in ["ENCRYPT_DECRYPT", "SIGN_VERIFY"]:
        raise ValueError("Invalid key_usage")
    
    try:
        response = kms_client.create_key(
            Description=description,
            KeyUsage=key_usage
        )
        return {
            "key_id": response["KeyMetadata"]["KeyId"],
            "key_arn": response["KeyMetadata"]["Arn"],
            "status": "success"
        }
    except Exception as e:
        logger.error(f"Failed to create KMS key: {e}")
        raise
```

### **JavaScript Code Style**
We follow **ESLint** and **Prettier** standards:

```javascript
// Good example
const createKey = async (keyData) => {
  try {
    const response = await fetch('/api/create-key', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${getToken()}`
      },
      body: JSON.stringify(keyData)
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const result = await response.json();
    return result;
  } catch (error) {
    console.error('Failed to create key:', error);
    throw error;
  }
};
```

### **CSS/SASS Standards**
We follow **BEM** methodology and use **SCSS**:

```scss
// Good example
.kms-card {
  background: rgba(255, 255, 255, 0.1);
  backdrop-filter: blur(10px);
  border: 1px solid rgba(255, 255, 255, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
  transition: all 0.3s ease;
  
  &:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
  }
  
  &__header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 1rem;
  }
  
  &__title {
    font-size: 1.25rem;
    font-weight: 600;
    color: var(--text-primary);
  }
  
  &__content {
    color: var(--text-secondary);
    line-height: 1.6;
  }
}
```

### **File Naming Conventions**
- **Python files**: `snake_case.py`
- **JavaScript files**: `camelCase.js` or `kebab-case.js`
- **CSS files**: `kebab-case.css`
- **Test files**: `test_snake_case.py` or `camelCase.test.js`

### **Import Organization**
```python
# Standard library imports
import os
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional

# Third-party imports
import boto3
import flask
from flask import jsonify, request
from flask_jwt_extended import jwt_required

# Local imports
from app.models import User, Key
from app.utils import validate_input, log_activity
```

---

## 🧪 **Testing**

### **Python Testing**
We use **pytest** for testing:

```python
# test_kms_operations.py
import pytest
from unittest.mock import Mock, patch
from app.kms_operations import create_kms_key, list_keys

class TestKMSOperations:
    @patch('app.kms_operations.kms_client')
    def test_create_kms_key_success(self, mock_kms_client):
        # Arrange
        mock_response = {
            "KeyMetadata": {
                "KeyId": "test-key-123",
                "Arn": "arn:aws:kms:us-east-1:123456789012:key/test-key-123"
            }
        }
        mock_kms_client.create_key.return_value = mock_response
        
        # Act
        result = create_kms_key("Test Key", "ENCRYPT_DECRYPT")
        
        # Assert
        assert result["key_id"] == "test-key-123"
        assert result["status"] == "success"
        mock_kms_client.create_key.assert_called_once()
    
    def test_create_kms_key_invalid_usage(self):
        # Act & Assert
        with pytest.raises(ValueError, match="Invalid key_usage"):
            create_kms_key("Test Key", "INVALID_USAGE")
```

### **JavaScript Testing**
We use **Jest** for testing:

```javascript
// kmsOperations.test.js
import { createKey, listKeys } from '../src/kmsOperations';

// Mock fetch
global.fetch = jest.fn();

describe('KMS Operations', () => {
  beforeEach(() => {
    fetch.mockClear();
  });

  test('createKey should return key data on success', async () => {
    // Arrange
    const mockResponse = {
      key_id: 'test-key-123',
      key_arn: 'arn:aws:kms:us-east-1:123456789012:key/test-key-123',
      status: 'success'
    };
    
    fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse
    });

    // Act
    const result = await createKey({
      description: 'Test Key',
      keyUsage: 'ENCRYPT_DECRYPT'
    });

    // Assert
    expect(result).toEqual(mockResponse);
    expect(fetch).toHaveBeenCalledWith('/api/create-key', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer test-token'
      },
      body: JSON.stringify({
        description: 'Test Key',
        keyUsage: 'ENCRYPT_DECRYPT'
      })
    });
  });
});
```

### **Running Tests**
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test file
pytest tests/test_kms_operations.py

# Run tests in parallel
pytest -n auto

# Run JavaScript tests
npm test

# Run tests in watch mode
npm run test:watch
```

### **Test Coverage Requirements**
- **Minimum coverage**: 80%
- **Critical paths**: 95%
- **New features**: 90%

---

## 🔄 **Pull Request Process**

### **Before Submitting**
1. **Update documentation** for any new features
2. **Add tests** for new functionality
3. **Run all tests** and ensure they pass
4. **Check code style** with linting tools
5. **Update CHANGELOG.md** with your changes

### **Pull Request Template**
```markdown
## 📝 Description
Brief description of changes made in this pull request.

## 🎯 Type of Change
- [ ] 🐛 Bug fix (non-breaking change which fixes an issue)
- [ ] ✨ New feature (non-breaking change which adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] 📚 Documentation update
- [ ] 🎨 Style/UI improvements
- [ ] ⚡ Performance improvements
- [ ] 🔧 Refactoring (no functional changes)
- [ ] 🧪 Test additions or improvements

## 🔗 Related Issues
Closes #(issue number)
Related to #(issue number)

## 🧪 Testing
- [ ] ✅ Unit tests pass
- [ ] ✅ Integration tests pass
- [ ] ✅ Manual testing completed
- [ ] ✅ Cross-browser testing (if applicable)
- [ ] ✅ Performance testing (if applicable)

## 📋 Checklist
- [ ] 🔍 Self-review completed
- [ ] 📝 Code follows style guidelines
- [ ] 📚 Documentation updated
- [ ] 🧪 Tests added/updated
- [ ] 🔒 Security considerations addressed
- [ ] ⚡ Performance impact considered
- [ ] 🎨 UI/UX improvements (if applicable)

## 📸 Screenshots
If applicable, add screenshots to help explain your changes.

## 🔧 Technical Details
- **Files Changed**: List of key files modified
- **New Dependencies**: Any new dependencies added
- **Breaking Changes**: Any breaking changes and migration steps
- **Performance Impact**: Any performance implications
```

### **Review Process**
1. **Automated checks** must pass
2. **Code review** by maintainers
3. **Testing** in staging environment
4. **Documentation review**
5. **Security review** (if applicable)

---

## 🚀 **Feature Development**

### **Feature Planning**
1. **Create an issue** describing the feature
2. **Discuss requirements** with maintainers
3. **Design the solution** with mockups if needed
4. **Break down into tasks** with clear acceptance criteria
5. **Estimate effort** and timeline

### **Development Workflow**
```bash
# Create feature branch
git checkout -b feature/ai-security-analysis

# Make changes
# ... implement feature ...

# Commit with conventional commits
git commit -m "feat: add AI-powered security analysis

- Implement security posture assessment
- Add risk scoring algorithm
- Integrate with existing monitoring
- Add comprehensive test coverage

Closes #123"

# Push and create PR
git push origin feature/ai-security-analysis
```

### **Feature Categories**
- **🔒 Security Features**: Authentication, authorization, encryption
- **🤖 AI Features**: Machine learning, automation, insights
- **📊 Analytics**: Dashboards, metrics, reporting
- **🎨 UI/UX**: Interface improvements, animations, accessibility
- **⚡ Performance**: Optimization, caching, scaling
- **🔧 Infrastructure**: Deployment, monitoring, DevOps

---

## 🐛 **Bug Reports**

### **Bug Report Template**
```markdown
## 🐛 Bug Description
A clear and concise description of what the bug is.

## 🔄 Steps to Reproduce
1. Go to '...'
2. Click on '...'
3. Scroll down to '...'
4. See error

## ✅ Expected Behavior
A clear and concise description of what you expected to happen.

## ❌ Actual Behavior
A clear and concise description of what actually happened.

## 📸 Screenshots
If applicable, add screenshots to help explain your problem.

## 🖥️ Environment
- **OS**: [e.g. Windows 10, macOS, Ubuntu]
- **Python Version**: [e.g. 3.8.5]
- **AWS KMS Platform Version**: [e.g. 1.0.0]
- **Browser**: [e.g. Chrome, Firefox] (if applicable)
- **AWS Region**: [e.g. us-east-1]

## 📋 Additional Context
Add any other context about the problem here, including:
- Error logs
- AWS configuration
- Network environment
- Related issues
```

### **Bug Triage Process**
1. **Reproduce the bug** locally
2. **Identify root cause** and affected components
3. **Assess severity** and impact
4. **Assign priority** and assignee
5. **Create fix** with tests
6. **Verify resolution** in multiple environments

---

## 📚 **Documentation**

### **Documentation Standards**
- **Clear and concise** writing
- **Code examples** for all features
- **Screenshots** for UI features
- **Step-by-step** instructions
- **Troubleshooting** sections

### **Documentation Types**
- **User Documentation**: How to use the platform
- **API Documentation**: Complete API reference
- **Developer Documentation**: How to contribute
- **Deployment Documentation**: How to deploy
- **Security Documentation**: Security best practices

### **Documentation Tools**
```bash
# Generate API documentation
python scripts/generate_api_docs.py

# Build documentation site
mkdocs build

# Serve documentation locally
mkdocs serve

# Check documentation links
python scripts/check_docs.py
```

---

## 🤝 **Community Guidelines**

### **Code of Conduct**
We are committed to providing a welcoming and inspiring community for all. Please read our [Code of Conduct](CODE_OF_CONDUCT.md) for details.

### **Communication Channels**
- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and general discussion
- **Discord**: Real-time chat and collaboration
- **Email**: Private or sensitive matters

### **Community Roles**
- **Contributors**: Anyone who contributes code or documentation
- **Reviewers**: Community members who review pull requests
- **Maintainers**: Project maintainers with merge permissions
- **Admins**: Repository administrators

### **Recognition**
- **Contributors list**: All contributors are listed in CONTRIBUTORS.md
- **Hall of Fame**: Special recognition for significant contributions
- **Badges**: GitHub badges for different contribution types
- **Swag**: Physical items for major contributors

---

## 🚀 **Release Process**

### **Release Types**
- **Patch releases**: Bug fixes and minor improvements
- **Minor releases**: New features (backward compatible)
- **Major releases**: Breaking changes and major features

### **Release Checklist**
```bash
# Pre-release
- [ ] All tests passing
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version bumped
- [ ] Security scan completed
- [ ] Performance tests passed

# Release
- [ ] Create release branch
- [ ] Tag release
- [ ] Build artifacts
- [ ] Deploy to staging
- [ ] Run integration tests
- [ ] Deploy to production
- [ ] Announce release

# Post-release
- [ ] Monitor for issues
- [ ] Update documentation
- [ ] Archive release branch
- [ ] Plan next release
```

### **Version Management**
```bash
# Bump version
python scripts/bump_version.py --type patch
python scripts/bump_version.py --type minor
python scripts/bump_version.py --type major

# Create release
git tag -a v1.2.3 -m "Release version 1.2.3"
git push origin v1.2.3
```

---

## 🎯 **Areas for Contribution**

### **High Priority**
- **Security improvements**: Vulnerability fixes, security audits
- **Performance optimization**: Speed improvements, memory usage
- **Accessibility**: WCAG compliance, screen reader support
- **Testing**: Test coverage, integration tests
- **Documentation**: API docs, user guides, tutorials

### **Medium Priority**
- **UI/UX improvements**: Design enhancements, animations
- **New features**: Additional KMS operations, analytics
- **Integration**: Third-party service integrations
- **Monitoring**: Enhanced logging, metrics
- **Deployment**: Containerization, CI/CD improvements

### **Low Priority**
- **Code refactoring**: Code cleanup, architecture improvements
- **Tooling**: Development tools, automation scripts
- **Examples**: Sample applications, tutorials
- **Translations**: Internationalization support
- **Themes**: Dark mode, custom themes

---

## 📞 **Getting Help**

### **Resources**
- **[Documentation](docs/)** - Complete project documentation
- **[Issues](https://github.com/yourusername/aws-kms-web-ui/issues)** - Search existing issues
- **[Discussions](https://github.com/yourusername/aws-kms-web-ui/discussions)** - Ask questions
- **[Wiki](https://github.com/yourusername/aws-kms-web-ui/wiki)** - Community knowledge base

### **Contact**
- **General questions**: Open a GitHub Discussion
- **Bug reports**: Create a GitHub Issue
- **Security issues**: Email security@yourcompany.com
- **Feature requests**: Create a GitHub Issue with feature label

---

## 🙏 **Acknowledgments**

Thank you to all contributors who have helped make the AWS KMS Web UI the most advanced KMS management platform available. Your contributions are valued and appreciated!

### **Contributor Hall of Fame**
- **Gold Contributors**: 100+ contributions
- **Silver Contributors**: 50+ contributions  
- **Bronze Contributors**: 10+ contributions

---

**Happy contributing! 🚀** 