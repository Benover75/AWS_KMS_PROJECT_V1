# 🔌 API Documentation

Complete API reference for the AWS KMS Web UI platform.

## 📋 **API Overview**

The AWS KMS Web UI provides a comprehensive REST API for managing AWS KMS keys, encryption operations, analytics, and automation. All endpoints return JSON responses and use standard HTTP status codes.

### **Base URL**
```
http://localhost:5000/api
```

### **Authentication**
Most endpoints require authentication via JWT tokens. Include the token in the Authorization header:
```
Authorization: Bearer <your_jwt_token>
```

### **Rate Limiting**
- **Default**: 100 requests per minute per IP
- **Authentication endpoints**: 10 requests per minute per IP
- **AI endpoints**: 20 requests per minute per user

---

## 🔐 **Authentication Endpoints**

### **POST /login**
Authenticate a user and receive a JWT token.

**Request Body:**
```json
{
    "username": "admin",
    "password": "admin123"
}
```

**Response:**
```json
{
    "success": true,
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "user": {
        "id": 1,
        "username": "admin",
        "role": "admin"
    }
}
```

### **POST /register**
Register a new user account.

**Request Body:**
```json
{
    "username": "newuser",
    "password": "password123",
    "email": "user@example.com"
}
```

**Response:**
```json
{
    "success": true,
    "message": "User registered successfully"
}
```

### **GET /whoami**
Get current user information.

**Response:**
```json
{
    "user": {
        "id": 1,
        "username": "admin",
        "role": "admin"
    }
}
```

---

## 🔑 **Key Management Endpoints**

### **GET /keys**
List all KMS keys in the current region.

**Query Parameters:**
- `limit` (optional): Number of keys to return (default: 50)
- `marker` (optional): Pagination token
- `state` (optional): Filter by key state (Enabled, Disabled, PendingDeletion)

**Response:**
```json
{
    "keys": [
        {
            "keyId": "arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ef-ghij-klmnopqrstuv",
            "keyArn": "arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ef-ghij-klmnopqrstuv",
            "keyState": "Enabled",
            "keyUsage": "ENCRYPT_DECRYPT",
            "keySpec": "SYMMETRIC_DEFAULT",
            "creationDate": "2024-01-15T10:30:00Z",
            "description": "My encryption key",
            "aliases": ["alias/my-key"]
        }
    ],
    "nextMarker": "string"
}
```

### **POST /create-key**
Create a new KMS key.

**Request Body:**
```json
{
    "description": "My new encryption key",
    "keyUsage": "ENCRYPT_DECRYPT",
    "keySpec": "SYMMETRIC_DEFAULT",
    "origin": "AWS_KMS",
    "tags": [
        {
            "TagKey": "Environment",
            "TagValue": "Production"
        }
    ],
    "policy": "string",
    "bypassPolicyLockoutSafetyCheck": false,
    "applicationName": "MyApp",
    "environment": "production",
    "keyPurpose": "data-encryption",
    "autoRotate": true
}
```

**Response:**
```json
{
    "success": true,
    "keyId": "arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ef-ghij-klmnopqrstuv",
    "keyArn": "arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ef-ghij-klmnopqrstuv"
}
```

### **POST /delete-key**
Schedule a key for deletion.

**Request Body:**
```json
{
    "keyId": "arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ef-ghij-klmnopqrstuv",
    "pendingWindowInDays": 7
}
```

**Response:**
```json
{
    "success": true,
    "deletionDate": "2024-01-22T10:30:00Z"
}
```

### **POST /enable-key**
Enable a disabled key.

**Request Body:**
```json
{
    "keyId": "arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ef-ghij-klmnopqrstuv"
}
```

### **POST /disable-key**
Disable a key.

**Request Body:**
```json
{
    "keyId": "arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ef-ghij-klmnopqrstuv"
}
```

---

## 🔒 **Encryption Endpoints**

### **POST /encrypt**
Encrypt data using a KMS key.

**Request Body:**
```json
{
    "keyId": "arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ef-ghij-klmnopqrstuv",
    "plaintext": "Hello, World!",
    "encryptionContext": {
        "Environment": "Production",
        "Application": "MyApp"
    }
}
```

**Response:**
```json
{
    "ciphertext": "AQICAHj...",
    "keyId": "arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ef-ghij-klmnopqrstuv",
    "encryptionAlgorithm": "SYMMETRIC_DEFAULT"
}
```

### **POST /decrypt**
Decrypt data using a KMS key.

**Request Body:**
```json
{
    "ciphertext": "AQICAHj...",
    "encryptionContext": {
        "Environment": "Production",
        "Application": "MyApp"
    }
}
```

**Response:**
```json
{
    "plaintext": "Hello, World!",
    "keyId": "arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ef-ghij-klmnopqrstuv",
    "encryptionAlgorithm": "SYMMETRIC_DEFAULT"
}
```

### **POST /generate-data-key**
Generate a data key for envelope encryption.

**Request Body:**
```json
{
    "keyId": "arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ef-ghij-klmnopqrstuv",
    "keySpec": "AES_256",
    "numberOfBytes": 32,
    "encryptionContext": {
        "Environment": "Production"
    }
}
```

**Response:**
```json
{
    "plaintext": "base64-encoded-plaintext-key",
    "ciphertextBlob": "AQICAHj...",
    "keyId": "arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ef-ghij-klmnopqrstuv"
}
```

---

## 📊 **Analytics Endpoints**

### **GET /key-stats**
Get key statistics and metrics.

**Response:**
```json
{
    "totalKeys": 25,
    "enabledKeys": 20,
    "disabledKeys": 3,
    "pendingDeletion": 2,
    "keyUsage": {
        "ENCRYPT_DECRYPT": 18,
        "SIGN_VERIFY": 7
    },
    "keySpecs": {
        "SYMMETRIC_DEFAULT": 20,
        "RSA_2048": 3,
        "RSA_3072": 2
    },
    "recentActivity": [
        {
            "timestamp": "2024-01-15T10:30:00Z",
            "action": "CreateKey",
            "keyId": "key-123",
            "user": "admin"
        }
    ]
}
```

### **GET /key-usage-details**
Get detailed key usage analytics.

**Response:**
```json
{
    "usageByRegion": {
        "us-east-1": 15,
        "us-west-2": 8,
        "eu-west-1": 2
    },
    "usageByPurpose": {
        "data-encryption": 12,
        "api-encryption": 8,
        "database-encryption": 5
    },
    "performanceMetrics": {
        "averageResponseTime": 45,
        "totalRequests": 1250,
        "errorRate": 0.02
    }
}
```

### **GET /key-rotation-reminders**
Get keys that need rotation.

**Response:**
```json
{
    "keysNeedingRotation": [
        {
            "keyId": "key-123",
            "lastRotated": "2023-07-15T10:30:00Z",
            "daysSinceRotation": 180,
            "recommendedRotation": true
        }
    ],
    "overdueKeys": [
        {
            "keyId": "key-456",
            "lastRotated": "2023-01-15T10:30:00Z",
            "daysSinceRotation": 365,
            "critical": true
        }
    ]
}
```

### **GET /recent-key-activity**
Get recent key activity.

**Query Parameters:**
- `limit` (optional): Number of activities to return (default: 20)

**Response:**
```json
{
    "activities": [
        {
            "timestamp": "2024-01-15T10:30:00Z",
            "action": "CreateKey",
            "keyId": "key-123",
            "user": "admin",
            "region": "us-east-1",
            "details": "Created new encryption key"
        }
    ]
}
```

---

## 🤖 **AI Assistant Endpoints**

### **GET /ai/status**
Check AI service status.

**Response:**
```json
{
    "status": "available",
    "model": "tinyllama",
    "version": "1.0.0",
    "responseTime": 150
}
```

### **POST /ai/query**
Send a natural language query to the AI assistant.

**Request Body:**
```json
{
    "query": "How do I rotate my encryption keys?",
    "context": {
        "currentKeys": 5,
        "region": "us-east-1"
    }
}
```

**Response:**
```json
{
    "response": "To rotate your encryption keys, you can use the automatic rotation feature...",
    "suggestions": [
        "Enable automatic rotation for key-123",
        "Schedule manual rotation for key-456"
    ],
    "confidence": 0.95
}
```

### **POST /ai/analyze-security**
Analyze security posture using AI.

**Request Body:**
```json
{
    "keyIds": ["key-123", "key-456"],
    "analysisType": "comprehensive"
}
```

**Response:**
```json
{
    "securityScore": 85,
    "recommendations": [
        "Enable automatic key rotation for 3 keys",
        "Review access policies for key-123",
        "Consider enabling CloudTrail logging"
    ],
    "risks": [
        {
            "level": "medium",
            "description": "Key key-456 hasn't been rotated in 300 days",
            "mitigation": "Enable automatic rotation"
        }
    ]
}
```

---

## ⚡ **Automation Endpoints**

### **POST /automation/rules**
Save automation rules.

**Request Body:**
```json
{
    "ruleName": "Auto-rotate-old-keys",
    "conditions": {
        "keyAge": 365,
        "keyState": "Enabled"
    },
    "actions": [
        {
            "type": "rotate_key",
            "parameters": {
                "automatic": true
            }
        }
    ],
    "enabled": true
}
```

**Response:**
```json
{
    "success": true,
    "ruleId": "rule-123",
    "message": "Automation rule saved successfully"
}
```

### **POST /automation/trigger**
Trigger automation rules.

**Request Body:**
```json
{
    "ruleId": "rule-123",
    "parameters": {
        "keyId": "key-123"
    }
}
```

### **GET /automation/rules**
List all automation rules.

**Response:**
```json
{
    "rules": [
        {
            "ruleId": "rule-123",
            "ruleName": "Auto-rotate-old-keys",
            "enabled": true,
            "lastTriggered": "2024-01-15T10:30:00Z",
            "triggerCount": 5
        }
    ]
}
```

---

## 🔄 **Key Rotation Endpoints**

### **POST /rotate-key**
Rotate a KMS key.

**Request Body:**
```json
{
    "keyId": "arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ef-ghij-klmnopqrstuv",
    "automatic": true
}
```

### **POST /schedule-rotation**
Schedule key rotation.

**Request Body:**
```json
{
    "keyId": "arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ef-ghij-klmnopqrstuv",
    "scheduleDate": "2024-02-15T10:30:00Z",
    "automatic": true
}
```

### **POST /enable-rotation**
Enable automatic key rotation.

**Request Body:**
```json
{
    "keyId": "arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ef-ghij-klmnopqrstuv"
}
```

---

## 🌍 **Multi-Region Endpoints**

### **POST /replicate-key**
Replicate a key to another region.

**Request Body:**
```json
{
    "sourceKeyId": "arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ef-ghij-klmnopqrstuv",
    "targetRegion": "us-west-2",
    "description": "Replicated key for disaster recovery"
}
```

### **GET /regions**
List available AWS regions.

**Response:**
```json
{
    "regions": [
        {
            "regionName": "US East (N. Virginia)",
            "region": "us-east-1",
            "keyCount": 15
        },
        {
            "regionName": "US West (Oregon)",
            "region": "us-west-2",
            "keyCount": 8
        }
    ]
}
```

---

## 💾 **Backup & Recovery Endpoints**

### **POST /backup-key**
Create a backup of a key.

**Request Body:**
```json
{
    "keyId": "arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ef-ghij-klmnopqrstuv",
    "description": "Monthly backup"
}
```

### **POST /restore-key**
Restore a key from backup.

**Request Body:**
```json
{
    "backupId": "backup-123",
    "targetRegion": "us-east-1"
}
```

---

## 📈 **Reporting Endpoints**

### **GET /usage-report**
Generate usage report.

**Query Parameters:**
- `startDate` (optional): Start date for report (ISO format)
- `endDate` (optional): End date for report (ISO format)
- `format` (optional): Report format (json, csv, pdf)

**Response:**
```json
{
    "reportId": "report-123",
    "generatedAt": "2024-01-15T10:30:00Z",
    "period": {
        "start": "2024-01-01T00:00:00Z",
        "end": "2024-01-15T23:59:59Z"
    },
    "summary": {
        "totalKeys": 25,
        "totalRequests": 1250,
        "totalCost": 45.67
    },
    "details": {
        "keysByRegion": {...},
        "keysByPurpose": {...},
        "costBreakdown": {...}
    }
}
```

### **GET /cost-optimization**
Get cost optimization recommendations.

**Response:**
```json
{
    "recommendations": [
        {
            "type": "unused_keys",
            "keys": ["key-123", "key-456"],
            "potentialSavings": 12.50,
            "action": "Delete unused keys"
        },
        {
            "type": "over_provisioned",
            "keys": ["key-789"],
            "potentialSavings": 8.25,
            "action": "Reduce key specifications"
        }
    ],
    "totalPotentialSavings": 20.75
}
```

### **GET /usage-prediction**
Get usage prediction for the next 30 days.

**Response:**
```json
{
    "prediction": {
        "estimatedRequests": 1500,
        "estimatedCost": 52.30,
        "confidence": 0.85
    },
    "trends": {
        "requestGrowth": 0.15,
        "costGrowth": 0.12
    }
}
```

---

## 🔔 **Monitoring & Alerts Endpoints**

### **GET /sessions**
Get active user sessions.

**Response:**
```json
{
    "sessions": [
        {
            "sessionId": "session-123",
            "userId": 1,
            "username": "admin",
            "loginTime": "2024-01-15T10:30:00Z",
            "lastActivity": "2024-01-15T11:45:00Z",
            "ipAddress": "192.168.1.100"
        }
    ]
}
```

### **POST /alerts/email**
Send email alert.

**Request Body:**
```json
{
    "to": "admin@example.com",
    "subject": "KMS Key Alert",
    "message": "Key key-123 has been scheduled for deletion",
    "priority": "high"
}
```

### **POST /alerts/slack**
Send Slack alert.

**Request Body:**
```json
{
    "channel": "#kms-alerts",
    "message": "KMS Key Alert: Key key-123 has been scheduled for deletion",
    "color": "warning"
}
```

---

## 🛡️ **Security Endpoints**

### **GET /security/status**
Get security status and compliance information.

**Response:**
```json
{
    "overallScore": 85,
    "compliance": {
        "gdpr": "compliant",
        "sox": "compliant",
        "hipaa": "compliant"
    },
    "securityChecks": [
        {
            "check": "Key Rotation",
            "status": "pass",
            "details": "All keys rotated within 365 days"
        },
        {
            "check": "Access Policies",
            "status": "warning",
            "details": "3 keys have overly permissive policies"
        }
    ],
    "recentThreats": [
        {
            "timestamp": "2024-01-15T10:30:00Z",
            "threat": "Unauthorized access attempt",
            "severity": "medium",
            "mitigated": true
        }
    ]
}
```

---

## 📝 **Error Responses**

All endpoints may return the following error responses:

### **400 Bad Request**
```json
{
    "error": "Invalid request parameters",
    "details": "Key ID is required"
}
```

### **401 Unauthorized**
```json
{
    "error": "Authentication required",
    "message": "Valid JWT token required"
}
```

### **403 Forbidden**
```json
{
    "error": "Insufficient permissions",
    "message": "Admin role required for this operation"
}
```

### **404 Not Found**
```json
{
    "error": "Resource not found",
    "message": "Key with ID 'key-123' not found"
}
```

### **429 Too Many Requests**
```json
{
    "error": "Rate limit exceeded",
    "message": "Too many requests, try again later",
    "retryAfter": 60
}
```

### **500 Internal Server Error**
```json
{
    "error": "Internal server error",
    "message": "An unexpected error occurred"
}
```

---

## 🔧 **Testing the API**

### **Using curl**
```bash
# Login
curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# Get keys (with token)
curl -X GET http://localhost:5000/api/keys \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

### **Using the Built-in API Tester**
The platform includes a comprehensive API testing interface at `/api-tester` that allows you to:
- Test all endpoints with a visual interface
- View request/response details
- Save and load test configurations
- Monitor API performance

---

## 📊 **API Performance**

### **Response Times**
- **Key operations**: < 200ms
- **Analytics queries**: < 500ms
- **AI queries**: < 2s
- **Bulk operations**: < 5s

### **Rate Limits**
- **Authentication**: 10 requests/minute
- **Key operations**: 100 requests/minute
- **Analytics**: 50 requests/minute
- **AI operations**: 20 requests/minute

### **Data Limits**
- **Request body**: 10MB maximum
- **Response body**: 50MB maximum
- **File uploads**: 100MB maximum

---

**This API documentation is continuously updated. For the latest information, always refer to the current version in the repository.** 