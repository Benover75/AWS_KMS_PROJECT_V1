#!/usr/bin/env python3
"""
KMS Monitoring and Alerting Script
Provides comprehensive monitoring for KMS keys and usage
"""

import boto3
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import argparse
from dataclasses import dataclass
from botocore.exceptions import ClientError
import os
from elasticsearch import Elasticsearch

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

ELASTICSEARCH_URL = os.getenv('ELASTICSEARCH_URL')
ELASTICSEARCH_API_KEY = os.getenv('ELASTICSEARCH_API_KEY')

def send_to_elasticsearch(index, doc):
    if not ELASTICSEARCH_URL or not ELASTICSEARCH_API_KEY:
        return False
    es = Elasticsearch(
        ELASTICSEARCH_URL,
        api_key=ELASTICSEARCH_API_KEY,
        verify_certs=True
    )
    # Add timestamp if not present
    if '@timestamp' not in doc:
        doc['@timestamp'] = datetime.utcnow().isoformat()
    es.index(index=index, document=doc)
    return True

@dataclass
class KMSMetrics:
    """Data class for KMS metrics"""
    key_id: str
    key_arn: str
    description: str
    key_state: str
    key_usage: str
    creation_date: datetime
    last_used_date: Optional[datetime]
    request_count: int
    error_count: int
    latency_avg: float
    latency_max: float

class KMSMonitor:
    """KMS Monitoring and Alerting Class"""
    
    def __init__(self, region: str = None):
        """Initialize monitoring clients"""
        self.region = region
        self.kms = boto3.client('kms', region_name=region)
        self.cloudwatch = boto3.client('cloudwatch', region_name=region)
        self.sns = boto3.client('sns', region_name=region)
        self.logs = boto3.client('logs', region_name=region)
    
    def get_key_metrics(self, key_id: str, hours: int = 24) -> Optional[KMSMetrics]:
        """Get comprehensive metrics for a KMS key"""
        try:
            # Get key metadata
            key_metadata = self.kms.describe_key(KeyId=key_id)['KeyMetadata']
            
            # Get CloudWatch metrics
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=hours)
            
            # Get request count
            request_response = self.cloudwatch.get_metric_statistics(
                Namespace='AWS/KMS',
                MetricName='NumberOfRequests',
                Dimensions=[{'Name': 'KeyId', 'Value': key_id}],
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,  # Hourly
                Statistics=['Sum']
            )
            
            # Get error count
            error_response = self.cloudwatch.get_metric_statistics(
                Namespace='AWS/KMS',
                MetricName='NumberOfErrors',
                Dimensions=[{'Name': 'KeyId', 'Value': key_id}],
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,
                Statistics=['Sum']
            )
            
            # Get latency metrics
            latency_response = self.cloudwatch.get_metric_statistics(
                Namespace='AWS/KMS',
                MetricName='Latency',
                Dimensions=[{'Name': 'KeyId', 'Value': key_id}],
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,
                Statistics=['Average', 'Maximum']
            )
            
            # Calculate totals
            request_count = sum(point['Sum'] for point in request_response.get('Datapoints', []))
            error_count = sum(point['Sum'] for point in error_response.get('Datapoints', []))
            
            # Calculate average latency
            latency_points = latency_response.get('Datapoints', [])
            latency_avg = sum(point['Average'] for point in latency_points) / len(latency_points) if latency_points else 0
            latency_max = max((point['Maximum'] for point in latency_points), default=0)
            
            return KMSMetrics(
                key_id=key_id,
                key_arn=key_metadata['Arn'],
                description=key_metadata.get('Description', ''),
                key_state=key_metadata['KeyState'],
                key_usage=key_metadata['KeyUsage'],
                creation_date=key_metadata['CreationDate'],
                last_used_date=key_metadata.get('LastUsedDate'),
                request_count=request_count,
                error_count=error_count,
                latency_avg=latency_avg,
                latency_max=latency_max
            )
            
        except Exception as e:
            logger.error(f"Failed to get metrics for key {key_id}: {e}")
            return None
    
    def get_all_key_metrics(self, hours: int = 24) -> List[KMSMetrics]:
        """Get metrics for all KMS keys"""
        try:
            keys = []
            paginator = self.kms.get_paginator('list_keys')
            
            for page in paginator.paginate():
                for key in page['Keys']:
                    metrics = self.get_key_metrics(key['KeyId'], hours)
                    if metrics:
                        keys.append(metrics)
            
            return keys
            
        except Exception as e:
            logger.error(f"Failed to get all key metrics: {e}")
            return []
    
    def create_cloudwatch_alarm(self, key_id: str, alarm_name: str, 
                               threshold: int = 1000, period: int = 300) -> bool:
        """Create CloudWatch alarm for KMS key"""
        try:
            self.cloudwatch.put_metric_alarm(
                AlarmName=alarm_name,
                AlarmDescription=f"KMS usage alarm for key {key_id}",
                MetricName='NumberOfRequests',
                Namespace='AWS/KMS',
                Statistic='Sum',
                Period=period,
                EvaluationPeriods=2,
                Threshold=threshold,
                ComparisonOperator='GreaterThanThreshold',
                Dimensions=[{'Name': 'KeyId', 'Value': key_id}],
                ActionsEnabled=True
            )
            
            logger.info(f"Created CloudWatch alarm: {alarm_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create alarm: {e}")
            return False
    
    def send_alert(self, topic_arn: str, subject: str, message: str) -> bool:
        """Send alert via SNS"""
        try:
            self.sns.publish(
                TopicArn=topic_arn,
                Subject=subject,
                Message=message
            )
            
            logger.info(f"Sent alert: {subject}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send alert: {e}")
            return False
    
    def log_audit_event(self, log_group: str, event: Dict) -> bool:
        """Log audit event to CloudWatch Logs"""
        try:
            # Ensure log group exists
            try:
                self.logs.create_log_group(logGroupName=log_group)
            except ClientError as e:
                if e.response['Error']['Code'] != 'ResourceAlreadyExistsException':
                    raise
            
            # Create log stream
            stream_name = f"kms-audit-{datetime.utcnow().strftime('%Y-%m-%d')}"
            try:
                self.logs.create_log_stream(
                    logGroupName=log_group,
                    logStreamName=stream_name
                )
            except ClientError as e:
                if e.response['Error']['Code'] != 'ResourceAlreadyExistsException':
                    raise
            
            # Put log event
            self.logs.put_log_events(
                logGroupName=log_group,
                logStreamName=stream_name,
                logEvents=[{
                    'timestamp': int(time.time() * 1000),
                    'message': json.dumps(event)
                }]
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
            return False
    
    def check_key_health(self, metrics: KMSMetrics) -> Dict:
        """Check health status of a KMS key"""
        health_status = {
            'key_id': metrics.key_id,
            'status': 'healthy',
            'issues': [],
            'recommendations': []
        }
        
        # Check key state
        if metrics.key_state != 'Enabled':
            health_status['status'] = 'unhealthy'
            health_status['issues'].append(f"Key is {metrics.key_state}")
            health_status['recommendations'].append("Enable the key if it should be active")
        
        # Check error rate
        if metrics.request_count > 0:
            error_rate = metrics.error_count / metrics.request_count
            if error_rate > 0.05:  # 5% error rate threshold
                health_status['status'] = 'warning'
                health_status['issues'].append(f"High error rate: {error_rate:.2%}")
                health_status['recommendations'].append("Investigate KMS errors")
        
        # Check latency
        if metrics.latency_avg > 1000:  # 1 second threshold
            health_status['status'] = 'warning'
            health_status['issues'].append(f"High average latency: {metrics.latency_avg:.2f}ms")
            health_status['recommendations'].append("Consider key rotation or optimization")
        
        # Check usage
        if metrics.request_count == 0:
            health_status['recommendations'].append("Key has no recent usage - consider if it's needed")
        
        return health_status
    
    def generate_report(self, hours: int = 24) -> Dict:
        """Generate comprehensive KMS report"""
        try:
            all_metrics = self.get_all_key_metrics(hours)
            
            report = {
                'generated_at': datetime.utcnow().isoformat(),
                'period_hours': hours,
                'total_keys': len(all_metrics),
                'enabled_keys': len([m for m in all_metrics if m.key_state == 'Enabled']),
                'total_requests': sum(m.request_count for m in all_metrics),
                'total_errors': sum(m.error_count for m in all_metrics),
                'keys': []
            }
            
            for metrics in all_metrics:
                health = self.check_key_health(metrics)
                key_report = {
                    'key_id': metrics.key_id,
                    'description': metrics.description,
                    'state': metrics.key_state,
                    'usage': metrics.key_usage,
                    'requests': metrics.request_count,
                    'errors': metrics.error_count,
                    'avg_latency_ms': round(metrics.latency_avg, 2),
                    'max_latency_ms': round(metrics.latency_max, 2),
                    'health': health
                }
                report['keys'].append(key_report)
            
            return report
            
        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
            return {}
    
    def monitor_and_alert(self, topic_arn: str, threshold: int = 1000) -> bool:
        """Monitor keys and send alerts for issues"""
        try:
            all_metrics = self.get_all_key_metrics(24)  # Last 24 hours
            alerts = []
            
            for metrics in all_metrics:
                health = self.check_key_health(metrics)
                
                if health['status'] != 'healthy':
                    alert = {
                        'key_id': metrics.key_id,
                        'description': metrics.description,
                        'status': health['status'],
                        'issues': health['issues'],
                        'recommendations': health['recommendations']
                    }
                    alerts.append(alert)
                
                # Check for high usage
                if metrics.request_count > threshold:
                    alerts.append({
                        'key_id': metrics.key_id,
                        'description': metrics.description,
                        'status': 'warning',
                        'issues': [f"High usage: {metrics.request_count} requests in 24h"],
                        'recommendations': ["Monitor for potential abuse or optimization needs"]
                    })
            
            if alerts:
                subject = f"KMS Alert: {len(alerts)} keys need attention"
                message = json.dumps(alerts, indent=2)
                self.send_alert(topic_arn, subject, message)
                
                # Log audit event
                self.log_audit_event('/aws/kms/alerts', {
                    'timestamp': datetime.utcnow().isoformat(),
                    'alerts': alerts
                })
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to monitor and alert: {e}")
            return False

def main():
    """Main function for CLI usage"""
    parser = argparse.ArgumentParser(description='KMS Monitoring and Alerting Tool')
    parser.add_argument('--region', help='AWS region')
    parser.add_argument('--action', choices=['report', 'monitor', 'alarm'], required=True, help='Action to perform')
    parser.add_argument('--key-id', help='Specific key ID to monitor')
    parser.add_argument('--hours', type=int, default=24, help='Hours to analyze')
    parser.add_argument('--topic-arn', help='SNS topic ARN for alerts')
    parser.add_argument('--threshold', type=int, default=1000, help='Usage threshold for alerts')
    parser.add_argument('--output', help='Output file for report')
    
    args = parser.parse_args()
    
    try:
        monitor = KMSMonitor(args.region)
        
        if args.action == 'report':
            report = monitor.generate_report(args.hours)
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(report, f, indent=2, default=str)
                print(f"Report saved to {args.output}")
            else:
                print(json.dumps(report, indent=2, default=str))
        
        elif args.action == 'monitor':
            if not args.topic_arn:
                print("Error: --topic-arn is required for monitoring")
                sys.exit(1)
            
            success = monitor.monitor_and_alert(args.topic_arn, args.threshold)
            if success:
                print("Monitoring completed successfully")
            else:
                print("Monitoring failed")
        
        elif args.action == 'alarm':
            if not args.key_id:
                print("Error: --key-id is required for alarm creation")
                sys.exit(1)
            
            alarm_name = f"kms-usage-{args.key_id.replace('/', '-')}"
            success = monitor.create_cloudwatch_alarm(args.key_id, alarm_name, args.threshold)
            if success:
                print(f"Alarm {alarm_name} created successfully")
            else:
                print("Alarm creation failed")
                
    except Exception as e:
        logger.error(f"Operation failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main() 