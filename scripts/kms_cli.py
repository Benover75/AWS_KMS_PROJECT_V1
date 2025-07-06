#!/usr/bin/env python3
"""
AWS KMS Management CLI Tool
Provides comprehensive key management capabilities
"""

import boto3
import json
import argparse
import sys
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import logging
from pathlib import Path
import click
from botocore.exceptions import ClientError, NoCredentialsError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class KMSManager:
    """KMS Key Management Class"""
    
    def __init__(self, region: str = None, profile: str = None):
        """Initialize KMS client"""
        try:
            if profile:
                session = boto3.Session(profile_name=profile)
                self.kms = session.client('kms', region_name=region)
            else:
                self.kms = boto3.client('kms', region_name=region)
            self.region = region or self.kms.meta.region_name
        except NoCredentialsError:
            logger.error("AWS credentials not found. Please configure your credentials.")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Failed to initialize KMS client: {e}")
            sys.exit(1)
    
    def list_keys(self, limit: int = 50) -> List[Dict]:
        """List KMS keys"""
        try:
            keys = []
            paginator = self.kms.get_paginator('list_keys')
            
            for page in paginator.paginate(Limit=limit):
                for key in page['Keys']:
                    # Get additional key details
                    try:
                        key_metadata = self.kms.describe_key(KeyId=key['KeyId'])['KeyMetadata']
                        key['Description'] = key_metadata.get('Description', '')
                        key['KeyState'] = key_metadata.get('KeyState', '')
                        key['KeyUsage'] = key_metadata.get('KeyUsage', '')
                        key['CreationDate'] = key_metadata.get('CreationDate', '')
                    except Exception as e:
                        logger.warning(f"Could not get details for key {key['KeyId']}: {e}")
                    
                    keys.append(key)
            
            return keys
        except Exception as e:
            logger.error(f"Failed to list keys: {e}")
            return []
    
    def list_aliases(self) -> List[Dict]:
        """List KMS aliases"""
        try:
            aliases = []
            paginator = self.kms.get_paginator('list_aliases')
            
            for page in paginator.paginate():
                aliases.extend(page['Aliases'])
            
            return aliases
        except Exception as e:
            logger.error(f"Failed to list aliases: {e}")
            return []
    
    def create_key(self, description: str, alias: str = None, policy: str = None, 
                   key_usage: str = 'ENCRYPT_DECRYPT', 
                   customer_master_key_spec: str = 'SYMMETRIC_DEFAULT',
                   enable_key_rotation: bool = True,
                   tags: Dict = None) -> Optional[str]:
        """Create a new KMS key"""
        try:
            # Prepare key creation parameters
            params = {
                'Description': description,
                'KeyUsage': key_usage,
                'CustomerMasterKeySpec': customer_master_key_spec,
                'EnableKeyRotation': enable_key_rotation
            }
            
            # Add policy if provided
            if policy:
                if os.path.exists(policy):
                    with open(policy, 'r') as f:
                        policy_content = f.read()
                else:
                    policy_content = policy
                params['Policy'] = policy_content
            
            # Add tags if provided
            if tags:
                params['Tags'] = [{'TagKey': k, 'TagValue': v} for k, v in tags.items()]
            
            # Create the key
            response = self.kms.create_key(**params)
            key_id = response['KeyMetadata']['KeyId']
            
            logger.info(f"Created KMS key: {key_id}")
            
            # Create alias if provided
            if alias:
                self.create_alias(alias, key_id)
            
            return key_id
            
        except Exception as e:
            logger.error(f"Failed to create key: {e}")
            return None
    
    def create_alias(self, alias_name: str, key_id: str) -> bool:
        """Create a KMS alias"""
        try:
            # Ensure alias name starts with 'alias/'
            if not alias_name.startswith('alias/'):
                alias_name = f'alias/{alias_name}'
            
            self.kms.create_alias(
                AliasName=alias_name,
                TargetKeyId=key_id
            )
            
            logger.info(f"Created alias: {alias_name} -> {key_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create alias: {e}")
            return False
    
    def delete_key(self, key_id: str, pending_window: int = 7) -> bool:
        """Schedule key deletion"""
        try:
            self.kms.schedule_key_deletion(
                KeyId=key_id,
                PendingWindowInDays=pending_window
            )
            
            logger.info(f"Scheduled key deletion: {key_id} (pending window: {pending_window} days)")
            return True
            
        except Exception as e:
            logger.error(f"Failed to schedule key deletion: {e}")
            return False
    
    def enable_key(self, key_id: str) -> bool:
        """Enable a KMS key"""
        try:
            self.kms.enable_key(KeyId=key_id)
            logger.info(f"Enabled key: {key_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to enable key: {e}")
            return False
    
    def disable_key(self, key_id: str) -> bool:
        """Disable a KMS key"""
        try:
            self.kms.disable_key(KeyId=key_id)
            logger.info(f"Disabled key: {key_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to disable key: {e}")
            return False
    
    def get_key_usage(self, key_id: str, days: int = 30) -> Dict:
        """Get key usage statistics"""
        try:
            cloudwatch = boto3.client('cloudwatch', region_name=self.region)
            
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=days)
            
            response = cloudwatch.get_metric_statistics(
                Namespace='AWS/KMS',
                MetricName='NumberOfRequests',
                Dimensions=[{'Name': 'KeyId', 'Value': key_id}],
                StartTime=start_time,
                EndTime=end_time,
                Period=86400,  # Daily
                Statistics=['Sum', 'Average', 'Maximum']
            )
            
            return response
        except Exception as e:
            logger.error(f"Failed to get key usage: {e}")
            return {}
    
    def validate_policy(self, policy_file: str) -> bool:
        """Validate KMS policy file"""
        try:
            with open(policy_file, 'r') as f:
                policy = json.load(f)
            
            # Basic validation
            required_fields = ['Version', 'Statement']
            for field in required_fields:
                if field not in policy:
                    logger.error(f"Missing required field: {field}")
                    return False
            
            if not isinstance(policy['Statement'], list):
                logger.error("Statement must be a list")
                return False
            
            for statement in policy['Statement']:
                if 'Effect' not in statement or 'Action' not in statement:
                    logger.error("Each statement must have Effect and Action")
                    return False
            
            logger.info("Policy validation successful")
            return True
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in policy file: {e}")
            return False
        except Exception as e:
            logger.error(f"Policy validation failed: {e}")
            return False

@click.group()
@click.option('--region', help='AWS region')
@click.option('--profile', help='AWS profile')
@click.pass_context
def cli(ctx, region, profile):
    """AWS KMS Management CLI Tool"""
    ctx.ensure_object(dict)
    ctx.obj['kms'] = KMSManager(region, profile)

@cli.command()
@click.option('--limit', default=50, help='Maximum number of keys to list')
@click.pass_context
def list_keys(ctx, limit):
    """List KMS keys"""
    kms = ctx.obj['kms']
    keys = kms.list_keys(limit)
    
    if not keys:
        click.echo("No keys found")
        return
    
    click.echo(f"\nFound {len(keys)} KMS keys:\n")
    for key in keys:
        click.echo(f"Key ID: {key['KeyId']}")
        click.echo(f"Description: {key.get('Description', 'N/A')}")
        click.echo(f"State: {key.get('KeyState', 'N/A')}")
        click.echo(f"Usage: {key.get('KeyUsage', 'N/A')}")
        click.echo(f"Created: {key.get('CreationDate', 'N/A')}")
        click.echo("-" * 50)

@cli.command()
@click.pass_context
def list_aliases(ctx):
    """List KMS aliases"""
    kms = ctx.obj['kms']
    aliases = kms.list_aliases()
    
    if not aliases:
        click.echo("No aliases found")
        return
    
    click.echo(f"\nFound {len(aliases)} KMS aliases:\n")
    for alias in aliases:
        click.echo(f"Alias: {alias['AliasName']}")
        click.echo(f"Target Key: {alias.get('TargetKeyId', 'N/A')}")
        click.echo(f"ARN: {alias.get('AliasArn', 'N/A')}")
        click.echo("-" * 50)

@cli.command()
@click.option('--description', required=True, help='Key description')
@click.option('--alias', help='Key alias')
@click.option('--policy', help='Policy file path or JSON string')
@click.option('--key-usage', default='ENCRYPT_DECRYPT', help='Key usage')
@click.option('--key-spec', default='SYMMETRIC_DEFAULT', help='Key specification')
@click.option('--enable-rotation/--disable-rotation', default=True, help='Enable key rotation')
@click.pass_context
def create_key(ctx, description, alias, policy, key_usage, key_spec, enable_rotation):
    """Create a new KMS key"""
    kms = ctx.obj['kms']
    
    # Validate policy if provided
    if policy and os.path.exists(policy):
        if not kms.validate_policy(policy):
            click.echo("Policy validation failed")
            return
    
    key_id = kms.create_key(
        description=description,
        alias=alias,
        policy=policy,
        key_usage=key_usage,
        customer_master_key_spec=key_spec,
        enable_key_rotation=enable_rotation
    )
    
    if key_id:
        click.echo(f"Successfully created key: {key_id}")
    else:
        click.echo("Failed to create key")

@cli.command()
@click.option('--key-id', required=True, help='Key ID or alias')
@click.option('--pending-window', default=7, help='Pending window in days')
@click.pass_context
def delete_key(ctx, key_id, pending_window):
    """Schedule key deletion"""
    kms = ctx.obj['kms']
    
    if click.confirm(f"Are you sure you want to delete key {key_id}?"):
        if kms.delete_key(key_id, pending_window):
            click.echo(f"Key {key_id} scheduled for deletion")
        else:
            click.echo("Failed to schedule key deletion")

@cli.command()
@click.option('--key-id', required=True, help='Key ID or alias')
@click.option('--days', default=30, help='Number of days to analyze')
@click.pass_context
def key_usage(ctx, key_id, days):
    """Get key usage statistics"""
    kms = ctx.obj['kms']
    usage = kms.get_key_usage(key_id, days)
    
    if usage.get('Datapoints'):
        click.echo(f"\nKey usage for {key_id} (last {days} days):\n")
        for datapoint in usage['Datapoints']:
            click.echo(f"Date: {datapoint['Timestamp']}")
            click.echo(f"Sum: {datapoint['Sum']}")
            click.echo(f"Average: {datapoint['Average']:.2f}")
            click.echo(f"Maximum: {datapoint['Maximum']}")
            click.echo("-" * 30)
    else:
        click.echo(f"No usage data found for key {key_id}")

@cli.command()
@click.option('--policy-file', required=True, help='Policy file path')
@click.pass_context
def validate_policy(ctx, policy_file):
    """Validate KMS policy file"""
    kms = ctx.obj['kms']
    
    if kms.validate_policy(policy_file):
        click.echo("Policy is valid")
    else:
        click.echo("Policy is invalid")

if __name__ == '__main__':
    cli() 