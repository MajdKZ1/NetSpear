"""
Cloud platform enumeration for AWS, GCP, and Azure.
"""
import logging
import subprocess
from typing import Optional, Dict, List, Any
import re

logger = logging.getLogger(__name__)


class CloudEnumerator:
    """Enumerate cloud resources and services."""
    
    def __init__(self, tool_paths: Optional[Dict[str, str]] = None):
        """
        Initialize cloud enumerator.
        
        Args:
            tool_paths: Dictionary of tool paths
        """
        self.tool_paths = tool_paths or {}
    
    def enumerate_aws(self, domain: Optional[str] = None) -> Dict[str, Any]:
        """
        Enumerate AWS resources.
        
        Args:
            domain: Optional domain to enumerate
            
        Returns:
            AWS enumeration results
        """
        results = {
            "s3_buckets": [],
            "cloudfront": [],
            "errors": [],
        }
        
        # S3 bucket enumeration
        if domain:
            # Try common bucket naming patterns
            bucket_patterns = [
                domain,
                f"www.{domain}",
                f"s3.{domain}",
                f"assets.{domain}",
                f"static.{domain}",
                f"media.{domain}",
            ]
            
            for bucket_name in bucket_patterns:
                bucket_info = self._check_s3_bucket(bucket_name)
                if bucket_info:
                    results["s3_buckets"].append(bucket_info)
        
        # Use cloud_enum if available
        if self._is_tool_available("cloud_enum"):
            try:
                cmd = ["cloud_enum", "-k", domain or ""]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.returncode == 0:
                    # Parse cloud_enum output
                    results["cloud_enum"] = result.stdout
            except Exception as e:
                results["errors"].append(f"cloud_enum failed: {e}")
        
        return results
    
    def _check_s3_bucket(self, bucket_name: str) -> Optional[Dict[str, Any]]:
        """Check if S3 bucket exists and is accessible."""
        try:
            import boto3
            from botocore.exceptions import ClientError
            
            s3 = boto3.client("s3")
            
            # Check if bucket exists
            try:
                s3.head_bucket(Bucket=bucket_name)
                return {
                    "name": bucket_name,
                    "exists": True,
                    "accessible": True,
                }
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code == "404":
                    return None
                elif error_code == "403":
                    return {
                        "name": bucket_name,
                        "exists": True,
                        "accessible": False,
                    }
                else:
                    return None
        except ImportError:
            # Try HTTP access
            import urllib.request
            url = f"http://{bucket_name}.s3.amazonaws.com"
            try:
                with urllib.request.urlopen(url, timeout=5) as response:
                    return {
                        "name": bucket_name,
                        "exists": True,
                        "accessible": True,
                        "public": True,
                    }
            except Exception:
                return None
    
    def enumerate_gcp(self, domain: Optional[str] = None) -> Dict[str, Any]:
        """
        Enumerate GCP resources.
        
        Args:
            domain: Optional domain to enumerate
            
        Returns:
            GCP enumeration results
        """
        results = {
            "storage_buckets": [],
            "app_engine": [],
            "errors": [],
        }
        
        # GCP Storage bucket enumeration
        if domain:
            bucket_patterns = [
                domain,
                f"www.{domain}",
                f"storage.{domain}",
            ]
            
            for bucket_name in bucket_patterns:
                bucket_info = self._check_gcs_bucket(bucket_name)
                if bucket_info:
                    results["storage_buckets"].append(bucket_info)
        
        return results
    
    def _check_gcs_bucket(self, bucket_name: str) -> Optional[Dict[str, Any]]:
        """Check if GCS bucket exists."""
        import urllib.request
        url = f"https://storage.googleapis.com/{bucket_name}"
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                return {
                    "name": bucket_name,
                    "exists": True,
                    "accessible": True,
                }
        except Exception:
            return None
    
    def enumerate_azure(self, domain: Optional[str] = None) -> Dict[str, Any]:
        """
        Enumerate Azure resources.
        
        Args:
            domain: Optional domain to enumerate
            
        Returns:
            Azure enumeration results
        """
        results = {
            "storage_accounts": [],
            "app_services": [],
            "errors": [],
        }
        
        # Azure Storage account enumeration
        if domain:
            account_patterns = [
                domain.replace(".", ""),
                f"{domain.replace('.', '')}storage",
            ]
            
            for account_name in account_patterns:
                account_info = self._check_azure_storage(account_name)
                if account_info:
                    results["storage_accounts"].append(account_info)
        
        return results
    
    def _check_azure_storage(self, account_name: str) -> Optional[Dict[str, Any]]:
        """Check if Azure Storage account exists."""
        import urllib.request
        url = f"https://{account_name}.blob.core.windows.net"
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                return {
                    "name": account_name,
                    "exists": True,
                    "accessible": True,
                }
        except Exception:
            return None
    
    def _is_tool_available(self, tool: str) -> bool:
        """Check if a tool is available."""
        import shutil
        return bool(shutil.which(tool))

