"""
Utility functions for the scanner
"""

import re
import hashlib
import json
from datetime import datetime
import os

class Utils:
    @staticmethod
    def sanitize_domain(domain):
        """Sanitize domain input"""
        domain = domain.strip()
        domain = domain.lower()
        # Remove protocol
        domain = re.sub(r'^https?://', '', domain)
        # Remove path
        domain = domain.split('/')[0]
        # Remove www
        domain = re.sub(r'^www\.', '', domain)
        return domain
    
    @staticmethod
    def get_domain_hash(domain):
        """Get hash of domain for unique identification"""
        return hashlib.md5(domain.encode()).hexdigest()[:8]
    
    @staticmethod
    def is_valid_url(url):
        """Validate URL format"""
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return url_pattern.match(url) is not None
    
    @staticmethod
    def format_size(bytes_size):
        """Format bytes to human readable size"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.2f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.2f} TB"
    
    @staticmethod
    def format_time(seconds):
        """Format seconds to human readable time"""
        if seconds < 60:
            return f"{seconds:.2f}s"
        elif seconds < 3600:
            return f"{seconds/60:.2f}m"
        else:
            return f"{seconds/3600:.2f}h"
    
    @staticmethod
    def ensure_dir(directory):
        """Ensure directory exists"""
        if not os.path.exists(directory):
            os.makedirs(directory)
    
    @staticmethod
    def parse_yaml_file(file_path):
        """Parse YAML file"""
        import yaml
        try:
            with open(file_path, 'r') as f:
                return yaml.safe_load(f)
        except:
            return {}
    
    @staticmethod
    def export_json(data, file_path):
        """Export data to JSON file"""
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    
    @staticmethod
    def calculate_https_score(https_enabled, hsts_enabled, valid_cert):
        """Calculate HTTPS security score"""
        score = 0
        if https_enabled:
            score += 30
            if hsts_enabled:
                score += 20
            if valid_cert:
                score += 10
        return min(score, 60)
    
    @staticmethod
    def get_security_level(score):
        """Get security level based on score"""
        if score >= 90:
            return 'Excellent'
        elif score >= 70:
            return 'Good'
        elif score >= 50:
            return 'Fair'
        elif score >= 30:
            return 'Poor'
        else:
            return 'Critical'
    
    @staticmethod
    def generate_summary(results):
        """Generate summary from results"""
        summary = {
            'total_checks': 0,
            'passed': 0,
            'failed': 0,
            'warning': 0,
            'security_headers': 0,
            'critical_issues': []
        }
        
        for module, data in results.get('modules', {}).items():
            if isinstance(data, dict):
                if module == 'security_headers':
                    if 'security_headers' in data:
                        summary['security_headers'] = len(data['security_headers'])
                        if data.get('hsts_enabled'):
                            summary['passed'] += 1
                        else:
                            summary['failed'] += 1
                            summary['critical_issues'].append('HSTS not enabled')
                elif module == 'ssl_tls':
                    if data.get('valid_certificate'):
                        summary['passed'] += 1
                    else:
                        summary['failed'] += 1
                        summary['critical_issues'].append('Invalid SSL certificate')
                elif module == 'html':
                    if data.get('html_validated'):
                        summary['passed'] += 1
                    else:
                        summary['warning'] += 1
        
        summary['total_checks'] = summary['passed'] + summary['failed'] + summary['warning']
        return summary