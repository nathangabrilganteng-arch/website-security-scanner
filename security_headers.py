"""
Security Headers Analysis Module
"""

import requests
import re
from urllib.parse import urlparse

class SecurityHeadersAnalyzer:
    def __init__(self, target, config):
        self.target = target
        self.config = config
        self.session = requests.Session()
        self.session.timeout = config.get('scan_timeout', 10)
        self.session.headers.update({
            'User-Agent': config.get('user_agent', 'Mozilla/5.0'),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })
    
    def analyze(self):
        """Analyze security headers"""
        results = {
            'url': self.target,
            'headers': {},
            'hsts_enabled': False,
            'csp_present': False,
            'x_frame_options': False,
            'x_content_type_options': False,
            'referrer_policy': False,
            'permissions_policy': False,
            'security_headers': []
        }
        
        try:
            response = self.session.get(self.target, allow_redirects=True, verify=self.config.get('verify_ssl', True))
            headers = response.headers
            
            # Check HSTS
            if 'Strict-Transport-Security' in headers:
                results['hsts_enabled'] = True
                results['headers']['Strict-Transport-Security'] = headers['Strict-Transport-Security']
                results['security_headers'].append('HSTS')
            
            # Check CSP
            if 'Content-Security-Policy' in headers:
                results['csp_present'] = True
                results['headers']['Content-Security-Policy'] = headers['Content-Security-Policy']
                results['security_headers'].append('CSP')
            elif 'Content-Security-Policy-Report-Only' in headers:
                results['csp_present'] = True
                results['headers']['Content-Security-Policy-Report-Only'] = headers['Content-Security-Policy-Report-Only']
                results['security_headers'].append('CSP (Report Only)')
            
            # Check X-Frame-Options
            if 'X-Frame-Options' in headers:
                results['x_frame_options'] = True
                results['headers']['X-Frame-Options'] = headers['X-Frame-Options']
                results['security_headers'].append('X-Frame-Options')
            
            # Check X-Content-Type-Options
            if 'X-Content-Type-Options' in headers:
                results['x_content_type_options'] = True
                results['headers']['X-Content-Type-Options'] = headers['X-Content-Type-Options']
                results['security_headers'].append('X-Content-Type-Options')
            
            # Check Referrer-Policy
            if 'Referrer-Policy' in headers:
                results['referrer_policy'] = True
                results['headers']['Referrer-Policy'] = headers['Referrer-Policy']
                results['security_headers'].append('Referrer-Policy')
            
            # Check Permissions-Policy
            if 'Permissions-Policy' in headers:
                results['permissions_policy'] = True
                results['headers']['Permissions-Policy'] = headers['Permissions-Policy']
                results['security_headers'].append('Permissions-Policy')
            
            # Check CORS headers
            cors_headers = ['Access-Control-Allow-Origin', 'Access-Control-Allow-Methods', 
                          'Access-Control-Allow-Headers', 'Access-Control-Allow-Credentials']
            results['cors_headers'] = {}
            for header in cors_headers:
                if header in headers:
                    results['cors_headers'][header] = headers[header]
            
            # Cookie analysis
            cookies = response.cookies
            results['cookies'] = []
            for cookie in cookies:
                cookie_info = {
                    'name': cookie.name,
                    'secure': cookie.secure,
                    'httponly': cookie.has_nonstandard_attr('httponly'),
                    'samesite': cookie._rest.get('samesite', 'None')
                }
                results['cookies'].append(cookie_info)
            
            # Response analysis
            results['status_code'] = response.status_code
            results['content_type'] = headers.get('Content-Type', 'unknown')
            results['server'] = headers.get('Server', 'unknown')
            results['redirect_count'] = len(response.history)
            
            # Mixed content check
            results['mixed_content'] = self.check_mixed_content(response.text)
            
            # Error pages
            results['error_pages'] = self.check_error_pages()
            
            # Cache control
            results['cache_control'] = headers.get('Cache-Control', 'not specified')
            results['pragma'] = headers.get('Pragma', 'not specified')
            
            # Security headers score
            results['score'] = len(results['security_headers']) * 10
            
        except requests.exceptions.SSLError:
            results['ssl_error'] = True
            results['status_code'] = 'SSL Error'
        except requests.exceptions.ConnectionError:
            results['connection_error'] = True
            results['status_code'] = 'Connection Error'
        except Exception as e:
            results['error'] = str(e)
            
        return results
    
    def check_mixed_content(self, html_content):
        """Check for mixed content"""
        mixed_patterns = [
            r'http://[^"\']+\.(jpg|jpeg|png|gif|css|js)',
            r'<img[^>]+src="http://',
            r'<script[^>]+src="http://',
            r'<link[^>]+href="http://'
        ]
        
        mixed_items = []
        for pattern in mixed_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            if matches:
                mixed_items.extend(matches)
        
        return {
            'has_mixed_content': len(mixed_items) > 0,
            'items': mixed_items[:10],  # Limit to 10 items
            'count': len(mixed_items)
        }
    
    def check_error_pages(self):
        """Check error pages"""
        error_pages = {}
        error_codes = [400, 401, 403, 404, 500, 502, 503]
        
        for code in error_codes:
            try:
                test_url = f"{self.target}/nonexistent_file_{code}.html"
                response = self.session.get(test_url, timeout=5)
                if response.status_code == code:
                    error_pages[code] = {
                        'status': 'custom',
                        'size': len(response.content)
                    }
                else:
                    error_pages[code] = {
                        'status': 'redirected',
                        'status_code': response.status_code
                    }
            except:
                error_pages[code] = {'status': 'unavailable'}
        
        return error_pages