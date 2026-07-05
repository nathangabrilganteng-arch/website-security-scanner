"""
SSL/TLS Inspection Module
"""

import ssl
import socket
import datetime
import requests
from urllib.parse import urlparse
import OpenSSL
import cryptography

class SSLTLSInspector:
    def __init__(self, target, config):
        self.target = target
        self.config = config
        
    def inspect(self):
        """Inspect SSL/TLS configuration"""
        results = {
            'https_enabled': False,
            'valid_certificate': False,
            'certificate_details': {},
            'tls_version': 'unknown',
            'ciphers': [],
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # Extract domain
            parsed = urlparse(self.target)
            hostname = parsed.hostname or self.target
            port = 443
            
            # Check HTTPS availability
            try:
                test_url = f"https://{hostname}"
                response = requests.get(test_url, timeout=10, verify=True)
                results['https_enabled'] = True
            except:
                results['https_enabled'] = False
                results['recommendations'].append("Enable HTTPS to encrypt communication")
                return results
            
            # Get SSL certificate
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # TLS version
                    results['tls_version'] = ssock.version()
                    
                    # Get certificate
                    cert = ssock.getpeercert()
                    
                    if cert:
                        results['valid_certificate'] = True
                        
                        # Certificate details
                        subject = dict(x[0] for x in cert.get('subject', []))
                        results['certificate_details'] = {
                            'subject': subject,
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'version': cert.get('version'),
                            'serial_number': cert.get('serialNumber'),
                            'not_before': cert.get('notBefore'),
                            'not_after': cert.get('notAfter'),
                            'subject_alt_name': cert.get('subjectAltName', [])
                        }
                        
                        # Check expiration
                        not_after = datetime.datetime.strptime(cert.get('notAfter'), '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (not_after - datetime.datetime.now()).days
                        
                        if days_until_expiry < 30:
                            results['certificate_details']['expiring_soon'] = True
                            results['recommendations'].append(f"Certificate expires in {days_until_expiry} days - renew immediately")
                        elif days_until_expiry < 90:
                            results['certificate_details']['expiring_soon'] = True
                            results['recommendations'].append(f"Certificate expires in {days_until_expiry} days - consider renewing")
                        else:
                            results['certificate_details']['expiring_soon'] = False
                        
                        # Check for weak algorithms
                        self.check_weak_ciphers(results)
                        
                        # HSTS recommendation
                        results['recommendations'].append("Implement HSTS to enforce HTTPS")
            
        except ssl.SSLError as e:
            results['ssl_error'] = str(e)
            results['valid_certificate'] = False
            results['recommendations'].append("Fix SSL certificate issues")
        except socket.error as e:
            results['connection_error'] = str(e)
        except Exception as e:
            results['error'] = str(e)
            
        return results
    
    def check_weak_ciphers(self, results):
        """Check for weak cipher suites"""
        weak_ciphers = [
            'NULL', 'EXPORT', 'DES', 'RC4', 'MD5', 'SSLv2', 'SSLv3'
        ]
        
        # This is a simplified check
        # In a real implementation, you'd test actual cipher suites
        if results.get('tls_version') in ['TLSv1', 'TLSv1.1']:
            results['vulnerabilities'].append(f"Using outdated TLS version: {results['tls_version']}")
            results['recommendations'].append("Upgrade to TLS 1.2 or 1.3")
        
        if results.get('tls_version') == 'TLSv1.3':
            results['vulnerabilities'].append("Using TLS 1.3 (secure)")
        
        return results