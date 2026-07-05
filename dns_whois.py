"""
DNS and WHOIS Information Module
"""

import dns.resolver
import whois
import socket
from urllib.parse import urlparse
import datetime

class DNSWhoisChecker:
    def __init__(self, target, config):
        self.target = target
        self.config = config
        
    def check(self):
        """Check DNS and WHOIS information"""
        results = {
            'domain': '',
            'dns_records': {},
            'whois': {},
            'domain_expiring_soon': False,
            'expiration_date': None
        }
        
        # Extract domain
        parsed = urlparse(self.target)
        domain = parsed.hostname or self.target
        results['domain'] = domain
        
        # DNS checks
        results['dns_records'] = self.get_dns_records(domain)
        
        # WHOIS check
        results['whois'] = self.get_whois(domain)
        
        # Expiration check
        if 'expiration_date' in results['whois']:
            exp_date = results['whois']['expiration_date']
            if isinstance(exp_date, list):
                exp_date = exp_date[0]
            
            if exp_date:
                results['expiration_date'] = exp_date.isoformat()
                days_remaining = (exp_date - datetime.datetime.now()).days
                results['domain_expiring_soon'] = days_remaining < 30
                results['days_remaining'] = days_remaining
        
        return results
    
    def get_dns_records(self, domain):
        """Get DNS records"""
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(r) for r in answers]
            except dns.resolver.NoAnswer:
                records[record_type] = []
            except dns.resolver.NXDOMAIN:
                records[record_type] = []
            except Exception as e:
                records[record_type] = [f"Error: {str(e)}"]
        
        return records
    
    def get_whois(self, domain):
        """Get WHOIS information"""
        try:
            w = whois.whois(domain)
            whois_info = {
                'registrar': w.registrar,
                'creation_date': w.creation_date.isoformat() if w.creation_date else None,
                'expiration_date': w.expiration_date.isoformat() if w.expiration_date else None,
                'name_servers': w.name_servers,
                'status': w.status,
                'registrant_email': w.email,
                'updated_date': w.updated_date.isoformat() if w.updated_date else None
            }
            return whois_info
        except Exception as e:
            return {'error': str(e)}