# src/gps_scanner.py
"""
GPS Location Scanner Module
Inspired by Hound - Information gathering & GPS coordinate capture
"""

import requests
import json
import socket
import platform
import subprocess
from urllib.parse import urlparse

class GPSScanner:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.results = {}
        
    def scan_website_location(self, target_url):
        """
        Scan website for location information using various methods
        """
        results = {
            'target': target_url,
            'ip_address': None,
            'geolocation': None,
            'server_location': None,
            'isp_info': None,
            'dns_records': None,
            'whois_info': None,
            'headers': {}
        }
        
        try:
            # Get IP Address
            domain = urlparse(target_url).netloc
            if domain:
                try:
                    ip = socket.gethostbyname(domain)
                    results['ip_address'] = ip
                    
                    # Get IP Geolocation
                    geo_info = self.get_ip_geolocation(ip)
                    results['geolocation'] = geo_info
                    
                    # Get DNS Records
                    results['dns_records'] = self.get_dns_records(domain)
                    
                    # Get Server Headers
                    response = self.session.get(target_url, timeout=10, verify=False)
                    results['headers'] = dict(response.headers)
                    
                    # Extract Server Location from Headers
                    results['server_location'] = self.extract_server_location(response.headers)
                    
                    # Get WHOIS Info
                    results['whois_info'] = self.get_whois_info(domain)
                    
                    # Get ISP Info
                    results['isp_info'] = self.get_isp_info(ip)
                    
                except socket.gaierror:
                    results['error'] = f"Could not resolve domain: {domain}"
                
        except Exception as e:
            results['error'] = str(e)
            
        return results
    
    def get_ip_geolocation(self, ip):
        """Get geolocation data for an IP address"""
        geo_data = {
            'latitude': None,
            'longitude': None,
            'city': None,
            'region': None,
            'country': None,
            'timezone': None
        }
        
        try:
            # Try ip-api.com (free, no API key required)
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    geo_data.update({
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'city': data.get('city'),
                        'region': data.get('regionName'),
                        'country': data.get('country'),
                        'timezone': data.get('timezone'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'as': data.get('as')
                    })
            else:
                # Fallback to ipinfo.io
                response = requests.get(f'https://ipinfo.io/{ip}/json', timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    loc = data.get('loc', '').split(',')
                    geo_data.update({
                        'latitude': float(loc[0]) if loc else None,
                        'longitude': float(loc[1]) if len(loc) > 1 else None,
                        'city': data.get('city'),
                        'region': data.get('region'),
                        'country': data.get('country'),
                        'isp': data.get('org'),
                        'timezone': data.get('timezone')
                    })
        except:
            pass
            
        return geo_data
    
    def get_isp_info(self, ip):
        """Get ISP information"""
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}?fields=isp,org,as', timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    'isp': data.get('isp'),
                    'organization': data.get('org'),
                    'as_number': data.get('as')
                }
        except:
            pass
        return None
    
    def get_dns_records(self, domain):
        """Get DNS records for a domain"""
        dns_records = {}
        try:
            import dns.resolver
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_records[record_type] = [str(r) for r in answers]
                except:
                    pass
        except ImportError:
            # Fallback to system commands
            try:
                a_record = subprocess.check_output(['nslookup', domain], text=True)
                dns_records['nslookup'] = a_record
            except:
                pass
        return dns_records
    
    def get_whois_info(self, domain):
        """Get WHOIS information"""
        try:
            import whois
            w = whois.whois(domain)
            return {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'name_servers': w.name_servers,
                'emails': w.emails,
                'country': w.country
            }
        except:
            # Fallback to system whois
            try:
                result = subprocess.check_output(['whois', domain], text=True, timeout=10)
                return {'raw_whois': result[:1000]}
            except:
                return None
    
    def extract_server_location(self, headers):
        """Extract server location from headers"""
        location_info = {
            'country': None,
            'region': None,
            'city': None,
            'coordinates': None
        }
        
        if 'cf-ray' in headers:
            try:
                response = requests.get('https://cloudflare.com/cdn-cgi/trace')
                if response.status_code == 200:
                    for line in response.text.split('\n'):
                        if line.startswith('loc='):
                            location_info['country'] = line.split('=')[1]
                            break
            except:
                pass
        
        if 'server' in headers:
            location_info['server_type'] = headers['server']
            
        return location_info
    
    def get_target_location_from_website(self, target_url):
        """Comprehensive location scanning for a website target"""
        results = {
            'url': target_url,
            'ip_geolocation': None,
            'server_location': None,
            'domain_info': None,
            'network_info': None,
            'gps_coordinates': None
        }
        
        domain = urlparse(target_url).netloc
        
        try:
            ip = socket.gethostbyname(domain)
            geo = self.get_ip_geolocation(ip)
            results['ip_geolocation'] = geo
            results['domain_info'] = self.get_whois_info(domain)
            results['gps_coordinates'] = self.extract_gps_from_content(target_url)
            results['network_info'] = {
                'ip': ip,
                'domain': domain,
                'dns_servers': self.get_dns_servers(),
                'network_interfaces': self.get_network_interfaces()
            }
            
        except Exception as e:
            results['error'] = str(e)
            
        return results
    
    def extract_gps_from_content(self, url):
        """Extract GPS coordinates from website content"""
        gps_data = {'latitude': None, 'longitude': None, 'found_in': []}
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            content = response.text
            
            import re
            patterns = [
                r'!1s0x[0-9a-f]+:0x[0-9a-f]+!2d([-+]?\d+\.\d+)!3d([-+]?\d+\.\d+)',
                r'[-+]?\d{1,2}\.\d{4,}\s*,\s*[-+]?\d{1,3}\.\d{4,}',
                r'data-lat=["\']([-+]?\d+\.\d+)["\'].*?data-lng=["\']([-+]?\d+\.\d+)["\']',
                r'openstreetmap.*?lat=([-+]?\d+\.\d+)&lon=([-+]?\d+\.\d+)'
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    if len(matches[0]) >= 2:
                        gps_data['latitude'] = float(matches[0][0])
                        gps_data['longitude'] = float(matches[0][1])
                        gps_data['found_in'].append('website_content')
                        break
                        
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(content, 'html.parser')
            meta_tags = soup.find_all('meta')
            for tag in meta_tags:
                if tag.get('name') and 'location' in tag.get('name', '').lower():
                    content_attr = tag.get('content')
                    if content_attr:
                        coords = re.findall(r'[-+]?\d+\.\d+', content_attr)
                        if len(coords) >= 2:
                            gps_data['latitude'] = float(coords[0])
                            gps_data['longitude'] = float(coords[1])
                            gps_data['found_in'].append('meta_tags')
                            break
                            
        except Exception as e:
            gps_data['error'] = str(e)
            
        return gps_data
    
    def get_dns_servers(self):
        """Get DNS servers"""
        dns_servers = []
        try:
            with open('/etc/resolv.conf', 'r') as f:
                for line in f:
                    if line.startswith('nameserver'):
                        dns_servers.append(line.split()[1])
        except:
            pass
        return dns_servers
    
    def get_network_interfaces(self):
        """Get network interfaces"""
        interfaces = []
        try:
            import psutil
            addrs = psutil.net_if_addrs()
            for iface_name, iface_addrs in addrs.items():
                for addr in iface_addrs:
                    if addr.family == socket.AF_INET:
                        interfaces.append({
                            'name': iface_name,
                            'ip': addr.address,
                            'netmask': addr.netmask
                        })
        except:
            try:
                result = subprocess.check_output(['ip', 'addr'], text=True)
                interfaces.append({'raw': result[:500]})
            except:
                pass
        return interfaces
    
    def location_report(self, results):
        """Generate location report"""
        report = []
        report.append("\n" + "="*60)
        report.append("📍 GPS LOCATION SCAN REPORT")
        report.append("="*60)
        
        if results.get('error'):
            report.append(f"❌ Error: {results['error']}")
            return "\n".join(report)
        
        if results.get('ip_geolocation'):
            geo = results['ip_geolocation']
            report.append("\n🌐 IP Geolocation:")
            report.append(f"  IP Address: {results.get('network_info', {}).get('ip', 'Unknown')}")
            if geo.get('latitude') and geo.get('longitude'):
                report.append(f"  📍 Coordinates: {geo['latitude']}, {geo['longitude']}")
                report.append(f"  🗺️ Google Maps: https://maps.google.com/?q={geo['latitude']},{geo['longitude']}")
            if geo.get('country'):
                report.append(f"  🌍 Country: {geo['country']}")
            if geo.get('city'):
                report.append(f"  🏙️ City: {geo['city']}")
            if geo.get('region'):
                report.append(f"  📍 Region: {geo['region']}")
            if geo.get('isp'):
                report.append(f"  🔌 ISP: {geo['isp']}")
            if geo.get('timezone'):
                report.append(f"  🕐 Timezone: {geo['timezone']}")
        
        if results.get('gps_coordinates'):
            gps = results['gps_coordinates']
            if gps.get('latitude') and gps.get('longitude'):
                report.append("\n📌 GPS Coordinates from Website:")
                report.append(f"  Latitude: {gps['latitude']}")
                report.append(f"  Longitude: {gps['longitude']}")
                report.append(f"  🔍 Found in: {', '.join(gps.get('found_in', ['unknown']))}")
                report.append(f"  🗺️ Google Maps: https://maps.google.com/?q={gps['latitude']},{gps['longitude']}")
        
        if results.get('domain_info'):
            domain = results['domain_info']
            report.append("\n📋 Domain Information:")
            if domain.get('registrar'):
                report.append(f"  Registrar: {domain['registrar']}")
            if domain.get('creation_date'):
                report.append(f"  Created: {domain['creation_date']}")
            if domain.get('expiration_date'):
                report.append(f"  Expires: {domain['expiration_date']}")
            if domain.get('country'):
                report.append(f"  Country: {domain['country']}")
        
        report.append("\n" + "="*60)
        return "\n".join(report)