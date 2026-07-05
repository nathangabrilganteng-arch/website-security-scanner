"""
Network Diagnostics Module - Wi-Fi features for local network
"""

import subprocess
import platform
import socket
import re
import requests
import time
import psutil

class NetworkScanner:
    def __init__(self, config):
        self.config = config
        self.os_type = platform.system()
        
    def diagnose(self):
        """Run network diagnostics"""
        results = {
            'ssid': None,
            'ip_address': None,
            'gateway': None,
            'dns_servers': None,
            'latency': None,
            'download_speed': None,
            'upload_speed': None,
            'signal_strength': None,
            'network_interfaces': []
        }
        
        # Get network info
        if self.os_type == 'Linux':
            results.update(self.get_linux_network_info())
        elif self.os_type == 'Windows':
            results.update(self.get_windows_network_info())
        else:
            results['error'] = f"Unsupported OS: {self.os_type}"
        
        # Get all network interfaces
        results['network_interfaces'] = self.get_network_interfaces()
        
        # Ping test
        results['latency'] = self.test_latency()
        
        # Speed test (basic)
        results.update(self.test_speed())
        
        return results
    
    def get_linux_network_info(self):
        """Get network info on Linux (Termux)"""
        info = {}
        
        try:
            # SSID
            try:
                ssid = subprocess.check_output(['nmcli', '-t', '-f', 'ACTIVE,SSID', 'dev', 'wifi'], 
                                            text=True).strip().split('\n')
                for line in ssid:
                    if line.startswith('yes:'):
                        info['ssid'] = line.split(':', 1)[1]
                        break
            except:
                try:
                    # Alternative using iwgetid
                    ssid = subprocess.check_output(['iwgetid', '-r'], text=True).strip()
                    if ssid:
                        info['ssid'] = ssid
                except:
                    info['ssid'] = 'Unknown'
            
            # IP Address
            try:
                # Get active interface
                iface = subprocess.check_output(['ip', 'route', 'show', 'default'], text=True)
                iface = iface.split()[-1] if iface else 'wlan0'
                
                ip = subprocess.check_output(['ip', '-4', 'addr', 'show', iface], text=True)
                ip_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', ip)
                info['ip_address'] = ip_match.group(1) if ip_match else None
                
                # Gateway
                gw = subprocess.check_output(['ip', 'route', 'show', 'default'], text=True)
                gw_match = re.search(r'via\s+(\d+\.\d+\.\d+\.\d+)', gw)
                info['gateway'] = gw_match.group(1) if gw_match else None
                
                # DNS
                dns = subprocess.check_output(['cat', '/etc/resolv.conf'], text=True)
                dns_servers = re.findall(r'nameserver\s+(\d+\.\d+\.\d+\.\d+)', dns)
                info['dns_servers'] = dns_servers[:3] if dns_servers else ['Not found']
                
                # Signal strength
                try:
                    signal = subprocess.check_output(['cat', '/proc/net/wireless'], text=True)
                    signal_match = re.search(r'wlan0:\s+(\d+)\s+(\d+)', signal)
                    if signal_match:
                        info['signal_strength'] = int(signal_match.group(2)) * 100 // 70  # Approximate
                except:
                    info['signal_strength'] = None
                    
            except Exception as e:
                info['error'] = str(e)
                
        except Exception as e:
            info['error'] = f"Linux detection error: {str(e)}"
            
        return info
    
    def get_windows_network_info(self):
        """Get network info on Windows"""
        info = {}
        try:
            # SSID
            try:
                result = subprocess.check_output(['netsh', 'wlan', 'show', 'interfaces'], 
                                               text=True, shell=True)
                ssid_match = re.search(r'SSID\s+:\s+(.+)', result)
                info['ssid'] = ssid_match.group(1).strip() if ssid_match else None
            except:
                info['ssid'] = 'Unknown'
            
            # IP Address and Gateway
            try:
                result = subprocess.check_output(['ipconfig'], text=True, shell=True)
                # Find active adapter (first one with IP)
                sections = re.split(r'\n\s*\n', result)
                for section in sections:
                    if 'IPv4 Address' in section or 'IP Address' in section:
                        ip_match = re.search(r'IP(?:v4)? Address[.\s]+: (\d+\.\d+\.\d+\.\d+)', section)
                        if ip_match:
                            info['ip_address'] = ip_match.group(1)
                            gw_match = re.search(r'Default Gateway[.\s]+: (\d+\.\d+\.\d+\.\d+)', section)
                            info['gateway'] = gw_match.group(1) if gw_match else None
                            break
                
                # DNS
                dns_servers = re.findall(r'DNS Servers[.\s]+: (\d+\.\d+\.\d+\.\d+)', result)
                info['dns_servers'] = dns_servers[:3] if dns_servers else ['Not found']
                
            except Exception as e:
                info['error'] = str(e)
                
        except Exception as e:
            info['error'] = f"Windows detection error: {str(e)}"
            
        return info
    
    def get_network_interfaces(self):
        """Get all network interfaces"""
        interfaces = []
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            
            for iface_name, iface_addrs in addrs.items():
                if iface_name in stats:
                    interface_info = {
                        'name': iface_name,
                        'is_up': stats[iface_name].isup,
                        'speed': stats[iface_name].speed,
                        'mtu': stats[iface_name].mtu,
                        'addresses': []
                    }
                    
                    for addr in iface_addrs:
                        interface_info['addresses'].append({
                            'family': str(addr.family),
                            'address': addr.address,
                            'netmask': addr.netmask,
                            'broadcast': addr.broadcast
                        })
                    
                    interfaces.append(interface_info)
        except:
            # Fallback to socket if psutil not available
            try:
                hostname = socket.gethostname()
                ip = socket.gethostbyname(hostname)
                interfaces.append({
                    'name': 'default',
                    'addresses': [{'address': ip}]
                })
            except:
                pass
                
        return interfaces
    
    def test_latency(self):
        """Test network latency"""
        try:
            # Ping Google DNS
            if self.os_type == 'Windows':
                cmd = ['ping', '-n', '4', '8.8.8.8']
            else:
                cmd = ['ping', '-c', '4', '8.8.8.8']
                
            result = subprocess.check_output(cmd, text=True, timeout=10)
            
            # Extract average latency
            if self.os_type == 'Windows':
                avg_match = re.search(r'Average = (\d+)ms', result)
            else:
                avg_match = re.search(r'avg = (\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+) ms', result)
                
            if avg_match:
                return float(avg_match.group(1))
            
            # Alternative ping to local gateway
            if self.gateway:
                if self.os_type == 'Windows':
                    cmd = ['ping', '-n', '4', self.gateway]
                else:
                    cmd = ['ping', '-c', '4', self.gateway]
                result = subprocess.check_output(cmd, text=True, timeout=5)
                avg_match = re.search(r'avg = (\d+\.\d+)', result)
                if avg_match:
                    return float(avg_match.group(1))
                    
        except:
            return None
            
        return None
    
    def test_speed(self):
        """Basic speed test"""
        results = {'download_speed': None, 'upload_speed': None}
        
        try:
            # Download test - download small file from GitHub
            start_time = time.time()
            response = requests.get('https://raw.githubusercontent.com/',
                                  timeout=10, stream=True)
            if response.status_code == 200:
                total_size = 0
                for chunk in response.iter_content(chunk_size=1024):
                    total_size += len(chunk)
                    if time.time() - start_time > 5:  # Max 5 seconds
                        break
                elapsed = time.time() - start_time
                if elapsed > 0:
                    results['download_speed'] = (total_size / 1024 / 1024) / elapsed  # MB/s
            
            # Upload test - send small data
            if results.get('download_speed'):
                test_data = 'x' * 1024 * 100  # 100KB
                start_time = time.time()
                try:
                    # Send to httpbin
                    response = requests.post('https://httpbin.org/post',
                                           data=test_data,
                                           timeout=5)
                    if response.status_code == 200:
                        elapsed = time.time() - start_time
                        if elapsed > 0:
                            results['upload_speed'] = (len(test_data) / 1024 / 1024) / elapsed  # MB/s
                except:
                    pass
                    
        except Exception as e:
            results['speed_test_error'] = str(e)
            
        return results