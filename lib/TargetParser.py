import re
import urllib.parse
from typing import Dict, Optional, Tuple

class TargetParser:
    """Handles target parsing, validation, and URL manipulation"""
    
    def __init__(self):
        # URL validation pattern
        self.url_pattern = r'^(https?://)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*|(\d{1,3}\.){3}\d{1,3})(:\d+)?(/[^\s]*)?$'
        
        # IP address pattern
        self.ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        
        # Hostname pattern
        self.hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    
    def validate_target(self, target: str) -> bool:
        """Validate if the target is a valid hostname, IP address, or URL"""
        if not target or not isinstance(target, str):
            return False
        
        target = target.strip()
        if not target:
            return False
        
        # Check if it matches URL pattern
        if re.match(self.url_pattern, target):
            # Extract host for further validation
            host = self._extract_host(target)
            if not host:
                return False
            
            # If host is an IP address, validate octets
            if re.match(self.ip_pattern, host):
                return self._validate_ip_address(host)
            
            # If host is a hostname, validate it
            if re.match(self.hostname_pattern, host):
                return True
        
        return False
    
    def _validate_ip_address(self, ip: str) -> bool:
        """Validate IP address octets"""
        try:
            octets = ip.split('.')
            if len(octets) != 4:
                return False
            
            for octet in octets:
                if not octet.isdigit():
                    return False
                value = int(octet)
                if value < 0 or value > 255:
                    return False
            
            return True
        except Exception:
            return False
    
    def _extract_host(self, target: str) -> Optional[str]:
        """Extract host from URL or return the original string if not a URL"""
        # Remove protocol if present
        if '://' in target:
            target = target.split('://', 1)[1]
        
        # Remove path if present
        if '/' in target:
            target = target.split('/', 1)[0]
        
        # Remove port if present
        if ':' in target:
            target = target.split(':', 1)[0]
        
        return target
    
    def parse_url(self, target: str) -> Dict[str, str]:
        """Parse URL into components"""
        result = {
            'original': target,
            'protocol': 'http',
            'host': '',
            'port': '',
            'path': '',
            'full_url': target
        }
        
        try:
            # If no protocol specified, assume http
            if not target.startswith(('http://', 'https://')):
                target = 'http://' + target
            
            parsed = urllib.parse.urlparse(target)
            
            result['protocol'] = parsed.scheme or 'http'
            result['host'] = parsed.hostname or ''
            result['port'] = str(parsed.port) if parsed.port else ''
            result['path'] = parsed.path or '/'
            result['full_url'] = target
            
        except Exception:
            # If parsing fails, try to extract basic components
            result['host'] = self._extract_host(target) or target
        
        return result
    
    def determine_protocol(self, target: str) -> str:
        """Determine the protocol for a target"""
        if target.startswith('https://'):
            return 'https'
        elif target.startswith('http://'):
            return 'http'
        else:
            # Default to http for unknown protocols
            return 'http'
    
    def get_host_port(self, target: str, include_port: bool = False) -> str:
        """Extract host and optionally port from target"""
        host = self._extract_host(target)
        if not host:
            return target
        
        if include_port and ':' in target:
            # Extract port from original target
            try:
                port_part = target.split('://', 1)[1].split('/', 1)[0]
                if ':' in port_part:
                    return port_part
            except Exception:
                pass
        
        return host
    
    def get_full_url(self, target: str, protocol: str = None) -> str:
        """Get full URL with protocol"""
        if not protocol:
            protocol = self.determine_protocol(target)
        
        # If already has protocol, return as is
        if target.startswith(('http://', 'https://')):
            return target
        
        # Extract host and path
        host = self._extract_host(target)
        path = ''
        
        if '/' in target:
            path = target.split('/', 1)[1]
        
        # Build full URL
        if path:
            return f"{protocol}://{host}/{path}"
        else:
            return f"{protocol}://{host}"
    
    def get_target_info(self, target: str) -> Dict[str, str]:
        """Get comprehensive information about a target"""
        info = {
            'original': target,
            'is_valid': self.validate_target(target),
            'type': 'unknown',
            'host': '',
            'port': '',
            'protocol': '',
            'path': '',
            'full_url': ''
        }
        
        if not info['is_valid']:
            return info
        
        # Parse the target
        parsed = self.parse_url(target)
        info.update(parsed)
        
        # Determine target type
        host = info['host']
        if re.match(self.ip_pattern, host):
            info['type'] = 'ip_address'
        elif re.match(self.hostname_pattern, host):
            info['type'] = 'hostname'
        else:
            info['type'] = 'url'
        
        return info
    
    def normalize_target(self, target: str) -> str:
        """Normalize target to standard format"""
        if not target:
            return target
        
        target = target.strip()
        
        # If it's a valid target, return as is
        if self.validate_target(target):
            return target
        
        # Try to fix common issues
        # Remove extra spaces
        target = re.sub(r'\s+', '', target)
        
        # Add protocol if missing
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        return target
    
    def is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address"""
        host = self._extract_host(target)
        if not host:
            return False
        return bool(re.match(self.ip_pattern, host))
    
    def is_hostname(self, target: str) -> bool:
        """Check if target is a hostname"""
        host = self._extract_host(target)
        if not host:
            return False
        return bool(re.match(self.hostname_pattern, host))
    
    def is_url(self, target: str) -> bool:
        """Check if target is a URL"""
        return bool(re.match(self.url_pattern, target))
    
    def get_scan_targets(self, target: str) -> list:
        """Get list of targets for scanning (useful for subdomain enumeration)"""
        targets = []
        
        if self.is_ip_address(target):
            targets.append(target)
        elif self.is_hostname(target):
            targets.append(target)
            # Could add subdomain generation here
        elif self.is_url(target):
            host = self._extract_host(target)
            if host:
                targets.append(host)
        
        return targets 
