import os
import shutil
from typing import Dict, List

class ToolRegistry:
    """Manages tool definitions and availability checking"""
    
    def __init__(self):
        self.required_tools = {
            # Network Scanning & Enumeration
            'nmap': 'Network mapper',
            'netcat': 'Network utility',
            'nbtscan': 'NetBIOS scanner',

            # Web Testing
            'feroxbuster': 'Fast content discovery',
            'sqlmap': 'SQL injection testing',
            'wpscan': 'WordPress security scanner',
            'whatweb': 'Web technology identifier',
            'httpx': 'HTTP toolkit',
            'ffuf': 'Web fuzzer',

            # DNS Tools
            'dig': 'DNS lookup utility',
            'whois': 'WHOIS client',
            'dnsrecon': 'DNS enumeration tool',
            'sublist3r': 'Subdomain enumeration',

            # Vulnerability Assessment
            'nuclei': 'Vulnerability scanner',
            'vulners': 'Vulnerability scanner',

            # Password Testing
            'hydra': 'Password cracking tool',
            'john': 'Password cracking tool',
            'hashcat': 'Password recovery tool',
            'cewl': 'Custom word list generator',
            'crunch': 'Wordlist generator',

            # Network Analysis
            'tcpdump': 'Packet analyzer',
            'wireshark': 'Network protocol analyzer',
            'tshark': 'CLI version of Wireshark',

            # SSL/TLS Testing
            'sslyze': 'SSL/TLS analyzer',
            'testssl.sh': 'SSL/TLS testing tool',

            # OSINT
            'theharvester': 'Email/domain reconnaissance',
            'recon-ng': 'Reconnaissance framework',
            'maltego': 'OSINT tool',
        }
    
    def _check_installed_tools(self) -> Dict[str, bool]:
        """Check which tools are installed on the system"""
        installed_tools = {}
        
        for tool in self.required_tools:
            # Check if tool is available in PATH
            installed_tools[tool] = shutil.which(tool) is not None
        
        return installed_tools
    
    def get_installed_tools(self) -> List[str]:
        """Get list of installed tools"""
        installed = self._check_installed_tools()
        return [tool for tool, is_installed in installed.items() if is_installed]
    
    def get_missing_tools(self) -> List[str]:
        """Get list of missing tools"""
        installed = self._check_installed_tools()
        return [tool for tool, is_installed in installed.items() if not is_installed]
    
    def get_tools_list(self) -> Dict[str, str]:
        """Get the complete tools list with descriptions"""
        return self.required_tools.copy()
    
    def is_tool_available(self, tool_name: str) -> bool:
        """Check if a specific tool is available"""
        return shutil.which(tool_name) is not None 