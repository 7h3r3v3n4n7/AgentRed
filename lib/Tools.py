import subprocess
import os
import re
import shutil
import signal
import psutil
import time
import datetime
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass

# Import RAG functionality
try:
    from .RAG import ScanRAG, SearchResult
    RAG_AVAILABLE = True
except ImportError:
    RAG_AVAILABLE = False

# Load environment variables
DEBUG = os.getenv('DEBUG', '0') == '1'
COMMAND_TIMEOUT = int(os.getenv('COMMAND_TIMEOUT', '300'))  # 5 minutes default timeout
MEMORY_THRESHOLD = float(os.getenv('MEMORY_THRESHOLD', '0.8'))  # 80% memory threshold

def debug_print(*args, **kwargs):
    """Print debug messages only if DEBUG is enabled"""
    if DEBUG:
        print("[DEBUG]", *args, **kwargs)

@dataclass
class CommandResult:
    output: str
    success: bool
    error: Optional[str] = None
    killed: bool = False
    timeout: bool = False
    output_file: Optional[str] = None  # Path to saved output file

class CommandTimeout(Exception):
    pass

class Tools:
    def __init__(self):
        debug_print("Initializing Tools...")
        self.original_target = None  # Set in App.py after getting user input
        self.scans_dir = "scans"  # Directory to store scan results
        self.current_scan_dir = None  # Current scan directory for this session
        
        # Initialize RAG system
        self.rag = None
        if RAG_AVAILABLE:
            try:
                self.rag = ScanRAG(self.scans_dir)
                debug_print("RAG system initialized")
            except Exception as e:
                debug_print(f"Failed to initialize RAG system: {e}")
        
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
            'spiderfoot': 'OSINT automation',

            # Network Utilities
            'curl': 'Data transfer tool',
            'netstat': 'Network statistics',
            'iftop': 'Network bandwidth monitor'
        }

        self.installed_tools = self._check_installed_tools()
        self.wordlists = self._check_wordlists()
        debug_print("Tools initialization complete")

    def _check_wordlists(self) -> Dict[str, Optional[str]]:
        """Check for common wordlist locations and return available ones or None"""
        debug_print("Checking wordlists...")
        wordlist_paths = {
            # Common web content wordlists
            'dirb_common': '/usr/share/wordlists/dirb/common.txt',
            'dirb_big': '/usr/share/wordlists/dirb/big.txt',
            'seclists_web_common': '/usr/share/seclists/Discovery/Web-Content/common.txt',
            'seclists_web_big': '/usr/share/seclists/Discovery/Web-Content/big.txt',
            'seclists_web_directory': '/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt',
            
            # Password wordlists
            'rockyou': '/usr/share/wordlists/rockyou.txt',
            'seclists_darkweb': '/usr/share/seclists/Passwords/darkweb2017.txt',
            'seclists_common_passwords': '/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt',
            
            # Username wordlists
            'seclists_usernames': '/usr/share/seclists/Usernames/top-usernames-shortlist.txt',
            'seclists_names': '/usr/share/seclists/Usernames/Names/names.txt',
            
            # Other wordlists
            'fasttrack': '/usr/share/wordlists/fasttrack.txt',
            'wfuzz_common': '/usr/share/wfuzz/wordlist/general/common.txt',
            'wfuzz_big': '/usr/share/wfuzz/wordlist/general/big.txt'
        }

        available = {
            name: path if os.path.exists(path) else None
            for name, path in wordlist_paths.items()
        }
        
        # Create fallback wordlists if none are available
        self._create_fallback_wordlists(available)
        
        debug_print(f"Available wordlists: {[k for k, v in available.items() if v]}")
        return available

    def _create_fallback_wordlists(self, available: Dict[str, Optional[str]]):
        """Create fallback wordlists if none are available"""
        debug_print("Checking for fallback wordlists...")
        
        # Create wordlists directory if it doesn't exist
        wordlist_dir = os.path.join(os.path.dirname(__file__), '..', 'wordlists')
        os.makedirs(wordlist_dir, exist_ok=True)
        
        # Check if we need to create any fallback wordlists
        web_wordlists = ['dirb_common', 'seclists_web_common', 'seclists_web_directory']
        password_wordlists = ['rockyou', 'seclists_common_passwords']
        username_wordlists = ['seclists_usernames', 'seclists_names']
        
        # Create fallback web wordlist if none available
        if not any(available.get(name) for name in web_wordlists):
            fallback_web = os.path.join(wordlist_dir, 'web_common.txt')
            if not os.path.exists(fallback_web):
                debug_print("Creating fallback web wordlist...")
                self._create_web_wordlist(fallback_web)
            available['fallback_web'] = fallback_web
        
        # Create fallback password wordlist if none available
        if not any(available.get(name) for name in password_wordlists):
            fallback_passwords = os.path.join(wordlist_dir, 'passwords_common.txt')
            if not os.path.exists(fallback_passwords):
                debug_print("Creating fallback password wordlist...")
                self._create_password_wordlist(fallback_passwords)
            available['fallback_passwords'] = fallback_passwords
        
        # Create fallback username wordlist if none available
        if not any(available.get(name) for name in username_wordlists):
            fallback_usernames = os.path.join(wordlist_dir, 'usernames_common.txt')
            if not os.path.exists(fallback_usernames):
                debug_print("Creating fallback username wordlist...")
                self._create_username_wordlist(fallback_usernames)
            available['fallback_usernames'] = fallback_usernames

    def _create_web_wordlist(self, path: str):
        """Create a basic web content wordlist"""
        common_paths = [
            'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin', 'config',
            'backup', 'backups', 'db', 'database', 'sql', 'mysql', 'oracle',
            'api', 'rest', 'graphql', 'swagger', 'docs', 'documentation',
            'test', 'dev', 'development', 'staging', 'prod', 'production',
            'assets', 'static', 'css', 'js', 'images', 'uploads', 'files',
            'cgi-bin', 'bin', 'tmp', 'temp', 'cache', 'logs', 'log',
            'robots.txt', 'sitemap.xml', '.htaccess', '.htpasswd',
            'wp-config.php', 'config.php', 'settings.php', 'info.php',
            'phpinfo.php', 'test.php', 'shell.php', 'cmd.php'
        ]
        
        with open(path, 'w') as f:
            for item in common_paths:
                f.write(f"{item}\n")
        debug_print(f"Created web wordlist: {path}")

    def _create_password_wordlist(self, path: str):
        """Create a basic password wordlist"""
        common_passwords = [
            'password', '123456', '123456789', 'qwerty', 'abc123', 'password123',
            'admin', 'administrator', 'root', 'user', 'guest', 'test', 'demo',
            '12345678', '111111', '123123', 'admin123', 'user123', 'pass123',
            'password1', '1234567', '1234567890', 'qwerty123', 'abc123456',
            'password1234', 'admin1234', 'user1234', 'pass1234', 'test123',
            'demo123', 'guest123', 'root123', 'administrator123'
        ]
        
        with open(path, 'w') as f:
            for item in common_passwords:
                f.write(f"{item}\n")
        debug_print(f"Created password wordlist: {path}")

    def _create_username_wordlist(self, path: str):
        """Create a basic username wordlist"""
        common_usernames = [
            'admin', 'administrator', 'root', 'user', 'guest', 'test', 'demo',
            'webmaster', 'master', 'manager', 'operator', 'service', 'system',
            'support', 'help', 'info', 'contact', 'sales', 'marketing',
            'john', 'jane', 'bob', 'alice', 'dave', 'sarah', 'mike', 'lisa',
            'tom', 'jerry', 'harry', 'hermione', 'ron', 'neville', 'luna'
        ]
        
        with open(path, 'w') as f:
            for item in common_usernames:
                f.write(f"{item}\n")
        debug_print(f"Created username wordlist: {path}")

    def get_best_wordlist(self, wordlist_type: str) -> Optional[str]:
        """Get the best available wordlist for a specific type"""
        debug_print(f"Getting best wordlist for type: {wordlist_type}")
        
        if wordlist_type == 'web':
            # Priority order for web wordlists
            priorities = [
                'seclists_web_directory',
                'seclists_web_common', 
                'dirb_common',
                'fallback_web'
            ]
        elif wordlist_type == 'password':
            # Priority order for password wordlists
            priorities = [
                'rockyou',
                'seclists_common_passwords',
                'fallback_passwords'
            ]
        elif wordlist_type == 'username':
            # Priority order for username wordlists
            priorities = [
                'seclists_usernames',
                'seclists_names',
                'fallback_usernames'
            ]
        else:
            debug_print(f"Unknown wordlist type: {wordlist_type}")
            return None
        
        for priority in priorities:
            if priority in self.wordlists and self.wordlists[priority]:
                debug_print(f"Selected wordlist: {priority} -> {self.wordlists[priority]}")
                return self.wordlists[priority]
        
        debug_print(f"No wordlist available for type: {wordlist_type}")
        return None

    def _check_installed_tools(self) -> Dict[str, bool]:
        debug_print("Checking installed tools...")
        installed = {tool: shutil.which(tool) is not None for tool in self.required_tools}
        debug_print(f"Installed tools: {[k for k, v in installed.items() if v]}")
        return installed

    def get_installed_tools(self) -> List[str]:
        return [tool for tool, installed in self.installed_tools.items() if installed]

    def get_missing_tools(self) -> List[str]:
        return [tool for tool, installed in self.installed_tools.items() if not installed]

    def _determine_protocol(self, target: str) -> str:
        """Determine protocol from target URL or scan results"""
        # Check if target is a URL
        if target.startswith(('http://', 'https://')):
            return 'https' if target.startswith('https://') else 'http'
        
        # Check if target has a port
        if ':' in target:
            port = target.split(':')[1].split('/')[0]
            if port == '443':
                return 'https'
            elif port == '80':
                return 'http'
        
        # Default to http if no protocol specified
        return 'http'

    def _parse_url(self, target: str) -> Dict[str, str]:
        """Parse URL into components, handling various input formats"""
        result = {
            'protocol': None,
            'host': None,
            'port': None,
            'path': None,
            'original': target
        }
        
        # Handle protocol
        if '://' in target:
            result['protocol'], rest = target.split('://', 1)
        else:
            rest = target
        
        # Handle path
        if '/' in rest:
            host_port, result['path'] = rest.split('/', 1)
            result['path'] = '/' + result['path']  # Add leading slash back
        else:
            host_port = rest
        
        # Handle port
        if ':' in host_port:
            result['host'], result['port'] = host_port.split(':', 1)
            # Remove any path from port if present
            if '/' in result['port']:
                result['port'], _ = result['port'].split('/', 1)
        else:
            result['host'] = host_port
        
        return result

    def _get_host_port(self, target: str, include_port: bool = False) -> str:
        """Get host:port string for network tools"""
        url_parts = self._parse_url(target)
        if include_port and url_parts['port']:
            return f"{url_parts['host']}:{url_parts['port']}"
        return url_parts['host']

    def _get_full_url(self, target: str, protocol: str = None) -> str:
        """Get full URL from target, preserving port and path"""
        url_parts = self._parse_url(target)
        
        # If already a full URL, return as is
        if url_parts['protocol']:
            return target
        
        # Determine protocol if not provided
        if protocol is None:
            protocol = self._determine_protocol(target)
        
        # Build URL components
        url = f"{protocol}://{url_parts['host']}"
        
        # Add port if specified
        if url_parts['port']:
            url += f":{url_parts['port']}"
        else:
            # Add default port based on protocol
            url += ':443' if protocol == 'https' else ':80'
        
        # Add path if present
        if url_parts['path']:
            url += url_parts['path']
        
        return url

    def _get_target_info(self, target: str) -> Dict[str, str]:
        """Get target information including protocol, host, port, and path"""
        debug_print(f"Getting target info for: {target}")
        url_parts = self._parse_url(target)
        protocol = self._determine_protocol(target)
        info = {
            'url_parts': url_parts,
            'protocol': protocol,
            'host': url_parts['host'],
            'port': url_parts['port'],
            'path': url_parts['path'],
            'full_url': self._get_full_url(target, protocol)
        }
        debug_print(f"Target info: {info}")
        return info

    def _check_memory_usage(self) -> bool:
        """Check if memory usage is above threshold"""
        try:
            memory_percent = psutil.virtual_memory().percent / 100
            if memory_percent > MEMORY_THRESHOLD:
                debug_print(f"Memory usage high: {memory_percent:.1%}")
            return memory_percent > MEMORY_THRESHOLD
        except Exception as e:
            debug_print(f"Error checking memory usage: {e}")
            return False

    def _handle_command_timeout(self, process: subprocess.Popen, timeout: int):
        """Handle command timeout"""
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            debug_print(f"Command timed out after {timeout} seconds")
            # Try to terminate gracefully first
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # Force kill if still running
                debug_print("Force killing process...")
                process.kill()
            raise CommandTimeout(f"Command timed out after {timeout} seconds")

    def _monitor_process(self, process: subprocess.Popen, timeout: int) -> Tuple[bool, Optional[str]]:
        """Monitor process execution and handle memory issues"""
        start_time = time.time()
        killed = False
        error = None

        while process.poll() is None:
            # Check timeout
            if time.time() - start_time > timeout:
                debug_print("Command timeout reached")
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                killed = True
                error = f"Command timed out after {timeout} seconds"
                break

            # Check memory usage
            if self._check_memory_usage():
                debug_print("Memory threshold exceeded, terminating process")
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                killed = True
                error = "Process killed due to high memory usage"
                break

            # Sleep briefly to prevent high CPU usage
            time.sleep(0.1)

        return killed, error

    def execute_command(self, command: str, target: Optional[str] = None, args: Optional[List[str]] = None, tool_config: Optional[Dict] = None) -> CommandResult:
        try:
            debug_print(f"Executing command: {command}")
            debug_print(f"Target: {target}")
            debug_print(f"Args: {args}")
            debug_print(f"Tool config: {tool_config}")

            parts = command.strip().split()
            if not parts:
                return CommandResult("", False, "Empty command")

            tool_name = parts[0]
            if tool_name not in self.installed_tools or not self.installed_tools[tool_name]:
                return CommandResult("", False, f"Tool '{tool_name}' is not installed or not in PATH")

            target = self.original_target or target
            if not target:
                return CommandResult("", False, "No target specified")

            target = target.strip()
            target_info = self._get_target_info(target)
            cmd = [tool_name]

            # Tool-specific configurations
            if tool_name == 'nmap':
                cmd.extend(args or ['-sV', '-sC', '-p-', '--max-retries', '2', '--min-rate', '1000', '-T4'])
                cmd.append(target_info['host'])

            elif tool_name == 'nikto':
                cmd.extend(['-h', target_info['host']])
                if target_info['port']:
                    cmd.extend(['-p', target_info['port']])
                cmd.extend(['-maxtime', '5m', '-Tuning', '0123456789a', '-Format', 'txt'])
                if tool_config and 'nikto' in tool_config:
                    proto = tool_config['nikto'].get('protocol')
                    if proto == 'https':
                        cmd.append('-ssl')
                    elif proto == 'http':
                        cmd.append('-nossl')
                if args:
                    cmd.extend(args)

            elif tool_name == 'gobuster':
                wordlist = self.get_best_wordlist('web') or '/dev/null'
                cmd.extend(['dir', '-u', target_info['full_url'], '-w', wordlist, '-x', 'php,html', '-t', '50', '-k'])
                if args:
                    cmd.extend(args)

            elif tool_name == 'sqlmap':
                cmd.extend(['-u', target_info['full_url'], '--batch', '--random-agent', '--level', '2', '--risk', '2'])
                if args:
                    cmd.extend(args)

            elif tool_name == 'wpscan':
                cmd.extend(['--url', target_info['full_url'], '--enumerate', 'p,t,u', '--disable-tls-checks'])
                if args:
                    cmd.extend(args)

            elif tool_name == 'hydra':
                userlist = self.get_best_wordlist('username') or '/dev/null'
                passlist = self.get_best_wordlist('password') or '/dev/null'
                cmd.extend(['-L', userlist, '-P', passlist])
                cmd.append(target_info['host'])
                service = 'ssh'  # fallback
                if args:
                    cmd.extend(args)
                    for arg in args:
                        if arg in ['http', 'ftp', 'smtp', 'rdp', 'ssh']:
                            service = arg
                            break
                cmd.append(service)

            elif tool_name == 'nuclei':
                cmd.extend(['-u', target_info['full_url'], '-severity', 'medium,high,critical'])
                if args:
                    cmd.extend(args)

            elif tool_name == 'ffuf':
                wordlist = self.get_best_wordlist('web') or '/dev/null'
                cmd.extend(['-u', f"{target_info['full_url']}/FUZZ", '-w', wordlist, '-mc', '200,204,301,302,307,403'])
                if args:
                    cmd.extend(args)

            elif tool_name == 'wfuzz':
                wordlist = self.get_best_wordlist('web') or '/dev/null'
                cmd.extend(['-u', f"{target_info['full_url']}/FUZZ", '-w', wordlist, '--hc', '404', '--sc', '-t', '50'])
                if args:
                    cmd.extend(args)

            elif tool_name == 'dirb':
                wordlist = self.get_best_wordlist('web') or '/dev/null'
                cmd.extend([target_info['full_url'], wordlist])
                if args:
                    cmd.extend(args)

            elif tool_name == 'feroxbuster':
                wordlist = self.get_best_wordlist('web') or '/dev/null'
                cmd.extend(['-u', target_info['full_url'], '-w', wordlist, '--threads', '50', '--status-codes', '200,204,301,302,307,403', '--insecure'])
                if args:
                    cmd.extend(args)

            else:
                cmd.append(target_info['host'])
                if args:
                    cmd.extend(args)

            debug_print(f"Final command: {' '.join(cmd)}")
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, universal_newlines=True, preexec_fn=os.setsid)
            killed, error = self._monitor_process(process, COMMAND_TIMEOUT)

            output = []
            while True:
                line = process.stdout.readline()
                if line == '' and process.poll() is not None:
                    break
                if line:
                    output.append(line.strip())
                    debug_print(f"Command output: {line.strip()}")

            return_code = process.poll()
            if killed:
                output_file = self._save_command_output(tool_name, target, '\n'.join(output), False, error)
                return CommandResult('\n'.join(output), False, error, killed=True, output_file=output_file)
            elif return_code == 0:
                output_file = self._save_command_output(tool_name, target, '\n'.join(output), True)
                return CommandResult('\n'.join(output), True, output_file=output_file)
            else:
                error = process.stderr.read()
                output_file = self._save_command_output(tool_name, target, "", False, error.strip())
                return CommandResult("", False, error.strip(), output_file=output_file)

        except CommandTimeout as e:
            output_file = self._save_command_output(tool_name, target, "", False, str(e))
            return CommandResult("", False, str(e), timeout=True, output_file=output_file)
        except Exception as e:
            output_file = self._save_command_output(tool_name, target, "", False, str(e))
            return CommandResult("", False, str(e), output_file=output_file)


    def report_vulnerability(self, type: str, severity: str, description: str, exploitation: Optional[Dict] = None, references: Optional[List[str]] = None) -> Dict:
        """Report a discovered vulnerability
        
        Args:
            type: Type of vulnerability
            severity: Severity level (low/medium/high/critical)
            description: Description of the vulnerability
            exploitation: Optional exploitation details
                - method: Method to exploit the vulnerability
                - code: Example exploitation code
                - requirements: Requirements for exploitation
            references: Optional references (CVEs, guides, etc.)
            
        Returns:
            Dict containing vulnerability information
        """
        debug_print(f"Reporting vulnerability: {type}")
        debug_print(f"Severity: {severity}")
        debug_print(f"Description: {description}")
        
        if exploitation:
            debug_print(f"Exploitation method: {exploitation.get('method')}")
            debug_print(f"Exploitation code: {exploitation.get('code')}")
            debug_print(f"Requirements: {exploitation.get('requirements')}")
        
        if references:
            debug_print(f"References: {references}")
        
        return {
            "type": type,
            "severity": severity,
            "description": description,
            "exploitation": exploitation,
            "references": references
        }

    def get_tools_list(self) -> Dict[str, str]:
        """Get list of available tools and their descriptions"""
        return self.required_tools

    def get_wordlists(self) -> Dict[str, Optional[str]]:
        """Get available wordlists"""
        return self.wordlists

    def initialize_scan_directory(self, target: str) -> str:
        """Initialize scan directory for a new target session"""
        try:
            # Create scans directory if it doesn't exist
            os.makedirs(self.scans_dir, exist_ok=True)
            
            # Create target directory with timestamp
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            target_clean = re.sub(r'[^\w\-_.]', '_', target)  # Clean target name for directory
            self.current_scan_dir = os.path.join(self.scans_dir, f"{target_clean}_{timestamp}")
            os.makedirs(self.current_scan_dir, exist_ok=True)
            
            debug_print(f"Initialized scan directory: {self.current_scan_dir}")
            return self.current_scan_dir
            
        except Exception as e:
            debug_print(f"Error initializing scan directory: {e}")
            return None

    def _save_command_output(self, tool_name: str, target: str, output: str, success: bool, error: str = None) -> Optional[str]:
        """Save command output to a file in the scans directory"""
        try:
            # Use existing scan directory if available, otherwise create one
            if self.current_scan_dir is None:
                self.initialize_scan_directory(target)
            
            if self.current_scan_dir is None:
                debug_print("Failed to create scan directory")
                return None
            
            # Create filename with tool name
            filename = f"{tool_name}.txt"
            filepath = os.path.join(self.current_scan_dir, filename)
            
            # Prepare content to save
            content = f"Command: {tool_name}\n"
            content += f"Target: {target}\n"
            content += f"Timestamp: {datetime.datetime.now().isoformat()}\n"
            content += f"Success: {success}\n"
            if error:
                content += f"Error: {error}\n"
            content += f"{'='*50}\n\n"
            
            if success:
                content += output
            else:
                content += f"Command failed: {error}"
            
            # Write to file
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            
            debug_print(f"Saved command output to: {filepath}")
            
            # Update RAG index if available
            if self.rag:
                try:
                    self.rag.refresh_index()
                    debug_print("RAG index updated")
                except Exception as e:
                    debug_print(f"Error updating RAG index: {e}")
            
            return filepath
            
        except Exception as e:
            debug_print(f"Error saving command output: {e}")
            return None

    # RAG-related methods
    def search_scan_results(self, query: str, top_k: int = 5, target_filter: Optional[str] = None) -> List[SearchResult]:
        """Search through scan results using RAG"""
        if not self.rag:
            debug_print("RAG system not available")
            return []
        
        try:
            results = self.rag.search(query, top_k, target_filter)
            debug_print(f"Found {len(results)} results for query: {query}")
            return results
        except Exception as e:
            debug_print(f"Error searching scan results: {e}")
            return []
    
    def get_scan_summary(self) -> Dict[str, Any]:
        """Get a summary of all scan results"""
        if not self.rag:
            return {"message": "RAG system not available"}
        
        try:
            return self.rag.get_summary()
        except Exception as e:
            debug_print(f"Error getting scan summary: {e}")
            return {"error": str(e)}
    
    def get_available_targets(self) -> List[str]:
        """Get list of all targets with scan results"""
        if not self.rag:
            return []
        
        try:
            return self.rag.get_targets()
        except Exception as e:
            debug_print(f"Error getting targets: {e}")
            return []
    
    def get_available_tools(self) -> List[str]:
        """Get list of all tools used in scan results"""
        if not self.rag:
            return []
        
        try:
            return self.rag.get_tools()
        except Exception as e:
            debug_print(f"Error getting tools: {e}")
            return []
    
    def get_target_scan_results(self, target: str) -> List[Dict[str, Any]]:
        """Get all scan results for a specific target"""
        if not self.rag:
            return []
        
        try:
            documents = self.rag.get_documents_by_target(target)
            results = []
            for doc in documents:
                results.append({
                    "tool": doc.tool,
                    "timestamp": doc.timestamp,
                    "success": doc.metadata.get("success", True),
                    "file_path": doc.file_path,
                    "content_preview": doc.content[:500] + "..." if len(doc.content) > 500 else doc.content
                })
            return results
        except Exception as e:
            debug_print(f"Error getting target scan results: {e}")
            return []
    
    def get_tool_scan_results(self, tool: str) -> List[Dict[str, Any]]:
        """Get all scan results for a specific tool"""
        if not self.rag:
            return []
        
        try:
            documents = self.rag.get_documents_by_tool(tool)
            results = []
            for doc in documents:
                results.append({
                    "target": doc.target,
                    "timestamp": doc.timestamp,
                    "success": doc.metadata.get("success", True),
                    "file_path": doc.file_path,
                    "content_preview": doc.content[:500] + "..." if len(doc.content) > 500 else doc.content
                })
            return results
        except Exception as e:
            debug_print(f"Error getting tool scan results: {e}")
            return []
    
    def refresh_rag_index(self):
        """Manually refresh the RAG index"""
        if not self.rag:
            debug_print("RAG system not available")
            return
        
        try:
            self.rag.refresh_index()
            debug_print("RAG index refreshed successfully")
        except Exception as e:
            debug_print(f"Error refreshing RAG index: {e}")
    
    def is_rag_available(self) -> bool:
        """Check if RAG system is available"""
        return self.rag is not None
