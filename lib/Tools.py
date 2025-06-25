import subprocess
import os
import re
import shutil
import signal
import psutil
import time
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

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

class CommandTimeout(Exception):
    pass

class Tools:
    def __init__(self):
        debug_print("Initializing Tools...")
        self.original_target = None  # Set in App.py after getting user input
        self.required_tools = {
            # Network Scanning & Enumeration
            'nmap': 'Network mapper',
            'masscan': 'Mass IP port scanner',
            'netcat': 'Network utility',
            'nbtscan': 'NetBIOS scanner',
            'rustscan': 'Fast port scanner',
            'unicornscan': 'Asynchronous scanner',

            # Web Testing
            'nikto': 'Web server scanner',
            'dirb': 'Web content scanner',
            'gobuster': 'Directory/file enumeration',
            'sqlmap': 'SQL injection testing',
            'wpscan': 'WordPress security scanner',
            'whatweb': 'Web technology identifier',
            'wfuzz': 'Web application fuzzer',
            'feroxbuster': 'Fast content discovery',
            'httpx': 'HTTP toolkit',
            'ffuf': 'Web fuzzer',

            # DNS Tools
            'dig': 'DNS lookup utility',
            'whois': 'WHOIS client',
            'dnsrecon': 'DNS enumeration tool',
            'dnsenum': 'DNS enumeration tool',
            'fierce': 'DNS reconnaissance tool',
            'sublist3r': 'Subdomain enumeration',

            # Vulnerability Assessment
            'nuclei': 'Vulnerability scanner',
            'vulners': 'Vulnerability scanner',
            'trivy': 'Vulnerability scanner',

            # Password Testing
            'hydra': 'Password cracking tool',
            'john': 'Password cracking tool',
            'hashcat': 'Password recovery tool',
            'cewl': 'Custom word list generator',
            'crunch': 'Wordlist generator',

            # Exploitation
            'metasploit-framework': 'Exploitation framework',
            'exploitdb': 'Exploit database',
            'searchsploit': 'Exploit database search tool',

            # Network Analysis
            'tcpdump': 'Packet analyzer',
            'wireshark': 'Network protocol analyzer',
            'tshark': 'CLI version of Wireshark',

            # SSL/TLS Testing
            'sslyze': 'SSL/TLS analyzer',
            'testssl.sh': 'SSL/TLS testing tool',
            'sslscan': 'SSL/TLS scanner',

            # OSINT
            'theharvester': 'Email/domain reconnaissance',
            'recon-ng': 'Reconnaissance framework',
            'maltego': 'OSINT tool',
            'spiderfoot': 'OSINT automation',

            # Network Utilities
            'curl': 'Data transfer tool',
            'wget': 'Web downloader',
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
        """Execute a security testing command
        
        Args:
            command: The command to execute
            target: The target host/IP/URL
            args: Optional command arguments
            tool_config: Optional tool-specific configuration
            
        Returns:
            CommandResult with output and status
        """
        try:
            debug_print(f"Executing command: {command}")
            debug_print(f"Target: {target}")
            debug_print(f"Args: {args}")
            debug_print(f"Tool config: {tool_config}")

            # Split command into tool and arguments
            parts = command.strip().split()
            if not parts:
                debug_print("Empty command")
                return CommandResult("", False, "Empty command")

            tool_name = parts[0]
            if tool_name not in self.installed_tools or not self.installed_tools[tool_name]:
                debug_print(f"Tool not installed: {tool_name}")
                return CommandResult("", False, f"Tool '{tool_name}' is not installed or not in PATH")

            # Override model-passed target with original user input if available
            target = self.original_target or target
            if not target:
                debug_print("No target specified")
                return CommandResult("", False, "No target specified")
            
            target = target.strip()
            
            # Get target information
            target_info = self._get_target_info(target)
            debug_print(f"Target info: {target_info}")

            cmd = [tool_name]

            # Tool-specific logic
            if tool_name == 'nmap':
                debug_print("Configuring nmap command...")
                # Use more conservative nmap settings
                if not args:
                    args = ['-sV', '-sC', '-p-', '--max-retries', '2', '--min-rate', '1000']
                elif '-p' not in ' '.join(args):
                    args.extend(['-p-', '--max-retries', '2', '--min-rate', '1000'])
                cmd.extend(args)
                cmd.append(target_info['host'])

            elif tool_name == 'nikto':
                debug_print("Configuring nikto command...")
                # Always include base parameters
                cmd.extend(['-h', target_info['full_url'], '-maxtime', '5m', '-Tuning', '123457890', '-Format', 'txt', '-n'])
                # Add protocol and port configuration if available
                if tool_config and 'nikto' in tool_config:
                    if 'protocol' in tool_config['nikto']:
                        cmd.append('-ssl' if tool_config['nikto']['protocol'] == 'https' else '-nossl')
                    if 'port' in tool_config['nikto']:
                        cmd.extend(['-p', tool_config['nikto']['port']])
                # Add any additional args after base parameters
                if args:
                    cmd.extend(args)

            elif tool_name == 'gobuster':
                debug_print("Configuring gobuster command...")
                wordlist = self.get_best_wordlist('web')
                cmd.extend(args or ['dir', '-u', target_info['full_url'], '-w', wordlist or '/dev/null'])

            elif tool_name == 'sqlmap':
                debug_print("Configuring sqlmap command...")
                cmd.extend(args or ['-u', target_info['full_url'], '--batch', '--random-agent'])

            elif tool_name == 'wpscan':
                debug_print("Configuring wpscan command...")
                cmd.extend(args or ['--url', target_info['full_url'], '--enumerate', 'p,t,u'])

            elif tool_name == 'masscan':
                debug_print("Configuring masscan command...")
                if not args:
                    args = ['-p-', '--rate=1000']  # Always scan all ports
                cmd.extend(args)
                cmd.append(target_info['host'])

            elif tool_name == 'hydra':
                debug_print("Configuring hydra command...")
                password_wordlist = self.get_best_wordlist('password')
                username_wordlist = self.get_best_wordlist('username')
                cmd.extend(args or ['-L', username_wordlist or '/dev/null', '-P', password_wordlist or '/dev/null'])
                cmd.append(target)

            elif tool_name == 'nuclei':
                debug_print("Configuring nuclei command...")
                if args:
                    cmd.extend(args)
                cmd.append(target_info['full_url'])

            elif tool_name == 'ffuf':
                debug_print("Configuring ffuf command...")
                wordlist = self.get_best_wordlist('web')
                cmd.extend(args or ['-u', f"{target_info['full_url']}/FUZZ", '-w', wordlist or '/dev/null'])

            elif tool_name == 'wfuzz':
                debug_print("Configuring wfuzz command...")
                wordlist = self.get_best_wordlist('web')
                cmd.extend(args or ['-u', f"{target_info['full_url']}/FUZZ", '-w', wordlist or '/dev/null'])

            elif tool_name == 'dirb':
                debug_print("Configuring dirb command...")
                wordlist = self.get_best_wordlist('web')
                cmd.extend(args or [target_info['full_url'], wordlist or '/dev/null'])

            elif tool_name == 'feroxbuster':
                debug_print("Configuring feroxbuster command...")
                wordlist = self.get_best_wordlist('web')
                cmd.extend(args or ['-u', target_info['full_url'], '-w', wordlist or '/dev/null'])

            else:
                debug_print(f"Using default command configuration for {tool_name}")
                cmd.append(target_info['host'])

            # Start the subprocess with a process group
            debug_print(f"Final command: {' '.join(cmd)}")
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True,
                preexec_fn=os.setsid
            )

            # Monitor process execution
            killed, error = self._monitor_process(process, COMMAND_TIMEOUT)

            # Capture output
            output = []
            while True:
                line = process.stdout.readline()
                if line == '' and process.poll() is not None:
                    break
                if line:
                    output.append(line.strip())
                    debug_print(f"Command output: {line.strip()}")

            # Get return code
            return_code = process.poll()
            debug_print(f"Command completed with return code: {return_code}")

            # Handle command completion
            if killed:
                return CommandResult('\n'.join(output), False, error, killed=True)
            elif return_code == 0:
                debug_print("Command executed successfully")
                return CommandResult('\n'.join(output), True)
            else:
                error = process.stderr.read()
                debug_print(f"Command failed with error: {error}")
                return CommandResult("", False, error.strip())

        except CommandTimeout as e:
            debug_print(f"Command timeout: {e}")
            return CommandResult("", False, str(e), timeout=True)
        except Exception as e:
            debug_print(f"Error executing command: {e}")
            return CommandResult("", False, str(e))

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
