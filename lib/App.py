from lib.Chat import Chat
from lib.Model import Model
from lib.Tools import Tools
import sys
import re
from typing import Optional
import os

# Load environment variables
DEBUG = os.getenv('DEBUG', '0') == '1'
COMMAND_TIMEOUT = int(os.getenv('COMMAND_TIMEOUT', '300'))  # 5 minutes default timeout

def debug_print(*args, **kwargs):
    """Print debug messages only if DEBUG is enabled"""
    if DEBUG:
        print("[DEBUG]", *args, **kwargs)

class App:
    def __init__(self):
        debug_print("Initializing App...")
        banner = """
 ░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓████████▓▒░▒▓███████▓▒░▒▓████████▓▒░▒▓███████▓▒░░▒▓████████▓▒░▒▓███████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓████████▓▒░▒▓█▓▒▒▓███▓▒░▒▓██████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓███████▓▒░ 
 by: 7h3 R3v3n4n7 (CyberDeathSec)
"""
        print(banner)
        
        # Initialize components
        debug_print("Initializing Tools...")
        self.tools = Tools()
        
        # Initialize Model
        debug_print("Initializing Model...")
        self.model = Model(target=None, tools=self.tools)
        
        # Load model
        debug_print("Loading model...")
        load_response = self.model.load_model()
        if "Error" in load_response:
            debug_print(f"Error loading model: {load_response}")
            print(f"Error loading model: {load_response}")
            sys.exit(1)
            
        # Initialize Chat with the model and tools
        debug_print("Initializing Chat...")
        self.chat = Chat(self.model, self.tools)
        
        # Print welcome message
        self.chat.print_welcome()
        
        # Get and validate target
        debug_print("Getting target...")
        self.target = self.get_target()
        self.tools.original_target = self.target
        debug_print("App initialization complete")

    def validate_target(self, target: str) -> bool:
        """Validate if the target is a valid hostname, IP address, or URL"""
        debug_print(f"Validating target: {target}")
        # URL validation
        url_pattern = r'^(https?://)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*|(\d{1,3}\.){3}\d{1,3})(:\d+)?(/[^\s]*)?$'
        if re.match(url_pattern, target):
            # If it's a URL, extract the host part for further validation
            host = self._extract_host(target)
            if not host:
                debug_print("Invalid host extracted from URL")
                return False
            
            # If host is an IP address, validate octets
            if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', host):
                octets = host.split('.')
                valid = all(0 <= int(octet) <= 255 for octet in octets)
                debug_print(f"IP address validation: {'valid' if valid else 'invalid'}")
                return valid
            
            # If host is a hostname, validate it
            hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
            valid = bool(re.match(hostname_pattern, host))
            debug_print(f"Hostname validation: {'valid' if valid else 'invalid'}")
            return valid
        
        debug_print("Target does not match URL pattern")
        return False

    def _extract_host(self, target: str) -> Optional[str]:
        """Extract host from URL or return the original string if not a URL"""
        debug_print(f"Extracting host from: {target}")
        # Remove protocol if present
        if '://' in target:
            target = target.split('://', 1)[1]
        
        # Remove path if present
        if '/' in target:
            target = target.split('/', 1)[0]
        
        # Remove port if present
        if ':' in target:
            target = target.split(':', 1)[0]
        
        debug_print(f"Extracted host: {target}")
        return target
    
    def get_target(self) -> str:
        """Prompt user for target hostname/IP/URL and validate input"""
        while True:
            try:
                target = input("\nEnter target hostname, IP address, or URL: ").strip()
                if self.validate_target(target):
                    debug_print(f"Valid target: {target}")
                    print("\nRunning initial port scan...")
                    # Use more conservative nmap settings
                    args = ['-sV', '-sC', '-p-', '--max-retries', '2', '--min-rate', '1000']
                    
                    debug_print("Executing initial nmap scan...")
                    result = self.tools.execute_command("nmap", target, args)
                    
                    if result.killed:
                        print(f"\nWarning: Initial scan was killed due to resource constraints.")
                        print("Continuing with limited information...")
                        self.initial_scan = None
                    elif result.timeout:
                        print(f"\nWarning: Initial scan timed out after {COMMAND_TIMEOUT} seconds.")
                        print("Continuing with limited information...")
                        self.initial_scan = None
                    elif result.success:
                        print("\nPort scan completed. Results:")
                        print(result.output)  # Print the scan results
                        self.initial_scan = result.output
                        debug_print("Initial scan completed successfully")
                        print("\nAnalyzing results... Please wait.")
                    else:
                        print(f"\nWarning: Initial scan failed: {result.error}")
                        debug_print(f"Initial scan failed: {result.error}")
                        self.initial_scan = None
                    return target
                print("Invalid target. Please enter a valid hostname, IP address, or URL.")
                debug_print("Invalid target entered")
            except (KeyboardInterrupt, EOFError):
                print("\nExiting...")
                debug_print("User interrupted target input")
                sys.exit(0)

    def run(self):
        """Run the application"""
        debug_print("Starting application...")
        # Start chat session with target and initial scan results
        initial_prompt = f"Target: {self.target}\n"
        if self.initial_scan:
            initial_prompt += f"Initial scan results:\n{self.initial_scan}\n\nAnalyze these results and suggest next steps."
        
        debug_print("Starting chat session...")
        response = self.chat.start_chat(initial_prompt)
        print(f"\nAssistant: {response}")
        
        # Main chat loop
        while True:
            try:
                user_input = input("\nYou: ").strip()
                
                if user_input.lower() in ['exit', 'quit']:
                    debug_print("User requested exit")
                    print("\nEnding chat session...")
                    break
                elif user_input.lower() == 'clear':
                    debug_print("User requested screen clear")
                    print("\033[H\033[J", end="")
                    continue
                elif not user_input:
                    continue
                
                debug_print(f"Processing user input: {user_input}")
                response = self.chat.handle_user_input(user_input, self.target)
                print(f"\nAssistant: {response}")
                
            except KeyboardInterrupt:
                debug_print("User interrupted chat")
                print("\n\nGoodbye!")
                break
            except Exception as e:
                debug_print(f"Error in chat loop: {e}")
                print(f"\nAn error occurred: {str(e)}")
                break