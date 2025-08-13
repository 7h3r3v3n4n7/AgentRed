from lib.Chat import Chat
from lib.Model import Model
from lib.Tools import Tools
from lib.Agents import AgentManager
import sys
import re
from typing import Optional
import os
import asyncio
from lib.Exporter import export_alpaca_data
from lib.config import Config
from lib.logging_utils import debug_print

# Load environment variables
COMMAND_TIMEOUT = int(os.getenv('COMMAND_TIMEOUT', '300'))  # 5 minutes default timeout

class App:
    def __init__(self):
        self.config = Config()
        debug_print("Initializing App...")
        # Set DEBUG environment variable if not set
        if 'DEBUG' not in os.environ:
            os.environ['DEBUG'] = '1'
            debug_print("DEBUG mode enabled")
            
        banner = """
▄▖      ▗ ▄▖   ▌
▌▌▛▌█▌▛▌▜▘▙▘█▌▛▌
▛▌▙▌▙▖▌▌▐▖▌▌▙▖▙▌
  ▄▌            

 by: 7h3 R3v3n4n7 (CyberDeathSec)
"""
        print(banner)
        
        # Initialize components
        debug_print("Initializing Tools...")
        self.tools = Tools(config=self.config)

        # Initialize Model
        debug_print("Initializing Model...")
        self.model = Model(target=None, tools=self.tools, config=self.config)
        
        # Load model
        debug_print("Loading model...")
        load_response = self.model.load_model()
        if "Error" in load_response:
            debug_print(f"Error loading model: {load_response}")
            print(f"Error loading model: {load_response}")
            sys.exit(1)

        # Initialize Agent Manager
        debug_print("Initializing Agent Manager...")
        self.agent_manager = AgentManager(self.tools, self.model, config=self.config)

        # --- Alpaca Export Opt-In ---
        self.export_opt_in = False
        self.export_server_url = self.config.EXPORT_SERVER_URL
        opt_env = os.getenv("EXPORT_ALPACA_DATA")
        if opt_env is not None:
            self.export_opt_in = opt_env == "1"
        else:
            print("\nWould you like to help improve the model by sending anonymized scan/learning data to the project server?")
            print("This is optional and can be disabled at any time.")
            choice = input("Opt in? (y/n): ").strip().lower()
            self.export_opt_in = choice == "y"
        if self.export_opt_in:
            print(f"\n[INFO] Alpaca dataset export is ENABLED. Data will be sent to: {self.export_server_url}")
        else:
            print("[INFO] Alpaca dataset export is DISABLED.")

        # Get execution mode preference
        self.execution_mode = self._get_execution_mode()
        
        # Initialize Chat with the model and tools (for interactive mode)
        if self.execution_mode == "chat":
            debug_print("Initializing Chat...")
            self.chat = Chat(self.model, self.tools, interactive_mode=True)
            self.chat.print_welcome()
        
        # Get and validate target
        debug_print("Getting target...")
        self.target = asyncio.run(self.get_target())
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
                    # Update model with target information
                    self.model.target = target
                    self.model.system_prompt = self.model._build_system_prompt()
                    debug_print("Updated model with target information")
                    print("\nRunning initial port scan...")
                    # Initialize scan directory for this target session
                    self.tools.initialize_scan_directory(target)
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

    def _get_execution_mode(self) -> str:
        """Get user preference for execution mode"""
        print("\nSelect execution mode:")
        print("1. Agent-based - Automated multi-agent penetration testing (Recommended)")
        print("2. Chat-based - Interactive chat with manual approval")
        
        while True:
            try:
                choice = input("\nEnter your choice (1 or 2): ").strip()
                if choice == '1':
                    return "agents"
                elif choice == '2':
                    return "chat"
                else:
                    print("Please enter 1 or 2.")
            except (KeyboardInterrupt, EOFError):
                print("\nExiting...")
                sys.exit(0)

    def maybe_export_alpaca(self):
        if self.export_opt_in:
            try:
                export_alpaca_data(self.agent_manager, self.tools.rag, self.export_server_url)
            except Exception as e:
                print(f"[WARN] Failed to export Alpaca dataset: {e}")

    async def run_agent_mode(self):
        """Run the application in agent mode"""
        debug_print("Starting agent-based testing...")
        
        print(f"\n🤖 Starting automated penetration testing with agents...")
        print(f"Target: {self.target}")
        
        # Run agent-based testing
        results = await self.agent_manager.run_agent_testing(self.target, self.initial_scan)
        
        # Display results
        self._display_agent_results(results)
        
        print(f"\n✅ Agent-based penetration testing completed for target: {self.target}")
        print("All agents have completed their tasks and provided findings.")
        self.maybe_export_alpaca()

    def _display_agent_results(self, results):
        """Display results from all agents with enhanced learning insights"""
        print(f"\n📊 INTELLIGENT AGENT TESTING RESULTS")
        print("=" * 60)
        
        # Group results by agent type
        agent_results = {}
        for result in results:
            agent_type = result.agent_type.value
            if agent_type not in agent_results:
                agent_results[agent_type] = []
            agent_results[agent_type].append(result)
        
        # Display results for each agent type
        for agent_type, agent_results_list in agent_results.items():
            print(f"\n🔍 {agent_type.upper().replace('_', ' ')} AGENT")
            print("-" * 40)
            
            for result in agent_results_list:
                status = "✅" if result.success else "❌"
                print(f"{status} Task: {result.task_id}")
                print(f"   Target: {result.target}")
                
                # Display strategy and learning insights
                if 'strategy' in result.metadata:
                    print(f"   Strategy: {result.metadata['strategy']}")
                if 'learning_insights' in result.metadata and result.metadata['learning_insights']:
                    print(f"   Learning: {result.metadata['learning_insights']}")
                if 'confidence' in result.metadata:
                    confidence_emoji = {
                        'high': '🟢',
                        'medium': '🟡',
                        'low': '🔴'
                    }.get(result.metadata['confidence'], '⚪')
                    print(f"   Confidence: {confidence_emoji} {result.metadata['confidence']}")
                
                # Display findings with confidence
                if result.findings:
                    print(f"   Findings ({len(result.findings)}):")
                    for finding in result.findings:
                        severity_emoji = {
                            'critical': '🔴',
                            'high': '🟠',
                            'medium': '🟡',
                            'low': '🟢'
                        }.get(finding.get('severity', 'low'), '⚪')
                        
                        confidence = finding.get('confidence', 'medium')
                        confidence_emoji = {
                            'high': '🟢',
                            'medium': '🟡',
                            'low': '🔴'
                        }.get(confidence, '⚪')
                        
                        print(f"   {severity_emoji} {finding.get('type', 'Unknown')}: {finding.get('description', 'No description')} {confidence_emoji}")
                
                # Display next tasks with reasoning
                if result.next_tasks:
                    print(f"   Next tasks ({len(result.next_tasks)}):")
                    for task in result.next_tasks:
                        reasoning = task.parameters.get('reasoning', 'No reasoning provided')
                        print(f"   - {task.description}")
                        print(f"     Reasoning: {reasoning}")
        
        # Display overall findings summary
        findings = self.agent_manager.get_findings_summary()
        if findings:
            print(f"\n📋 OVERALL FINDINGS SUMMARY")
            print("-" * 40)
            
            # Group by severity
            severity_groups = {'critical': [], 'high': [], 'medium': [], 'low': []}
            for finding in findings:
                severity = finding.get('severity', 'low')
                severity_groups[severity].append(finding)
            
            for severity in ['critical', 'high', 'medium', 'low']:
                if severity_groups[severity]:
                    severity_emoji = {
                        'critical': '🔴',
                        'high': '🟠',
                        'medium': '🟡',
                        'low': '🟢'
                    }[severity]
                    
                    print(f"\n{severity_emoji} {severity.upper()} SEVERITY ({len(severity_groups[severity])} findings):")
                    for finding in severity_groups[severity]:
                        confidence = finding.get('confidence', 'medium')
                        confidence_emoji = {
                            'high': '🟢',
                            'medium': '🟡',
                            'low': '🔴'
                        }.get(confidence, '⚪')
                        print(f"  - {finding.get('type', 'Unknown')}: {finding.get('description', 'No description')} {confidence_emoji}")
        
        # Display learning summary
        self._display_learning_summary()

        # Display error summary
        errors = []
        for agent_type, agent_results_list in agent_results.items():
            for result in agent_results_list:
                if not result.success:
                    error_msg = result.metadata.get('error') or result.output or 'Unknown error'
                    errors.append({
                        'task_id': result.task_id,
                        'agent_type': agent_type,
                        'error': error_msg
                    })
        if errors:
            print(f"\n❗ ERROR SUMMARY")
            print("-" * 40)
            for err in errors:
                print(f"❌ Task: {err['task_id']} | Agent: {err['agent_type']}\n   Error: {err['error']}")
    
    def _display_learning_summary(self):
        """Display learning insights from all agents"""
        print(f"\n🧠 AI LEARNING SUMMARY")
        print("-" * 40)
        
        learning_summary = self.agent_manager.get_learning_summary()
        
        # Overall insights
        overall = learning_summary['overall_insights']
        print(f"📈 Overall Performance:")
        print(f"   Success Rate: {overall['success_rate']:.2%}")
        print(f"   Successful Techniques: {overall['total_successful_techniques']}")
        print(f"   Failed Techniques: {overall['total_failed_techniques']}")
        print(f"   Target Types Learned: {len(overall['target_types_learned'])}")
        
        # Agent-specific insights
        print(f"\n🤖 Agent Learning:")
        for agent_type, agent_summary in learning_summary['agents'].items():
            print(f"   {agent_type.upper()}:")
            print(f"     Target Types: {len(agent_summary['target_types_learned'])}")
            print(f"     Successful Techniques: {agent_summary['total_successful_techniques']}")
            print(f"     Most Effective Tools: {len(agent_summary['most_effective_tools'])}")
        
        # Coordinator insights
        if learning_summary['coordinator']:
            coord = learning_summary['coordinator']
            print(f"\n🎯 Coordinator Learning:")
            print(f"   Target Types Coordinated: {len(coord['target_types_coordinated'])}")
            print(f"   Strategies Learned: {coord['total_strategies_learned']}")
            print(f"   Best Strategies:")
            for target_type, strategy in coord['best_strategies'].items():
                print(f"     {target_type}: {strategy['agent_sequence']} (Success: {strategy['success_rate']:.2%})")

    def run_chat_mode(self):
        """Run the application in chat mode"""
        debug_print("Starting chat-based testing...")
        
        # Start chat session with target and initial scan results
        initial_prompt = f"Target: {self.target}\n"
        if self.initial_scan:
            initial_prompt += f"Initial scan results:\n{self.initial_scan}\n\nAnalyze these results and suggest next steps."
        
        debug_print("Starting chat session...")
        response = self.chat.start_chat(initial_prompt)
        
        # Interactive mode - show input prompt and wait for user input
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
                
            except KeyboardInterrupt:
                debug_print("User interrupted chat")
                print("\n\nGoodbye!")
                break
            except Exception as e:
                debug_print(f"Error in chat loop: {e}")
                print(f"\nAn error occurred: {str(e)}")
                break
        self.maybe_export_alpaca()

    def run(self):
        """Run the application based on selected mode"""
        debug_print("Starting application...")
        
        if self.execution_mode == "agents":
            # Run in agent mode
            asyncio.run(self.run_agent_mode())
        elif self.execution_mode == "chat":
            # Run in chat mode
            self.run_chat_mode()
        else:
            print(f"Unknown execution mode: {self.execution_mode}")
            sys.exit(1)
