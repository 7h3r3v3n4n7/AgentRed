import os
import json
from lib.Tools import Tools, CommandResult
from typing import Tuple, List, Dict, Optional
from .Model import Model
import re

class Chat:
    def __init__(self, model: Model, tools: Tools, interactive_mode: bool = False):
        """Initialize Chat with a model instance and tools"""
        if model is None:
            raise ValueError("Model instance is required")
        self.model = model
        self.tools = tools
        self.chat_history = []
        self.command_history = []
        self.interactive_mode = interactive_mode

    def _check_for_vulnerability(self, data):
        """Checks if the 'vulnerability' key is present in the JSON data and prints it."""
        if "vulnerability" in data:
            print(f"\n!!! VULNERABILITY DETECTED !!!\n{data['vulnerability']}\n")

    def _get_user_command_choice(self, commands: List[str]) -> Optional[str]:
        """Get user's choice of command to execute"""
        if not commands:
            return None

        print("\nAvailable commands:")
        for i, cmd in enumerate(commands, 1):
            print(f"{i}. {cmd}")

        while True:
            try:
                choice = input("\nEnter command number to execute (or 'q' to quit): ").strip()
                if choice.lower() == 'q':
                    return None
                
                idx = int(choice) - 1
                if 0 <= idx < len(commands):
                    return commands[idx]
                print("Invalid choice. Please try again.")
            except ValueError:
                print("Please enter a valid number.")

    def _display_response(self, response: str) -> str:
        """Display the response in a user-friendly format and return the parsed data"""
        try:
            data = json.loads(response)
            
            # Display the response text
            if "response" in data:
                print(f"\n📋 Analysis: {data['response']}")
            
            # Display the command if present (always as suggested, not executing)
            if "command" in data and data["command"]:
                print(f"\n🔧 Suggested Command: {data['command']}")
            
            return data
        except json.JSONDecodeError:
            print(f"\n⚠️  Warning: Could not parse response as JSON")
            print(f"Raw response: {response}")
            return {}

    def _handle_rag_query(self, user_input: str) -> bool:
        """Handle RAG-related queries and return True if handled"""
        input_lower = user_input.lower()
        
        # Check for RAG-specific commands
        if input_lower.startswith('search ') or input_lower.startswith('find '):
            query = user_input[6:] if input_lower.startswith('search ') else user_input[5:]
            self._search_scan_results(query)
            return True
        
        elif input_lower.startswith('summary') or input_lower == 'scan summary':
            self._show_scan_summary()
            return True
        
        elif input_lower.startswith('targets') or input_lower == 'available targets':
            self._show_available_targets()
            return True
        
        elif input_lower.startswith('tools') or input_lower == 'available tools':
            self._show_available_tools()
            return True
        
        elif input_lower.startswith('target ') and 'results' in input_lower:
            target = user_input.split()[1]
            self._show_target_results(target)
            return True
        
        elif input_lower.startswith('tool ') and 'results' in input_lower:
            tool = user_input.split()[1]
            self._show_tool_results(tool)
            return True
        
        elif input_lower == 'refresh index' or input_lower == 'rebuild index':
            self._refresh_rag_index()
            return True
        
        return False

    def _search_scan_results(self, query: str):
        """Search through scan results"""
        if not self.tools.is_rag_available():
            print("\n❌ RAG system not available. Install dependencies with: pip install sentence-transformers faiss-cpu numpy")
            return
        
        print(f"\n🔍 Searching scan results for: '{query}'")
        results = self.tools.search_scan_results(query, top_k=5)
        
        if not results:
            print("No relevant scan results found.")
            return
        
        print(f"\n📊 Found {len(results)} relevant results:")
        for i, result in enumerate(results, 1):
            print(f"\n{i}. {result.document.tool} on {result.document.target}")
            print(f"   Score: {result.score:.3f}")
            print(f"   Timestamp: {result.document.timestamp}")
            print(f"   Snippet: {result.snippet}")
            print(f"   File: {result.document.file_path}")

    def _show_scan_summary(self):
        """Show summary of all scan results"""
        if not self.tools.is_rag_available():
            print("\n❌ RAG system not available.")
            return
        
        summary = self.tools.get_scan_summary()
        
        if "message" in summary:
            print(f"\n📋 {summary['message']}")
            return
        
        print(f"\n📊 Scan Results Summary:")
        print(f"Total Documents: {summary['total_documents']}")
        print(f"Index Type: {summary['index_type']}")
        
        if summary['targets']:
            print(f"\n🎯 Targets ({len(summary['targets'])}):")
            for target in summary['targets'][:10]:  # Show first 10
                print(f"  - {target}")
            if len(summary['targets']) > 10:
                print(f"  ... and {len(summary['targets']) - 10} more")
        
        if summary['tools']:
            print(f"\n🛠️  Tools Used ({len(summary['tools'])}):")
            for tool in summary['tools'][:10]:  # Show first 10
                count = summary['tool_counts'].get(tool, 0)
                print(f"  - {tool}: {count} scans")
            if len(summary['tools']) > 10:
                print(f"  ... and {len(summary['tools']) - 10} more")

    def _show_available_targets(self):
        """Show list of available targets"""
        if not self.tools.is_rag_available():
            print("\n❌ RAG system not available.")
            return
        
        targets = self.tools.get_available_targets()
        
        if not targets:
            print("\n📋 No targets found in scan results.")
            return
        
        print(f"\n🎯 Available Targets ({len(targets)}):")
        for target in targets:
            print(f"  - {target}")

    def _show_available_tools(self):
        """Show list of available tools"""
        if not self.tools.is_rag_available():
            print("\n❌ RAG system not available.")
            return
        
        tools = self.tools.get_available_tools()
        
        if not tools:
            print("\n📋 No tools found in scan results.")
            return
        
        print(f"\n🛠️  Available Tools ({len(tools)}):")
        for tool in tools:
            print(f"  - {tool}")

    def _show_target_results(self, target: str):
        """Show scan results for a specific target"""
        if not self.tools.is_rag_available():
            print("\n❌ RAG system not available.")
            return
        
        results = self.tools.get_target_scan_results(target)
        
        if not results:
            print(f"\n📋 No scan results found for target: {target}")
            return
        
        print(f"\n📊 Scan Results for {target} ({len(results)} scans):")
        for result in results:
            status = "✅" if result['success'] else "❌"
            print(f"\n{status} {result['tool']} - {result['timestamp']}")
            print(f"   File: {result['file_path']}")
            print(f"   Preview: {result['content_preview']}")

    def _show_tool_results(self, tool: str):
        """Show scan results for a specific tool"""
        if not self.tools.is_rag_available():
            print("\n❌ RAG system not available.")
            return
        
        results = self.tools.get_tool_scan_results(tool)
        
        if not results:
            print(f"\n📋 No scan results found for tool: {tool}")
            return
        
        print(f"\n📊 Scan Results for {tool} ({len(results)} scans):")
        for result in results:
            status = "✅" if result['success'] else "❌"
            print(f"\n{status} {result['target']} - {result['timestamp']}")
            print(f"   File: {result['file_path']}")
            print(f"   Preview: {result['content_preview']}")

    def _refresh_rag_index(self):
        """Refresh the RAG index"""
        if not self.tools.is_rag_available():
            print("\n❌ RAG system not available.")
            return
        
        print("\n🔄 Refreshing RAG index...")
        self.tools.refresh_rag_index()
        print("✅ RAG index refreshed successfully!")

    def start_chat(self, initial_prompt: str) -> str:
        """Start a new chat session with the target and initial scan results"""
        self.chat_history = []
        self.command_history = []
        
        # Use the model's system prompt instead of overriding it
        system_msg = {
            "role": "system",
            "content": self.model.system_prompt
        }
        self.chat_history.append(system_msg)
        
        # Enhance initial prompt with RAG context if available
        enhanced_prompt = self._enhance_input_with_rag_context(initial_prompt, initial_prompt.split('\n')[0].replace('Target: ', ''))
        
        # Add initial prompt with scan results
        self.chat_history.append({"role": "user", "content": enhanced_prompt})
        
        # Get initial response from model
        response = self.model.get_chat_completion(self.chat_history)
        self.chat_history.append({"role": "assistant", "content": response})
        
        # Display response and check for vulnerability
        data = self._display_response(response)
        self._check_for_vulnerability(data)
        
        # Process commands if not in interactive mode
        if not self.interactive_mode:
            commands = self._extract_commands(response)
            if commands:
                self._execute_commands(commands, initial_prompt.split('\n')[0].replace('Target: ', ''))
        
        return response

    def handle_user_input(self, user_input: str, target: str) -> str:
        """Handle user input and return model's response"""
        # Check if this is a RAG query for the user first
        if self._handle_rag_query(user_input):
            return "RAG query handled"
        
        # Add user message to history
        self.chat_history.append({"role": "user", "content": user_input})
        
        # Enhance the user input with relevant scan context if RAG is available
        enhanced_input = self._enhance_input_with_rag_context(user_input, target)
        
        # Update the last user message with enhanced context
        if enhanced_input != user_input:
            self.chat_history[-1]["content"] = enhanced_input
        
        # Get model's response
        response = self.model.get_chat_completion(self.chat_history)
        self.chat_history.append({"role": "assistant", "content": response})
        
        # Display response and check for vulnerability
        data = self._display_response(response)
        self._check_for_vulnerability(data)
        
        # Process commands
        commands = self._extract_commands(response)
        if commands:
            if self.interactive_mode:
                # In interactive mode, ask user for approval
                chosen_command = self._get_user_command_choice(commands)
                if chosen_command:
                    self._execute_commands([chosen_command], target)
            else:
                # In automatic mode, execute all commands
                self._execute_commands(commands, target)
        
        return response

    def _enhance_input_with_rag_context(self, user_input: str, target: str) -> str:
        """Enhance user input with relevant scan context from RAG"""
        if not self.tools.is_rag_available():
            return user_input
        
        try:
            # Search for relevant scan results
            results = self.tools.search_scan_results(user_input, top_k=3, target_filter=target)
            
            if not results:
                return user_input
            
            # Build context from relevant results
            context_parts = []
            context_parts.append("RELEVANT PREVIOUS SCAN RESULTS:")
            
            for i, result in enumerate(results, 1):
                context_parts.append(f"\n{i}. {result.document.tool} scan on {result.document.target}:")
                context_parts.append(f"   Timestamp: {result.document.timestamp}")
                context_parts.append(f"   Success: {result.document.metadata.get('success', True)}")
                context_parts.append(f"   Key findings: {result.snippet}")
                
                # Add more detailed content if it's highly relevant
                if result.score > 0.7:  # High relevance threshold
                    # Extract key information from the scan content
                    key_info = self._extract_key_scan_info(result.document.content)
                    if key_info:
                        context_parts.append(f"   Details: {key_info}")
            
            context_parts.append(f"\nCURRENT USER QUERY: {user_input}")
            
            enhanced_input = "\n".join(context_parts)
            debug_print(f"Enhanced input with {len(results)} relevant scan results")
            
            return enhanced_input
            
        except Exception as e:
            debug_print(f"Error enhancing input with RAG context: {e}")
            return user_input

    def _extract_key_scan_info(self, content: str) -> str:
        """Extract key information from scan content"""
        lines = content.split('\n')
        key_info = []
        
        # Look for important patterns in scan results
        important_patterns = [
            r'open\s+(\d+)/',  # Open ports
            r'(\d+\.\d+\.\d+\.\d+)',  # IP addresses
            r'vulnerability|vuln|CVE',  # Vulnerabilities
            r'http[s]?://',  # URLs
            r'admin|login|wp-admin',  # Admin interfaces
            r'SSH|FTP|SMTP|HTTP|HTTPS',  # Services
            r'WordPress|Apache|Nginx|IIS',  # Technologies
        ]
        
        for line in lines:
            line_lower = line.lower()
            for pattern in important_patterns:
                if re.search(pattern, line_lower, re.IGNORECASE):
                    # Clean up the line and add it
                    clean_line = line.strip()
                    if len(clean_line) > 10 and len(clean_line) < 200:  # Reasonable length
                        key_info.append(clean_line)
                        break
            
            # Limit the number of key info items
            if len(key_info) >= 5:
                break
        
        return "; ".join(key_info) if key_info else ""

    def _execute_commands(self, commands: List[str], target: str):
        """Execute a list of commands and get follow-up analysis"""
        for command in commands:
            print(f"\n🚀 Executing: {command}")
            
            # Execute the command and wait for output
            result = self.tools.execute_command(command, target)
            
            if result.success:
                print(f"\n✅ Command completed successfully")
                print(f"📄 Output:\n{result.output}")
                if result.output_file:
                    print(f"💾 Output saved to: {result.output_file}")
                output_for_llm = result.output
            else:
                print(f"\n❌ Command failed")
                print(f"📄 Error:\n{result.error}")
                if result.output_file:
                    print(f"💾 Error details saved to: {result.output_file}")
                output_for_llm = f"ERROR: {result.error}" if result.error else "ERROR: Command failed."
            
            self.command_history.append((command, output_for_llm))
            
            # Always add the output (or error) to chat history as a user message BEFORE LLM follow-up
            self.chat_history.append({
                "role": "user",
                "content": f"Command output:\n{output_for_llm}"
            })
            
            # Now get model's follow-up analysis, which will see the output
            print(f"\n🤖 Analyzing results...")
            follow_up = self.model.get_chat_completion(self.chat_history)
            self.chat_history.append({"role": "assistant", "content": follow_up})
            
            # Display follow-up response (but don't execute commands automatically)
            data = self._display_response(follow_up)
            self._check_for_vulnerability(data)
            
            # Don't automatically execute follow-up commands to prevent loops
            # User can manually request execution if needed

    def _process_response(self, response: str) -> List[str]:
        """Process model response: check for vulnerability and extract commands"""
        try:
            # Parse JSON response
            data = json.loads(response)
            
            # Check for vulnerability
            self._check_for_vulnerability(data)
            
            # Extract commands
            return self._extract_commands(response)
            
        except json.JSONDecodeError:
            print(f"Warning: Could not parse JSON response: {response}")
            return []
        except Exception as e:
            print(f"Error processing response: {e}")
            return []

    def _extract_commands(self, text: str) -> List[str]:
        """Extract commands from model's JSON response"""
        try:
            data = json.loads(text)
            if "command" in data and data["command"]:
                return [data["command"]]
        except Exception:
            pass
        return []

    def get_chat_history(self) -> List[Dict[str, str]]:
        """Get the chat history"""
        return self.chat_history

    def get_command_history(self) -> List[Tuple[str, str]]:
        """Get the command execution history"""
        return self.command_history

    def print_welcome(self):
        """Print welcome message and instructions"""
        print("\nWelcome to AgentRed")
        print("\nThe assistant will help you test the security of your target.")
        print(f"\nMode: {'Interactive' if self.interactive_mode else 'Automatic'}")
        if self.interactive_mode:
            print("Commands will require your approval before execution.")
            print("You can ask questions and the assistant will suggest appropriate tools to use.")
        else:
            print("Commands will be automatically executed.")
        
        

if __name__ == "__main__":
    print("This module should be imported and used from main.py") 
