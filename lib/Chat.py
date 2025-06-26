import os
import json
from lib.Tools import Tools, CommandResult
from typing import Tuple, List, Dict, Optional
from .Model import Model

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
            
            # Display the command if present
            if "command" in data and data["command"]:
                if self.interactive_mode:
                    print(f"\n🔧 Suggested Command: {data['command']}")
                else:
                    print(f"\n🔧 Executing: {data['command']}")
            
            return data
        except json.JSONDecodeError:
            print(f"\n⚠️  Warning: Could not parse response as JSON")
            print(f"Raw response: {response}")
            return {}

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
        
        # Add initial prompt with scan results
        self.chat_history.append({"role": "user", "content": initial_prompt})
        
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
        # Add user message to history
        self.chat_history.append({"role": "user", "content": user_input})
        
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
            
            # Display follow-up response
            data = self._display_response(follow_up)
            self._check_for_vulnerability(data)

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
