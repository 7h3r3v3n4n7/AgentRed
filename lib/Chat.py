import os
from lib.Tools import Tools, CommandResult
from typing import Tuple, List, Dict, Optional
from .Model import Model

class Chat:
    def __init__(self, model: Model, tools: Tools):
        """Initialize Chat with a model instance and tools"""
        if model is None:
            raise ValueError("Model instance is required")
        self.model = model
        self.tools = tools
        self.chat_history = []
        self.command_history = []
        self.print_welcome()

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

    def start_chat(self, initial_prompt: str) -> str:
        """Start a new chat session with the target and initial scan results"""
        self.chat_history = []
        self.command_history = []
        
        # Initial system message
        system_msg = {
            "role": "system",
            "content": "You are a helpful security testing assistant. Analyze the provided scan results and suggest appropriate next steps based on the findings."
        }
        self.chat_history.append(system_msg)
        
        # Add initial prompt with scan results
        self.chat_history.append({"role": "user", "content": initial_prompt})
        
        # Get initial response from model
        response = self.model.get_chat_completion(self.chat_history)
        self.chat_history.append({"role": "assistant", "content": response})
        
        return response

    def handle_user_input(self, user_input: str, target: str) -> str:
        """Handle user input and return model's response"""
        # Add user message to history
        self.chat_history.append({"role": "user", "content": user_input})
        
        # Get model's response
        response = self.model.get_chat_completion(self.chat_history)
        self.chat_history.append({"role": "assistant", "content": response})
        
        # Check if response contains commands
        commands = self._extract_commands(response)
        if commands:
            # Get user's choice of command
            chosen_command = self._get_user_command_choice(commands)
            if chosen_command:
                # Add command execution request to history
                self.chat_history.append({
                    "role": "user",
                    "content": f"Execute this command: {chosen_command}"
                })
                
                # Get model's response with command execution
                follow_up = self.model.get_chat_completion(self.chat_history)
                self.chat_history.append({"role": "assistant", "content": follow_up})
                return follow_up
        
        return response

    def _extract_commands(self, text: str) -> List[str]:
        """Extract commands from model's response"""
        commands = []
        lines = text.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('$') or line.startswith('#'):
                commands.append(line[1:].strip())
        return commands

    def get_chat_history(self) -> List[Dict[str, str]]:
        """Get the chat history"""
        return self.chat_history

    def get_command_history(self) -> List[Tuple[str, str]]:
        """Get the command execution history"""
        return self.command_history

    def print_welcome(self):
        """Print welcome message and instructions"""
        print("\nWelcome to the Security Testing Assistant!")
        print("Type 'exit' or 'quit' to end the session")
        print("Type 'clear' to clear the screen")
        print("\nThe assistant will help you test the security of your target.")
        print("You can ask questions and the assistant will suggest appropriate tools to use.")
        print("When a command is suggested, you'll be prompted to choose whether to run it.")

if __name__ == "__main__":
    print("This module should be imported and used from main.py")
