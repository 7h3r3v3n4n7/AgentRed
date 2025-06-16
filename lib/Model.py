import os
import re
import json
import warnings
import logging
import sys
import psutil
import gc
from typing import Dict, List, Optional
from llama_cpp import Llama
from llama_cpp.llama_grammar import LlamaGrammar
from .Tools import Tools, CommandResult

# Load environment variables
DEBUG = os.getenv('DEBUG', '0') == '1'

def debug_print(*args, **kwargs):
    """Print debug messages only if DEBUG is enabled"""
    if DEBUG:
        print("[DEBUG]", *args, **kwargs)

# Suppress warnings
warnings.filterwarnings("ignore")

# Set all loggers to CRITICAL level
logging.getLogger().setLevel(logging.CRITICAL)

# Suppress llama-cpp performance metrics and warnings
os.environ["LLAMA_CPP_LOG_LEVEL"] = "FATAL"  # Changed from ERROR to FATAL
os.environ["LLAMA_CPP_LOGGING"] = "0"
os.environ["LLAMA_CPP_SILENT"] = "1"  # Added to suppress all output

class Model:
    def __init__(self, target: str = None, tools: Tools = None):
        debug_print("Initializing AI Model...")
        self.model = None
        self.target = target
        self.tools = tools
        self.tools_list = tools.get_tools_list() if tools else {}
        
        # Calculate token limits based on available memory
        self._calculate_token_limits()
        
        self.system_prompt = self._build_system_prompt()
        self.messages = [
            {
                "role": "system",
                "content": self.system_prompt
            }
        ]
        self.max_messages = 10  # Limit conversation history
        self.memory_threshold = 0.8  # 80% memory usage threshold
        
        # Load JSON grammar from file
        grammar_path = os.path.join(os.path.dirname(__file__), "grammars", "json.gbnf")
        with open(grammar_path, 'r') as f:
            self.json_grammar = LlamaGrammar.from_string(f.read())
        debug_print("Model initialization complete")

    def _calculate_token_limits(self):
        """Calculate token limits based on available system memory"""
        try:
            # Get available system memory in GB
            available_memory = psutil.virtual_memory().available / (1024 * 1024 * 1024)
            total_memory = psutil.virtual_memory().total / (1024 * 1024 * 1024)
            
            # Calculate base token limits
            # Using more conservative estimates:
            # - 1GB per 8K tokens for context (reduced from 16K)
            # - 1GB per 2K tokens for generation (reduced from 4K)
            # - Reserve 3GB for system operations (increased from 2GB)
            
            # Calculate maximum context size (reserving 3GB for system)
            self.max_context_tokens = min(16384, int((available_memory - 3) * 8192))
            self.max_context_tokens = max(4096, self.max_context_tokens)  # Minimum 4K tokens
            
            # Calculate maximum generation tokens (reserving 3GB for system)
            self.max_generation_tokens = min(2048, int((available_memory - 3) * 2048))
            self.max_generation_tokens = max(1024, self.max_generation_tokens)  # Minimum 1K tokens
            
            # Calculate memory threshold based on total memory
            self.memory_threshold = min(0.7, 0.5 + (total_memory * 0.01))  # More conservative threshold
            
            debug_print(f"Memory-based token limits:")
            debug_print(f"- Available memory: {available_memory:.1f}GB")
            debug_print(f"- Context tokens: {self.max_context_tokens}")
            debug_print(f"- Generation tokens: {self.max_generation_tokens}")
            debug_print(f"- Memory threshold: {self.memory_threshold:.1%}")
            
        except Exception as e:
            debug_print(f"Warning: Could not calculate memory-based limits: {e}")
            # More conservative fallback values
            self.max_context_tokens = 4096
            self.max_generation_tokens = 1024
            self.memory_threshold = 0.7

    def _build_system_prompt(self) -> str:
        tools_info = "Available Tools:"
        if self.tools_list:
            for tool in self.tools_list:
                tools_info += f"{tool},"

        return f"""ABSOLUTELY NO SIMULATION OR ROLEPLAY. This is a real-world penetration test on a live target. Every command you suggest will be executed. Respond using only real tools and valid JSON.

DO NOT describe what you would do. DO IT by responding with an actual command.

ONLY use tools listed below:
{tools_info}

Start by performing a port scan on the target:
Target: {self.target}

STRICT RULES:
1. Respond ONLY in valid JSON. No text outside the JSON object.
2. JSON MUST include these fields: "response", "command"
3. JSON MAY include "vulnerability" if a vuln is confirmed.
4. DO NOT use markdown formatting.
5. DO NOT simulate requests or describe actions. Use real commands.
6. DO NOT include hypothetical examples or roleplay.
7. DO NOT reason step by step. Provide actionable output only.
8. EVERY response MUST include a command to execute.
9. NEVER respond without a command.
10. NEVER describe what you would do - just do it with a command.

OUTPUT FORMAT EXAMPLE:
{{
  "response": "Starting with a comprehensive port scan to discover open services.",
  "command": "nmap -sV -sC -p- {self.target}"
}}

If a vulnerability is confirmed:
{{
  "response": "SQL injection vulnerability detected in login form.",
  "command": "sqlmap -u {self.target}/login.php --forms --batch",
  "vulnerability": {{
    "type": "SQL Injection",
    "severity": "high",
    "description": "The login form fails to sanitize user input.",
    "exploitation": {{
      "method": "1. Intercept login\n2. Inject payload\n3. Gain access",
      "code": "username=admin' OR '1'='1&password=anything",
      "requirements": ["Burp Suite", "Login endpoint access"]
    }},
    "references": ["CVE-2023-1234", "OWASP SQLi Guide"]
  }}
}}
"""

    def _check_memory_usage(self) -> bool:
        """Check if memory usage is above threshold"""
        try:
            memory_percent = psutil.virtual_memory().percent / 100
            if memory_percent > self.memory_threshold:
                debug_print(f"Memory usage high: {memory_percent:.1%}")
            return memory_percent > self.memory_threshold
        except Exception as e:
            debug_print(f"Error checking memory usage: {e}")
            return False

    def _cleanup_memory(self):
        """Clean up memory without clearing message history"""
        debug_print("Performing memory cleanup...")
        # Force garbage collection
        gc.collect()
        
        # Clear any cached data
        if hasattr(self, 'model') and self.model:
            # Clear any cached tensors or intermediate results
            if hasattr(self.model, 'clear_cache'):
                debug_print("Clearing model cache...")
                self.model.clear_cache()
        
        # Sleep briefly to allow memory to be freed
        import time
        time.sleep(0.1)
        debug_print("Memory cleanup complete")

    def _get_optimal_context_size(self) -> int:
        """Return the pre-calculated context size"""
        return self.max_context_tokens

    def load_model(self):
        try:
            if self.model is not None:
                return "Model already loaded"

            model_path = "models/pentest-agent.gguf"
            if not os.path.exists(model_path):
                return f"Error: Model file not found at {model_path}"

            # Calculate optimal context size
            context_size = self._get_optimal_context_size()
            debug_print(f"Loading model with context size: {context_size} tokens")

            # Suppress stdout during model loading
            devnull = open(os.devnull, 'w')
            old_stdout = sys.stdout
            sys.stdout = devnull
            try:
                self.model = Llama(
                    model_path=model_path,
                    n_ctx=context_size,
                    n_threads=4,
                    chat_format="chatml-function-calling",
                    verbose=False  # Disable verbose output
                )
            except Exception as e:
                # If first attempt fails, try with smaller context
                if context_size > 8192:
                    debug_print("Retrying with smaller context size...")
                    context_size = 8192
                    self.model = Llama(
                        model_path=model_path,
                        n_ctx=context_size,
                        n_threads=4,
                        chat_format="chatml-function-calling",
                        verbose=False
                    )
                else:
                    raise e
            finally:
                sys.stdout = old_stdout
                devnull.close()
            debug_print("Model loaded successfully")
            return "Model loaded"
        except Exception as e:
            return f"Error loading model: {str(e)}"

    def _build_tools_schema(self) -> List[Dict]:
        """Build the tools schema for function calling"""
        tools = []
        
        # Add command execution tool
        tools.append({
            "type": "function",
            "function": {
                "name": "execute_command",
                "description": "Execute a security testing command",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "The command to execute"
                        },
                        "target": {
                            "type": "string",
                            "description": "The target host/IP/URL"
                        },
                        "args": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            },
                            "description": "Optional command arguments"
                        },
                        "tool_config": {
                            "type": "object",
                            "description": "Optional tool-specific configuration"
                        }
                    },
                    "required": ["command"]
                }
            }
        })
        
        # Add vulnerability reporting tool
        tools.append({
            "type": "function",
            "function": {
                "name": "report_vulnerability",
                "description": "Report a discovered vulnerability",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "type": {
                            "type": "string",
                            "description": "Type of vulnerability"
                        },
                        "severity": {
                            "type": "string",
                            "description": "Severity level (low/medium/high/critical)"
                        },
                        "description": {
                            "type": "string",
                            "description": "Description of the vulnerability"
                        },
                        "exploitation": {
                            "type": "object",
                            "properties": {
                                "method": {
                                    "type": "string",
                                    "description": "Method to exploit the vulnerability"
                                },
                                "code": {
                                    "type": "string",
                                    "description": "Example exploitation code"
                                },
                                "requirements": {
                                    "type": "array",
                                    "items": {
                                        "type": "string"
                                    },
                                    "description": "Requirements for exploitation"
                                }
                            }
                        },
                        "references": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            },
                            "description": "References (CVEs, guides, etc.)"
                        }
                    },
                    "required": ["type", "severity", "description"]
                }
            }
        })
        
        return tools

    def _suppress_stdout(self):
        """Context manager for suppressing stdout"""
        devnull = open(os.devnull, 'w')
        old_stdout = sys.stdout
        sys.stdout = devnull
        return devnull, old_stdout

    def _restore_stdout(self, devnull, old_stdout):
        """Restore stdout and close devnull"""
        sys.stdout = old_stdout
        devnull.close()

    def _execute_with_memory_management(self, func, *args, **kwargs):
        """Execute a function with memory management"""
        if self._check_memory_usage():
            debug_print("Memory usage high, performing cleanup...")
            self._cleanup_memory()
        
        debug_print(f"Executing function: {func.__name__}")
        result = func(*args, **kwargs)
        
        self._cleanup_memory()
        return result

    def get_chat_completion(self, messages: List[Dict[str, str]]) -> str:
        """Generate a response from the model using ChatML function calling"""
        try:
            if self.model is None:
                debug_print("Loading model...")
                self.load_model()
                if self.model is None:
                    return json.dumps({
                        "response": "Error: Failed to load model",
                        "command": "echo 'Model failed to load'"
                    })

            debug_print("Generating response...")
            tools = self._build_tools_schema()
            
            # Generate initial response
            devnull, old_stdout = self._suppress_stdout()
            try:
                result = self._execute_with_memory_management(
                    self.model.create_chat_completion,
                    messages=messages,
                    tools=tools,
                    temperature=0.7,
                    max_tokens=self.max_generation_tokens
                )
            finally:
                self._restore_stdout(devnull, old_stdout)
            
            debug_print("Response generated")

            if not result or not isinstance(result, dict) or "choices" not in result or len(result["choices"]) == 0:
                debug_print("No valid response generated")
                return json.dumps({
                    "response": "Error: No response generated from model",
                    "command": "echo 'No response generated'"
                })

            response_message = result["choices"][0]["message"]
            
            if "tool_calls" in response_message:
                debug_print("Processing tool calls...")
                tool_calls = response_message["tool_calls"]
                responses = []
                
                for tool_call in tool_calls:
                    function_name = tool_call["function"]["name"]
                    function_args = json.loads(tool_call["function"]["arguments"])
                    debug_print(f"Tool call: {function_name}")
                    
                    if function_name == "execute_command" and self.tools:
                        command = function_args.get("command", "")
                        target = function_args.get("target", self.target)
                        args = function_args.get("args")
                        tool_config = function_args.get("tool_config")
                        
                        debug_print(f"Executing command: {command}")
                        result = self.tools.execute_command(command, target, args, tool_config)
                        responses.append({
                            "response": f"Command executed: {command}",
                            "command": command,
                            "output": result.output if result.success else result.error
                        })
                    
                    elif function_name == "report_vulnerability":
                        debug_print(f"Reporting vulnerability: {function_args.get('type')}")
                        responses.append({
                            "response": f"Vulnerability detected: {function_args.get('type')}",
                            "command": "echo 'Vulnerability detected'",
                            "vulnerability": function_args
                        })
                
                messages.append({
                    "role": "function",
                    "name": function_name,
                    "content": json.dumps(responses)
                })
                
                # Get follow-up response
                debug_print("Getting follow-up response...")
                devnull, old_stdout = self._suppress_stdout()
                try:
                    follow_up = self._execute_with_memory_management(
                        self.model.create_chat_completion,
                        messages=messages,
                        tools=tools,
                        temperature=0.7,
                        max_tokens=self.max_generation_tokens
                    )
                finally:
                    self._restore_stdout(devnull, old_stdout)
                
                if follow_up and "choices" in follow_up and len(follow_up["choices"]) > 0:
                    response = follow_up["choices"][0]["message"]["content"]
                    if not self.validate_json_response(response):
                        debug_print("Invalid response format")
                        return json.dumps({
                            "response": "Invalid response format",
                            "command": "echo 'Invalid response format'"
                        })
                    return response
                
                return json.dumps(responses[0]) if responses else json.dumps({
                    "response": "No function responses",
                    "command": "echo 'No function responses'"
                })
            
            response = response_message["content"]
            if not self.validate_json_response(response):
                debug_print("Invalid response format")
                return json.dumps({
                    "response": "Invalid response format",
                    "command": "echo 'Invalid response format'"
                })
            return response

        except Exception as e:
            debug_print(f"Error in get_chat_completion: {e}")
            return json.dumps({
                "response": f"Error generating response: {str(e)}",
                "command": "echo 'Error occurred'"
            })

    def clean_response(self, text: str) -> str:
        """Clean up model response text"""
        if not text:
            return ""
            
        # Remove any markdown code blocks
        text = re.sub(r'```.*?```', '', text, flags=re.DOTALL)
        text = text.replace('```', '')
        
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', '', text)
        
        # Remove user/assistant markers
        text = re.sub(r'\[user\d+\]|\[assistant\]', '', text)
        
        # Fix HTML entities
        text = text.replace('&lt;', '<').replace('&gt;', '>')
        
        # Remove any text before the first { and after the last }
        text = re.sub(r'^[^{]*', '', text)
        text = re.sub(r'[^}]*$', '', text)
        
        # Normalize whitespace
        text = re.sub(r'\n{3,}', '\n\n', text)
        
        return text.strip()

    def validate_json_response(self, response: str) -> bool:
        try:
            json.loads(response)
            return True
        except json.JSONDecodeError:
            return False
