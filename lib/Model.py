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
from lib.config import Config
from lib.logging_utils import debug_print

# Load environment variables
DEBUG = os.getenv('DEBUG', '0') == '1'

# Suppress warnings
warnings.filterwarnings("ignore")

# Set all loggers to CRITICAL level
logging.getLogger().setLevel(logging.CRITICAL)

# Suppress llama-cpp performance metrics and warnings
os.environ["LLAMA_CPP_LOG_LEVEL"] = "FATAL"  # Changed from ERROR to FATAL
os.environ["LLAMA_CPP_LOGGING"] = "0"
os.environ["LLAMA_CPP_SILENT"] = "1"  # Added to suppress all output

class Model:
    def __init__(self, target: str = None, tools: Tools = None, config: Config = None):
        self.config = config or Config()
        debug_print("Initializing AI Model...")
        self.model = None
        self.target = target
        self.tools = tools
        # Only include installed tools with descriptions
        if tools:
            installed = tools.get_installed_tools()
            self.tools_list = {k: tools.required_tools[k] for k in installed}
        else:
            self.tools_list = {}
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
        self.memory_threshold = self.config.MEMORY_THRESHOLD
        # Load JSON grammar from file
        try:
            grammar_path = os.path.join(os.path.dirname(__file__), "grammars", "json.gbnf")
            debug_print(f"Loading grammar from: {grammar_path}")
            if not os.path.exists(grammar_path):
                debug_print("Grammar file not found, creating default JSON grammar")
                self.json_grammar = self._create_default_json_grammar()
            else:
                with open(grammar_path, 'r') as f:
                    grammar_content = f.read()
                    debug_print(f"Grammar content: {grammar_content[:100]}...")  # Print first 100 chars
                    self.json_grammar = LlamaGrammar.from_string(grammar_content)
            debug_print("Grammar loaded successfully")
        except Exception as e:
            debug_print(f"Error loading grammar: {e}")
            debug_print("Using default JSON grammar")
            self.json_grammar = self._create_default_json_grammar()
        debug_print("Model initialization complete")

    def _create_default_json_grammar(self) -> LlamaGrammar:
        """Create a default JSON grammar for response validation"""
        grammar = """
root ::= object
object ::= "{" ws (string ":" ws value ("," ws string ":" ws value)*)? ws "}"
array ::= "[" ws (value ("," ws value)*)? ws "]"
string ::= "\"" ([^"\\] | "\\" ["\\/bfnrt] | "\\u" [0-9a-fA-F]{4})* "\""
number ::= "-"? ("0" | [1-9] [0-9]*) ("." [0-9]+)? ([eE] [-+]? [0-9]+)?
boolean ::= "true" | "false"
null ::= "null"
value ::= object | array | string | number | boolean | null
ws ::= [ \t\n\r]*
"""
        return LlamaGrammar.from_string(grammar)

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
            for tool, desc in self.tools_list.items():
                tools_info += f"\n- {tool}: {desc}"

        # Add RAG context if available
        rag_context = ""
        if hasattr(self.tools, 'is_rag_available') and self.tools.is_rag_available():
            try:
                summary = self.tools.get_scan_summary()
                if "total_documents" in summary and summary["total_documents"] > 0:
                    rag_context = f"\n\nPREVIOUS SCAN CONTEXT:"
                    rag_context += f"\n- Total scan results available: {summary['total_documents']}"
                    rag_context += f"\n- Targets scanned: {', '.join(summary.get('targets', [])[:5])}"
                    rag_context += f"\n- Tools used: {', '.join(summary.get('tools', [])[:5])}"
                    rag_context += f"\n- You can reference previous scan results when making decisions."
                    rag_context += f"\n- Consider patterns and findings from previous scans when suggesting next steps."
            except Exception as e:
                debug_print(f"Error building RAG context: {e}")

        return f"""You are a penetration testing assistant. You MUST respond in valid JSON format ONLY.

TARGET: {self.target}

AVAILABLE TOOLS:
{tools_info}{rag_context}

RESPONSE FORMAT: (You MUST use this exact format for ALL responses)
{{
    "response": "Your analysis or explanation here",
    "command": "The command to execute"
}}

If you find a vulnerability, add a vulnerability field:
{{
    "response": "Vulnerability description",
    "command": "Command to verify or exploit",
    "vulnerability": {{
        "type": "Vulnerability type",
        "severity": "low/medium/high/critical",
        "description": "Detailed description",
        "exploitation": {{
            "method": "How to exploit",
            "code": "Example code",
            "requirements": ["Required tools"]
        }},
        "references": ["CVE numbers or guides"]
    }}
}}

RULES:
1. ALWAYS respond in valid JSON with ONLY "response" and "command" fields
2. ALWAYS give a valid command with proper arguements.
3. ALWAYS rely on the provided nmap scan.
4. DO NOT rerun nmap scans unless absolutely necessary.
5. NEVER describe actions - just provide the JSON
6. ALWAYS analyze scan results before suggesting next steps
7. ALWAYS suggest a specific command to execute
8. When relevant, reference patterns from previous scan results
9. Consider historical findings when planning next steps
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
                debug_print("Model already loaded")
                return "Model already loaded"

            model_path = "models/pentest-agent.gguf"
            debug_print(f"Loading model from: {model_path}")
            
            if not os.path.exists(model_path):
                error_msg = f"Error: Model file not found at {model_path}"
                debug_print(error_msg)
                return error_msg

            # Calculate optimal context size
            context_size = self._get_optimal_context_size()
            debug_print(f"Loading model with context size: {context_size} tokens")

            try:
                debug_print("Initializing Llama model...")
                self.model = Llama(
                    model_path=model_path,
                    n_ctx=context_size,
                    n_threads=4,
                    verbose=False
                )
                debug_print("Model loaded successfully")
                return "Model loaded"
            except Exception as e:
                debug_print(f"Error during model initialization: {str(e)}")
                # If first attempt fails, try with smaller context
                if context_size > 8192:
                    debug_print("Retrying with smaller context size...")
                    context_size = 8192
                    try:
                        self.model = Llama(
                            model_path=model_path,
                            n_ctx=context_size,
                            n_threads=4,
                            verbose=False
                        )
                        debug_print("Model loaded successfully with reduced context")
                        return "Model loaded with reduced context"
                    except Exception as e2:
                        error_msg = f"Error loading model with reduced context: {str(e2)}"
                        debug_print(error_msg)
                        return error_msg
                else:
                    error_msg = f"Error loading model: {str(e)}"
                    debug_print(error_msg)
                    return error_msg

        except Exception as e:
            error_msg = f"Unexpected error loading model: {str(e)}"
            debug_print(error_msg)
            return error_msg

    def _suppress_stdout(self):
        """Context manager for suppressing stdout"""
        # Never suppress stdout if DEBUG is enabled
        if DEBUG:
            return None, None
            
        devnull = open(os.devnull, 'w')
        old_stdout = sys.stdout
        sys.stdout = devnull
        return devnull, old_stdout

    def _restore_stdout(self, devnull, old_stdout):
        """Restore stdout and close devnull"""
        if not DEBUG and devnull and old_stdout:
            sys.stdout = old_stdout
            devnull.close()

    def _execute_with_memory_management(self, func, *args, **kwargs):
        """Execute a function with memory management"""
        if self._check_memory_usage():
            debug_print("Memory usage high, performing cleanup...")
            self._cleanup_memory()
        
        debug_print(f"Executing function: {func.__name__}")
        debug_print(f"Function args: {args}")
        debug_print(f"Function kwargs: {kwargs}")
        
        result = func(*args, **kwargs)
        debug_print(f"Function result: {result}")
        
        self._cleanup_memory()
        return result

    def get_chat_completion(self, messages: List[Dict[str, str]]) -> str:
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
            debug_print(f"Messages: {messages}")

            # Plain chat completion with grammar
            result = self._execute_with_memory_management(
                self.model.create_chat_completion,
                messages=messages,
                temperature=0.7,
                max_tokens=self.max_generation_tokens,
                grammar=self.json_grammar
            )
            debug_print(f"Model response type: {type(result)}")
            debug_print(f"Raw model response: {result}")

            if not result or not isinstance(result, dict):
                debug_print(f"Invalid result type: {type(result)}")
                return json.dumps({
                    "response": "Error: Invalid response from model",
                    "command": "echo 'Invalid response'"
                })

            if "choices" not in result or len(result["choices"]) == 0:
                debug_print("No choices in response")
                return json.dumps({
                    "response": "Error: No choices in response",
                    "command": "echo 'No choices'"
                })

            response_message = result["choices"][0]["message"]
            response = response_message.get("content", "")
            debug_print(f"Final response content: {response}")

            if not self.validate_json_response(response):
                debug_print("Invalid response format")
                return json.dumps({
                    "response": "Invalid response format from model. Please check the system prompt or model behavior.",
                    "command": "echo 'Invalid response format'"
                })
            return response

        except Exception as e:
            debug_print(f"Error in get_chat_completion: {e}")
            import traceback
            debug_print(f"Traceback: {traceback.format_exc()}")
            return json.dumps({
                "response": f"Error generating response: {str(e)}",
                "command": "echo 'Error occurred'"
            })

    def validate_json_response(self, response: str) -> bool:
        """Validate if the response is a valid JSON string"""
        try:
            debug_print(f"Validating JSON response: {response}")
            debug_print(f"Response type: {type(response)}")
            debug_print(f"Response length: {len(response)}")
            
            # Clean the response first
            cleaned_response = self.clean_response(response)
            debug_print(f"Cleaned response: {cleaned_response}")
            
            # Try to parse JSON
            try:
                data = json.loads(cleaned_response)
                debug_print(f"Parsed JSON: {data}")
            except json.JSONDecodeError as e:
                debug_print(f"JSON decode error: {e}")
                debug_print(f"Error position: {e.pos}")
                debug_print(f"Error line: {e.lineno}")
                debug_print(f"Error column: {e.colno}")
                debug_print(f"Error message: {e.msg}")
                return False
            
            # Check required fields
            if not isinstance(data, dict):
                debug_print("Response is not a dictionary")
                return False
                
            if "response" not in data:
                debug_print("Missing 'response' field")
                return False
                
            if "command" not in data:
                debug_print("Missing 'command' field")
                return False
                
            debug_print("Response validation successful")
            return True

        except Exception as e:
            debug_print(f"Validation error: {e}")
            import traceback
            debug_print(f"Traceback: {traceback.format_exc()}")
            return False

    def clean_response(self, text: str) -> str:
        """Clean up model response text"""
        if not text:
            debug_print("Empty response text")
            return ""
            
        debug_print(f"Cleaning response text: {text}")
            
        # Remove any markdown code blocks
        text = re.sub(r'```.*?```', '', text, flags=re.DOTALL)
        text = text.replace('```', '')
        debug_print(f"After removing code blocks: {text}")
        
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', '', text)
        debug_print(f"After removing HTML: {text}")
        
        # Remove user/assistant markers
        text = re.sub(r'\[user\d+\]|\[assistant\]', '', text)
        debug_print(f"After removing markers: {text}")
        
        # Fix HTML entities
        text = text.replace('&lt;', '<').replace('&gt;', '>')
        debug_print(f"After fixing entities: {text}")
        
        # Remove any text before the first { and after the last }
        text = re.sub(r'^[^{]*', '', text)
        text = re.sub(r'[^}]*$', '', text)
        debug_print(f"After removing non-JSON text: {text}")
        
        # Normalize whitespace
        text = re.sub(r'\n{3,}', '\n\n', text)
        debug_print(f"After normalizing whitespace: {text}")
        
        cleaned = text.strip()
        debug_print(f"Final cleaned text: {cleaned}")
        return cleaned
