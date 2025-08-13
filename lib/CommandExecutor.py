import subprocess
import os
import signal
import psutil
import time
from typing import Optional, Tuple
from dataclasses import dataclass
from lib.logging_utils import debug_print

# Load environment variables
COMMAND_TIMEOUT = int(os.getenv('COMMAND_TIMEOUT', '300'))  # 5 minutes default timeout
MEMORY_THRESHOLD = float(os.getenv('MEMORY_THRESHOLD', '0.8'))  # 80% memory threshold

@dataclass
class CommandResult:
    output: str
    success: bool
    error: str = ""
    killed: bool = False
    timeout: bool = False
    output_file: Optional[str] = None  # Path to saved output file

class CommandTimeout(Exception):
    pass

class CommandExecutor:
    """Handles command execution, process management, and timeout handling"""
    
    def __init__(self):
        debug_print("Initializing CommandExecutor...")
    
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
        """Handle command timeout by killing the process"""
        try:
            debug_print(f"Command timed out after {timeout} seconds, killing process...")
            process.terminate()
            
            # Wait a bit for graceful termination
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                debug_print("Process didn't terminate gracefully, force killing...")
                process.kill()
                process.wait()
                
        except Exception as e:
            debug_print(f"Error handling command timeout: {e}")

    def _monitor_process(self, process: subprocess.Popen, timeout: int) -> Tuple[bool, str, str]:
        """Monitor a process and return success status, output, and error"""
        start_time = time.time()
        output_lines = []
        error_lines = []
        
        try:
            while process.poll() is None:
                # Check timeout
                if time.time() - start_time > timeout:
                    self._handle_command_timeout(process, timeout)
                    return False, "", "Command timed out"
                
                # Check memory usage
                if self._check_memory_usage():
                    debug_print("Memory usage high, killing process...")
                    process.terminate()
                    return False, "", "Process killed due to high memory usage"
                
                # Read output
                try:
                    stdout_line = process.stdout.readline().decode('utf-8', errors='ignore')
                    if stdout_line:
                        output_lines.append(stdout_line.strip())
                    
                    stderr_line = process.stderr.readline().decode('utf-8', errors='ignore')
                    if stderr_line:
                        error_lines.append(stderr_line.strip())
                        
                except Exception as e:
                    debug_print(f"Error reading process output: {e}")
                
                time.sleep(0.1)  # Small delay to prevent busy waiting
            
            # Read any remaining output
            remaining_stdout, remaining_stderr = process.communicate()
            if remaining_stdout:
                output_lines.extend(remaining_stdout.decode('utf-8', errors='ignore').splitlines())
            if remaining_stderr:
                error_lines.extend(remaining_stderr.decode('utf-8', errors='ignore').splitlines())
            
            success = process.returncode == 0
            output = '\n'.join(output_lines)
            error = '\n'.join(error_lines) if error_lines else ""

            return success, output, error

        except Exception as e:
            debug_print(f"Error monitoring process: {e}")
            return False, "", f"Error monitoring process: {str(e)}"

    def execute_command(self, command: str, target: Optional[str] = None, args: Optional[list] = None, tool_config: Optional[dict] = None) -> CommandResult:
        """Execute a command and return the result"""
        try:
            # Build the full command
            if args:
                full_command = [command] + args
            else:
                full_command = command.split()
            
            debug_print(f"Executing command: {full_command}")
            
            # Check memory before execution
            if self._check_memory_usage():
                debug_print("Memory usage high, skipping command execution")
                return CommandResult(
                    output="",
                    success=False,
                    error="Memory usage too high to execute command",
                    killed=True
                )
            
            # Execute the command
            process = subprocess.Popen(
                full_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                bufsize=1,
                universal_newlines=False
            )
            
            # Monitor the process
            success, output, error = self._monitor_process(process, COMMAND_TIMEOUT)
            
            # Create CommandResult
            command_result = CommandResult(
                output=output,
                success=success,
                error=error,
                killed=not success and "killed" in str(error).lower(),
                timeout=not success and "timeout" in str(error).lower()
            )
            
            debug_print(f"Command execution completed: success={success}")
            return command_result
            
        except Exception as e:
            debug_print(f"Error executing command: {e}")
            return CommandResult(
                output="",
                success=False,
                error=str(e),
                killed=False
            )

    def execute_with_timeout(self, command: str, timeout: int = COMMAND_TIMEOUT) -> CommandResult:
        """Execute a command with a specific timeout"""
        global COMMAND_TIMEOUT
        original_timeout = COMMAND_TIMEOUT
        try:
            # Temporarily change timeout
            COMMAND_TIMEOUT = timeout
            return self.execute_command(command)
        finally:
            COMMAND_TIMEOUT = original_timeout

    async def async_execute_command(self, command: str, target: Optional[str] = None, args: Optional[list] = None, tool_config: Optional[dict] = None, timeout: int = None) -> CommandResult:
        """Asynchronously execute a command and return the result"""
        import asyncio
        if timeout is None:
            timeout = COMMAND_TIMEOUT
        if args:
            full_command = [command] + args
        else:
            full_command = command.split()
        debug_print(f"[ASYNC] Executing command: {full_command}")
        # Check memory before execution
        if self._check_memory_usage():
            debug_print("[ASYNC] Memory usage high, skipping command execution")
            return CommandResult(
                output="",
                success=False,
                error="Memory usage too high to execute command",
                killed=True
            )
        try:
            process = await asyncio.create_subprocess_exec(
                *full_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            start_time = asyncio.get_event_loop().time()
            output_lines = []
            error_lines = []
            killed = False
            timed_out = False
            async def read_stream(stream, lines):
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    lines.append(line.decode('utf-8', errors='ignore').strip())
            # Start reading stdout and stderr concurrently
            stdout_task = asyncio.create_task(read_stream(process.stdout, output_lines))
            stderr_task = asyncio.create_task(read_stream(process.stderr, error_lines))
            while True:
                if process.returncode is not None:
                    break
                # Timeout check
                elapsed = asyncio.get_event_loop().time() - start_time
                if elapsed > timeout:
                    debug_print(f"[ASYNC] Command timed out after {timeout} seconds, killing process...")
                    process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), timeout=5)
                    except asyncio.TimeoutError:
                        debug_print("[ASYNC] Process didn't terminate gracefully, force killing...")
                        process.kill()
                        await process.wait()
                    killed = True
                    timed_out = True
                    break
                # Memory check
                if self._check_memory_usage():
                    debug_print("[ASYNC] Memory usage high, killing process...")
                    process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), timeout=5)
                    except asyncio.TimeoutError:
                        process.kill()
                        await process.wait()
                    killed = True
                    break
                await asyncio.sleep(0.1)
            await process.wait()
            # Wait for output reading to finish
            await stdout_task
            await stderr_task
            # Read any remaining output
            try:
                remaining_stdout, remaining_stderr = await process.communicate()
                if remaining_stdout:
                    output_lines.extend(remaining_stdout.decode('utf-8', errors='ignore').splitlines())
                if remaining_stderr:
                    error_lines.extend(remaining_stderr.decode('utf-8', errors='ignore').splitlines())
            except Exception as e:
                debug_print(f"[ASYNC] Error reading remaining output: {e}")
            success = process.returncode == 0 and not killed and not timed_out
            output = '\n'.join(output_lines)
            error = '\n'.join(error_lines) if error_lines else ""
            return CommandResult(
                output=output,
                success=success,
                error=error,
                killed=killed,
                timeout=timed_out
            )
        except Exception as e:
            debug_print(f"[ASYNC] Error executing command: {e}")
            return CommandResult(
                output="",
                success=False,
                error=str(e),
                killed=False
            )

    def is_process_running(self, pid: int) -> bool:
        """Check if a process is still running"""
        try:
            process = psutil.Process(pid)
            return process.is_running()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    def kill_process(self, pid: int) -> bool:
        """Kill a process by PID"""
        try:
            process = psutil.Process(pid)
            process.terminate()
            
            # Wait for termination
            try:
                process.wait(timeout=5)
                return True
            except psutil.TimeoutExpired:
                process.kill()
                process.wait()
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False 