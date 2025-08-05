import os
import datetime
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
import asyncio

# Import our new modular components
from .CommandExecutor import CommandExecutor, CommandResult
from .WordlistManager import WordlistManager
from .TargetParser import TargetParser
from .ToolRegistry import ToolRegistry
from lib.config import Config

# Import RAG functionality
try:
    from .RAG import ScanRAG, SearchResult
    RAG_AVAILABLE = True
except ImportError:
    RAG_AVAILABLE = False

# Load environment variables
DEBUG = os.getenv('DEBUG', '0') == '1'

def debug_print(*args, **kwargs):
    """Print debug messages only if DEBUG is enabled"""
    if DEBUG:
        print("[DEBUG]", *args, **kwargs)

class Tools:
    def __init__(self, config: Config, concurrency_limit: int = 5):
        self.config = config
        debug_print("Initializing Tools...")
        self.original_target = None  # Set in App.py after getting user input
        self.scans_dir = "scans"  # Directory to store scan results
        self.current_scan_dir = None  # Current scan directory for this session
        
        # Initialize modular components
        self.command_executor = CommandExecutor()
        self.wordlist_manager = WordlistManager(config=self.config)
        self.target_parser = TargetParser()
        self.tool_registry = ToolRegistry()
        
        # Initialize RAG system
        self.rag = None
        if RAG_AVAILABLE:
            try:
                self.rag = ScanRAG(self.scans_dir, config=self.config)
                debug_print("RAG system initialized")
            except Exception as e:
                debug_print(f"Failed to initialize RAG system: {e}")
        
        debug_print("Tools initialization complete")
        self.concurrency_limit = concurrency_limit
        self._semaphore = asyncio.Semaphore(concurrency_limit)
        self.max_scans_mb = self.config.SCANS_MAX_MB
        self._warned_scan_session = False
    
    def validate_target(self, target: str) -> bool:
        """Validate if the target is a valid hostname, IP address, or URL"""
        return self.target_parser.validate_target(target)
    
    def get_target_info(self, target: str) -> Dict[str, str]:
        """Get comprehensive information about a target"""
        return self.target_parser.get_target_info(target)
    
    def get_installed_tools(self) -> List[str]:
        """Get list of installed tools"""
        return self.tool_registry.get_installed_tools()
    
    def get_missing_tools(self) -> List[str]:
        """Get list of missing tools"""
        return self.tool_registry.get_missing_tools()
    
    def get_tools_list(self) -> Dict[str, str]:
        """Get the complete tools list with descriptions"""
        return self.tool_registry.get_tools_list()
    
    def get_wordlists(self) -> Dict[str, Optional[str]]:
        """Get available wordlists"""
        return self.wordlist_manager.get_available_wordlists()
    
    def get_best_wordlist(self, wordlist_type: str) -> Optional[str]:
        """Get the best available wordlist for a given type"""
        return self.wordlist_manager.get_best_wordlist(wordlist_type)
    
    def execute_command(self, command: str, target: Optional[str] = None, args: Optional[List[str]] = None, tool_config: Optional[Dict] = None) -> CommandResult:
        """Execute a command and return the result"""
        result = self.command_executor.execute_command(command, target, args, tool_config)
        
        # Save command output if we have a target
        if target and result.output:
            self._save_command_output(command, target, result.output, result.success, result.error)
        
        return result
    
    async def async_execute_command(self, command: str, target: Optional[str] = None, args: Optional[List[str]] = None, tool_config: Optional[Dict] = None, timeout: int = None) -> CommandResult:
        """Asynchronously execute a command and return the result, with global concurrency limit"""
        async with self._semaphore:
            result = await self.command_executor.async_execute_command(command, target, args, tool_config, timeout)
            # Save command output if we have a target
            if target and result.output:
                self._save_command_output(command, target, result.output, result.success, result.error)
            return result
    
    def initialize_scan_directory(self, target: str) -> str:
        """Initialize scan directory for a target"""
        # Create scans directory if it doesn't exist
        os.makedirs(self.scans_dir, exist_ok=True)
        
        # Create target-specific directory
        target_dir = os.path.join(self.scans_dir, target.replace('/', '_').replace(':', '_'))
        os.makedirs(target_dir, exist_ok=True)
        
        self.current_scan_dir = target_dir
        debug_print(f"Initialized scan directory: {target_dir}")
        return target_dir
    
    def _get_total_scans_size(self) -> int:
        """Return total size of all scan outputs in bytes"""
        total = 0
        for root, dirs, files in os.walk(self.scans_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                if os.path.isfile(fpath):
                    total += os.path.getsize(fpath)
        return total

    def _get_scans_info(self):
        """Return list of (size, mtime, path) for all scan outputs"""
        info = []
        for root, dirs, files in os.walk(self.scans_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                if os.path.isfile(fpath):
                    stat = os.stat(fpath)
                    info.append((stat.st_size, stat.st_mtime, fpath))
        return info

    def _maybe_warn_and_prompt_scan_cleanup(self):
        total_mb = self._get_total_scans_size() / (1024*1024)
        if total_mb > self.max_scans_mb and not self._warned_scan_session:
            print(f"\n⚠️  WARNING: Total scan output size is {total_mb:.1f} MB (limit: {self.max_scans_mb} MB)")
            info = sorted(self._get_scans_info(), reverse=True)
            print("Largest scan outputs:")
            for size, mtime, path in info[:5]:
                print(f"  {os.path.basename(path)} - {size/(1024*1024):.1f} MB")
            resp = input("Do you want to clean up old scan outputs now? (y/N): ").strip().lower()
            if resp == 'y':
                # Delete oldest files until under limit
                info_by_age = sorted(self._get_scans_info(), key=lambda x: x[1])
                cur_total = total_mb
                deleted = []
                for size, mtime, path in info_by_age:
                    if cur_total <= self.max_scans_mb:
                        break
                    try:
                        os.remove(path)
                        cur_total -= size/(1024*1024)
                        deleted.append(path)
                        print(f"Deleted {os.path.basename(path)}")
                    except Exception as e:
                        print(f"Failed to delete {path}: {e}")
                print(f"Cleanup complete. Total scan output size now {cur_total:.1f} MB.")
            else:
                print("No cleanup performed. You may encounter this warning again.")
                self._warned_scan_session = True

    def _save_command_output(self, tool_name: str, target: str, output: str, success: bool, error: str = None) -> Optional[str]:
        self._maybe_warn_and_prompt_scan_cleanup()
        if not self.current_scan_dir:
            return None
        
        try:
            # Create filename with timestamp
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{tool_name}_{timestamp}.txt"
            filepath = os.path.join(self.current_scan_dir, filename)
            
            # Write output to file
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"Target: {target}\n")
                f.write(f"Tool: {tool_name}\n")
                f.write(f"Timestamp: {datetime.datetime.now().isoformat()}\n")
                f.write(f"Success: {success}\n")
                if error:
                    f.write(f"Error: {error}\n")
                f.write("\n" + "="*50 + "\n\n")
                f.write(output)
            
            debug_print(f"Saved command output to: {filepath}")
            # Automatically refresh RAG index after saving scan output
            self.refresh_rag_index()
            return filepath
            
        except Exception as e:
            debug_print(f"Error saving command output: {e}")
            return None
    
    def report_vulnerability(self, type: str, severity: str, description: str, exploitation: Optional[Dict] = None, references: Optional[List[str]] = None) -> Dict:
        """Report a vulnerability finding"""
        vulnerability = {
            "type": type,
            "severity": severity,
            "description": description,
            "timestamp": datetime.datetime.now().isoformat(),
            "target": self.original_target
        }
        
        if exploitation:
            vulnerability["exploitation"] = exploitation
        
        if references:
            vulnerability["references"] = references
        
        # Save vulnerability report
        if self.current_scan_dir:
            try:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"vulnerability_{type}_{severity}_{timestamp}.json"
                filepath = os.path.join(self.current_scan_dir, filename)
                
                import json
                with open(filepath, 'w') as f:
                    json.dump(vulnerability, f, indent=2)
                
                debug_print(f"Saved vulnerability report to: {filepath}")
                
            except Exception as e:
                debug_print(f"Error saving vulnerability report: {e}")
        
        return vulnerability
    
    # RAG-related methods
    def search_scan_results(self, query: str, top_k: int = 5, target_filter: Optional[str] = None) -> List[SearchResult]:
        """Search through scan results"""
        if not self.is_rag_available():
            return []
        
        try:
            return self.rag.search(query, top_k, target_filter)
        except Exception as e:
            debug_print(f"Error searching scan results: {e}")
            return []
    
    def get_scan_summary(self) -> Dict[str, Any]:
        """Get enhanced summary of all scan results with vulnerability analysis"""
        if not self.is_rag_available():
            return {"message": "RAG system not available"}
        
        try:
            summary = self.rag.get_summary()
            
            # Add enhanced insights if available
            if hasattr(self.rag, 'get_automated_insights'):
                insights = self.rag.get_automated_insights()
                summary['automated_insights'] = insights
            
            return summary
        except Exception as e:
            debug_print(f"Error getting scan summary: {e}")
            return {"message": f"Error getting scan summary: {e}"}
    
    def get_vulnerability_correlations(self, target: str = None) -> List[Dict[str, Any]]:
        """Get vulnerability correlations for analysis"""
        if not self.is_rag_available():
            return []
        
        try:
            if hasattr(self.rag, 'get_vulnerability_correlations'):
                correlations = self.rag.get_vulnerability_correlations(target)
                return [
                    {
                        'primary_finding': {
                            'type': corr.primary_finding.vulnerability_type,
                            'severity': corr.primary_finding.severity,
                            'target': corr.primary_finding.target,
                            'description': corr.primary_finding.description
                        },
                        'correlated_findings': [
                            {
                                'type': f.vulnerability_type,
                                'severity': f.severity,
                                'target': f.target,
                                'description': f.description
                            } for f in corr.correlated_findings
                        ],
                        'correlation_strength': corr.correlation_strength,
                        'correlation_type': corr.correlation_type,
                        'attack_path': corr.attack_path
                    } for corr in correlations
                ]
            return []
        except Exception as e:
            debug_print(f"Error getting vulnerability correlations: {e}")
            return []
    
    def get_temporal_analysis(self, target: str, days: int = 30) -> Dict[str, Any]:
        """Get temporal analysis for a target"""
        if not self.is_rag_available():
            return {"message": "RAG system not available"}
        
        try:
            if hasattr(self.rag, 'get_temporal_analysis'):
                analysis = self.rag.get_temporal_analysis(target, days)
                if analysis:
                    return {
                        'target': analysis.target,
                        'time_period': analysis.time_period,
                        'scan_frequency': analysis.scan_frequency,
                        'vulnerability_trends': analysis.vulnerability_trends,
                        'tool_usage_trends': analysis.tool_usage_trends,
                        'risk_score_trend': analysis.risk_score_trend
                    }
            return {"message": "Temporal analysis not available"}
        except Exception as e:
            debug_print(f"Error getting temporal analysis: {e}")
            return {"message": f"Error getting temporal analysis: {e}"}
    
    def get_available_targets(self) -> List[str]:
        """Get list of available targets"""
        if not self.is_rag_available():
            return []
        
        try:
            return self.rag.get_targets()
        except Exception as e:
            debug_print(f"Error getting available targets: {e}")
            return []
    
    def get_available_tools(self) -> List[str]:
        """Get list of available tools"""
        if not self.is_rag_available():
            return []
        
        try:
            return self.rag.get_tools()
        except Exception as e:
            debug_print(f"Error getting available tools: {e}")
            return []
    
    def get_target_scan_results(self, target: str) -> List[Dict[str, Any]]:
        """Get scan results for a specific target"""
        if not self.is_rag_available():
            return []
        
        try:
            documents = self.rag.get_documents_by_target(target)
            results = []
            
            for doc in documents:
                results.append({
                    'tool': doc.tool,
                    'target': doc.target,
                    'timestamp': doc.timestamp,
                    'success': doc.metadata.get('success', True),
                    'file_path': doc.file_path,
                    'content_preview': doc.content[:200] + "..." if len(doc.content) > 200 else doc.content
                })
            
            return results
        except Exception as e:
            debug_print(f"Error getting target scan results: {e}")
            return []
    
    def get_tool_scan_results(self, tool: str) -> List[Dict[str, Any]]:
        """Get scan results for a specific tool"""
        if not self.is_rag_available():
            return []
        
        try:
            documents = self.rag.get_documents_by_tool(tool)
            results = []
            
            for doc in documents:
                results.append({
                    'tool': doc.tool,
                    'target': doc.target,
                    'timestamp': doc.timestamp,
                    'success': doc.metadata.get('success', True),
                    'file_path': doc.file_path,
                    'content_preview': doc.content[:200] + "..." if len(doc.content) > 200 else doc.content
                })
            
            return results
        except Exception as e:
            debug_print(f"Error getting tool scan results: {e}")
            return []
    
    def refresh_rag_index(self):
        """Refresh the RAG index"""
        if not self.is_rag_available():
            return
        
        try:
            self.rag.refresh_index()
            debug_print("RAG index refreshed")
        except Exception as e:
            debug_print(f"Error refreshing RAG index: {e}")
    
    def is_rag_available(self) -> bool:
        """Check if RAG system is available"""
        return RAG_AVAILABLE and self.rag is not None
