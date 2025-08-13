import os
import json
import re
import asyncio
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
from datetime import datetime
import threading
import queue
import pickle
import hashlib
from collections import defaultdict
from lib.config import Config

# Load environment variables
DEBUG = os.getenv('DEBUG', '0') == '1'

def debug_print(*args, **kwargs):
    """Print debug messages only if DEBUG is enabled"""
    if DEBUG:
        print("[DEBUG]", *args, **kwargs)

class AgentType(Enum):
    """Types of agents available"""
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    WEB_TESTING = "web_testing"
    EXPLOITATION = "exploitation"
    COORDINATOR = "coordinator"

class AgentStatus(Enum):
    """Agent status states"""
    IDLE = "idle"
    WORKING = "working"
    COMPLETED = "completed"
    FAILED = "failed"
    WAITING = "waiting"

@dataclass
class AgentTask:
    """Represents a task for an agent"""
    id: str
    agent_type: AgentType
    target: str
    description: str
    parameters: Dict[str, Any]
    priority: int = 1
    dependencies: List[str] = None
    created_at: datetime = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []
        if self.created_at is None:
            self.created_at = datetime.now()

@dataclass
class AgentResult:
    """Result from an agent execution"""
    task_id: str
    agent_type: AgentType
    target: str
    success: bool
    output: str
    findings: List[Dict[str, Any]]
    next_tasks: List[AgentTask]
    metadata: Dict[str, Any]

@dataclass
class LearningMemory:
    """Memory structure for agent learning"""
    target_type: str  # e.g., "web_server", "api", "database"
    successful_techniques: List[Dict[str, Any]]
    failed_techniques: List[Dict[str, Any]]
    tool_effectiveness: Dict[str, float]  # tool -> success rate
    parameter_preferences: Dict[str, Dict[str, Any]]  # tool -> preferred params
    last_updated: datetime

class BaseAgent:
    """Base class for all agents with enhanced AI intelligence"""
    
    def __init__(self, agent_type: AgentType, tools, model):
        self.agent_type = agent_type
        self.tools = tools
        self.model = model
        self.status = AgentStatus.IDLE
        self.task_queue = queue.Queue()
        self.results = []
        self.running = False
        
        # Enhanced AI Intelligence Components
        self.learning_memory = {}  # target_type -> LearningMemory
        self.context_history = []  # Recent context for better decision making
        self.adaptive_strategies = {}  # Learned strategies for different scenarios
        self.performance_metrics = defaultdict(list)  # Track performance over time
        
        # Load existing learning data
        self._load_learning_data()
        
    def _load_learning_data(self):
        """Load learning data from persistent storage"""
        try:
            memory_file = f"agent_memory_{self.agent_type.value}.pkl"
            if os.path.exists(memory_file):
                with open(memory_file, 'rb') as f:
                    self.learning_memory = pickle.load(f)
                debug_print(f"Loaded learning data for {self.agent_type.value} agent")
        except Exception as e:
            debug_print(f"Error loading learning data: {e}")
    
    def _save_learning_data(self):
        """Save learning data to persistent storage"""
        try:
            memory_file = f"agent_memory_{self.agent_type.value}.pkl"
            with open(memory_file, 'wb') as f:
                pickle.dump(self.learning_memory, f)
            debug_print(f"Saved learning data for {self.agent_type.value} agent")
        except Exception as e:
            debug_print(f"Error saving learning data: {e}")
    
    def _get_target_type(self, target: str, context: str = "") -> str:
        """Determine the type of target for learning purposes"""
        target_lower = target.lower()
        
        # Analyze target characteristics
        if any(port in context for port in ['80', '443', '8080', '8443']):
            return "web_server"
        elif any(db in context for db in ['mysql', 'postgres', 'mongo', 'redis']):
            return "database"
        elif any(api in context for api in ['api', 'rest', 'graphql', 'soap']):
            return "api"
        elif any(service in context for service in ['ssh', 'ftp', 'smtp', 'pop3']):
            return "service"
        else:
            return "unknown"
    
    def _learn_from_result(self, task: AgentTask, result: AgentResult):
        """Learn from task execution results"""
        target_type = self._get_target_type(task.target, result.output)
        
        if target_type not in self.learning_memory:
            self.learning_memory[target_type] = LearningMemory(
                target_type=target_type,
                successful_techniques=[],
                failed_techniques=[],
                tool_effectiveness={},
                parameter_preferences={},
                last_updated=datetime.now()
            )
        
        memory = self.learning_memory[target_type]
        
        # Learn from success/failure
        if result.success:
            # Extract successful techniques
            for finding in result.findings:
                technique = {
                    'tool': finding.get('tool', 'unknown'),
                    'parameters': task.parameters,
                    'finding_type': finding.get('type', 'unknown'),
                    'severity': finding.get('severity', 'low'),
                    'timestamp': datetime.now()
                }
                memory.successful_techniques.append(technique)
        else:
            # Learn from failures
            failed_technique = {
                'tool': task.parameters.get('tool', 'unknown'),
                'parameters': task.parameters,
                'error': result.output,
                'timestamp': datetime.now()
            }
            memory.failed_techniques.append(failed_technique)
        
        # Update tool effectiveness
        for finding in result.findings:
            tool = finding.get('tool', 'unknown')
            if tool in memory.tool_effectiveness:
                memory.tool_effectiveness[tool] = (memory.tool_effectiveness[tool] + 1) / 2
            else:
                memory.tool_effectiveness[tool] = 1.0
        
        memory.last_updated = datetime.now()
        self._save_learning_data()
    
    def _get_adaptive_prompt(self, task: AgentTask) -> str:
        """Get an adaptive prompt based on learning and context"""
        target_type = self._get_target_type(task.target)
        base_prompt = self.get_system_prompt()
        
        # Add learning context
        if target_type in self.learning_memory:
            memory = self.learning_memory[target_type]
            
            # Add successful techniques
            if memory.successful_techniques:
                recent_successes = memory.successful_techniques[-3:]  # Last 3 successful techniques
                success_context = "\n\nLEARNING CONTEXT - Successful Techniques:\n"
                for technique in recent_successes:
                    success_context += f"- {technique['tool']}: {technique['finding_type']} ({technique['severity']})\n"
                base_prompt += success_context
            
            # Add tool effectiveness
            if memory.tool_effectiveness:
                tool_context = "\n\nTOOL EFFECTIVENESS (Higher is better):\n"
                sorted_tools = sorted(memory.tool_effectiveness.items(), key=lambda x: x[1], reverse=True)
                for tool, effectiveness in sorted_tools[:5]:  # Top 5 tools
                    tool_context += f"- {tool}: {effectiveness:.2f}\n"
                base_prompt += tool_context
        
        # Add recent context
        if self.context_history:
            context = "\n\nRECENT CONTEXT:\n"
            for entry in self.context_history[-3:]:  # Last 3 context entries
                context += f"- {entry}\n"
            base_prompt += context
        
        return base_prompt
    
    def _update_context_history(self, task: AgentTask, result: AgentResult):
        """Update context history for better decision making"""
        context_entry = f"Target: {task.target}, Success: {result.success}, Findings: {len(result.findings)}"
        self.context_history.append(context_entry)
        
        # Keep only last 10 entries
        if len(self.context_history) > 10:
            self.context_history = self.context_history[-10:]
    
    def _get_intelligent_tools(self, target: str, context: str = "") -> str:
        """Get intelligent tool recommendations based on learning"""
        target_type = self._get_target_type(target, context)
        available_tools = self._get_available_tools()
        
        if target_type in self.learning_memory:
            memory = self.learning_memory[target_type]
            
            # Prioritize tools based on effectiveness
            if memory.tool_effectiveness:
                sorted_tools = sorted(memory.tool_effectiveness.items(), key=lambda x: x[1], reverse=True)
                prioritized_tools = []
                
                for tool, effectiveness in sorted_tools:
                    if tool in available_tools:
                        prioritized_tools.append(f"- {tool} (Effectiveness: {effectiveness:.2f})")
                
                # Add other available tools
                for tool in available_tools:
                    if not any(tool in pt for pt in prioritized_tools):
                        prioritized_tools.append(f"- {tool}")
                
                return "\n".join(prioritized_tools)
        
        return available_tools
    
    def get_system_prompt(self) -> str:
        """Get the enhanced system prompt with learning capabilities"""
        base_prompt = f"""You are an intelligent {self.agent_type.value.replace('_', ' ')} agent specialized in penetration testing.

Your role is to:
1. Analyze the given task and target using learned patterns
2. Execute appropriate commands using available tools (prioritizing effective ones)
3. Interpret results and identify findings
4. Suggest next steps or additional tasks based on learned strategies
5. Adapt your approach based on target characteristics and previous successes

IMPORTANT: Use your learning to make intelligent decisions about:
- Which tools to use based on their effectiveness for this target type
- What parameters to use based on previous successful configurations
- How to prioritize findings and next steps
- When to try alternative approaches if initial attempts fail

Available Tools:
{self._get_available_tools()}

RESPONSE FORMAT:
{{
    "analysis": "Your intelligent analysis considering learned patterns",
    "strategy": "Your chosen strategy based on learning and context",
    "findings": [
        {{
            "type": "finding_type",
            "severity": "low/medium/high/critical",
            "description": "Description of the finding",
            "evidence": "Evidence from the scan",
            "recommendation": "What to do next",
            "confidence": "high/medium/low"
        }}
    ],
    "next_tasks": [
        {{
            "agent_type": "agent_type",
            "description": "Task description",
            "parameters": {{"param": "value"}},
            "priority": 1,
            "reasoning": "Why this task is suggested"
        }}
    ],
    "learning_insights": "What you learned from this execution",
    "status": "completed/requires_followup/failed"
}}

Always respond in valid JSON format."""
        return base_prompt
    
    def _get_available_tools(self) -> str:
        """Get available tools for this agent"""
        if hasattr(self.tools, 'get_installed_tools'):
            installed = self.tools.get_installed_tools()
            tools_list = []
            for tool in installed:
                if self._is_tool_relevant(tool):
                    tools_list.append(f"- {tool}")
            return "\n".join(tools_list)
        return "All tools available"
    
    def _is_tool_relevant(self, tool: str) -> bool:
        """Check if a tool is relevant for this agent type"""
        tool_mapping = {
            AgentType.RECONNAISSANCE: ['nmap', 'dig', 'whois', 'dnsrecon', 'sublist3r', 'theharvester'],
            AgentType.VULNERABILITY_ASSESSMENT: ['nuclei', 'vulners', 'sslyze', 'testssl.sh'],
            AgentType.WEB_TESTING: ['feroxbuster', 'sqlmap', 'wpscan', 'whatweb', 'httpx', 'ffuf'],
            AgentType.EXPLOITATION: ['hydra', 'john', 'hashcat', 'sqlmap', 'metasploit']
        }
        return tool in tool_mapping.get(self.agent_type, [])
    
    async def execute_task(self, task: AgentTask) -> AgentResult:
        """Execute a task with enhanced AI intelligence"""
        self.status = AgentStatus.WORKING
        debug_print(f"Agent {self.agent_type.value} executing task: {task.id}")
        
        try:
            # Build adaptive prompt for this task
            prompt = self._build_adaptive_task_prompt(task)
            
            # Get agent's intelligent response
            response = self._get_agent_response(prompt, task)
            
            # Parse the enhanced response
            parsed_response = self._parse_agent_response(response)
            
            # Execute any commands suggested by the agent
            executed_commands = await self._execute_suggested_commands(parsed_response, task)
            
            # Create result
            result = AgentResult(
                task_id=task.id,
                agent_type=self.agent_type,
                target=task.target,
                success=parsed_response.get('status') != 'failed',
                output=response,
                findings=parsed_response.get('findings', []),
                next_tasks=self._create_intelligent_next_tasks(parsed_response, task),
                metadata={
                    'executed_commands': executed_commands,
                    'strategy': parsed_response.get('strategy', ''),
                    'learning_insights': parsed_response.get('learning_insights', ''),
                    'confidence': parsed_response.get('confidence', 'medium')
                }
            )
            
            # Learn from the result
            self._learn_from_result(task, result)
            
            # Update context history
            self._update_context_history(task, result)
            
            self.status = AgentStatus.COMPLETED
            return result
            
        except Exception as e:
            debug_print(f"Agent {self.agent_type.value} failed: {e}")
            self.status = AgentStatus.FAILED
            error_msg = str(e)
            return AgentResult(
                task_id=task.id,
                agent_type=self.agent_type,
                target=task.target,
                success=False,
                output=error_msg,
                findings=[],
                next_tasks=[],
                metadata={'error': error_msg}
            )
    
    def _build_adaptive_task_prompt(self, task: AgentTask) -> str:
        """Build an adaptive prompt for the given task"""
        target_type = self._get_target_type(task.target)
        
        prompt = f"""TARGET: {task.target}
TARGET TYPE: {target_type}
TASK: {task.description}
PARAMETERS: {json.dumps(task.parameters, indent=2)}

Analyze the target using your learned patterns and execute appropriate {self.agent_type.value.replace('_', ' ')} tasks.
Consider your previous successes and failures for similar target types.
Provide your analysis, findings, and suggest next steps with reasoning."""

        # Add learning context if available
        if target_type in self.learning_memory:
            memory = self.learning_memory[target_type]
            if memory.successful_techniques:
                prompt += f"\n\nLEARNING: You have {len(memory.successful_techniques)} successful techniques for {target_type} targets."
        
        return prompt
    
    def _get_agent_response(self, prompt: str, task: AgentTask) -> str:
        """Get response from the agent's model with enhanced context"""
        # Create messages for the model with adaptive prompt
        messages = [
            {"role": "system", "content": self._get_adaptive_prompt(task)},
            {"role": "user", "content": prompt}
        ]
        
        # Get response from model
        response = self.model.get_chat_completion(messages)
        return response
    
    def _parse_agent_response(self, response: str) -> Dict[str, Any]:
        """Parse the agent's enhanced JSON response"""
        try:
            parsed = json.loads(response)
            
            # Ensure all required fields are present
            if 'findings' not in parsed:
                parsed['findings'] = []
            if 'next_tasks' not in parsed:
                parsed['next_tasks'] = []
            if 'status' not in parsed:
                parsed['status'] = 'completed'
            if 'strategy' not in parsed:
                parsed['strategy'] = 'standard'
            if 'learning_insights' not in parsed:
                parsed['learning_insights'] = ''
            
            return parsed
        except json.JSONDecodeError:
            debug_print(f"Failed to parse agent response: {response}")
            return {
                "analysis": "Failed to parse response",
                "strategy": "fallback",
                "findings": [],
                "next_tasks": [],
                "status": "failed",
                "learning_insights": "Response parsing failed"
            }
    
    async def _execute_suggested_commands(self, parsed_response: Dict[str, Any], task: AgentTask) -> List[Dict[str, Any]]:
        """Execute commands suggested by the intelligent agent asynchronously"""
        executed = []
        # Look for commands in the response
        if 'command' in parsed_response:
            command = parsed_response['command']
            result = await self.tools.async_execute_command(command, task.target)
            executed.append({
                'command': command,
                'success': result.success,
                'output': result.output,
                'error': result.error
            })
        return executed
    
    def _create_intelligent_next_tasks(self, parsed_response: Dict[str, Any], current_task: AgentTask) -> List[AgentTask]:
        """Create intelligent next tasks based on agent response and learning"""
        next_tasks = []
        
        for task_suggestion in parsed_response.get('next_tasks', []):
            # Add reasoning to task parameters
            parameters = task_suggestion.get('parameters', {})
            parameters['reasoning'] = task_suggestion.get('reasoning', 'No reasoning provided')
            
            task = AgentTask(
                id=f"{current_task.id}_followup_{len(next_tasks)}",
                agent_type=AgentType(task_suggestion.get('agent_type', 'reconnaissance')),
                target=current_task.target,
                description=task_suggestion.get('description', ''),
                parameters=parameters,
                priority=task_suggestion.get('priority', 1),
                dependencies=[current_task.id]
            )
            next_tasks.append(task)
        
        return next_tasks
    
    def get_learning_summary(self) -> Dict[str, Any]:
        """Get a summary of the agent's learning"""
        summary = {
            'agent_type': self.agent_type.value,
            'target_types_learned': list(self.learning_memory.keys()),
            'total_successful_techniques': sum(len(mem.successful_techniques) for mem in self.learning_memory.values()),
            'total_failed_techniques': sum(len(mem.failed_techniques) for mem in self.learning_memory.values()),
            'most_effective_tools': {},
            'recent_context': self.context_history[-5:] if self.context_history else []
        }
        
        # Get most effective tools for each target type
        for target_type, memory in self.learning_memory.items():
            if memory.tool_effectiveness:
                best_tool = max(memory.tool_effectiveness.items(), key=lambda x: x[1])
                summary['most_effective_tools'][target_type] = {
                    'tool': best_tool[0],
                    'effectiveness': best_tool[1]
                }
        
        return summary

class ReconnaissanceAgent(BaseAgent):
    """Agent specialized in reconnaissance tasks with enhanced learning"""
    
    def __init__(self, tools, model):
        super().__init__(AgentType.RECONNAISSANCE, tools, model)
    
    def get_system_prompt(self) -> str:
        return super().get_system_prompt() + """

SPECIFIC TASKS:
- Port scanning and service enumeration with intelligent port selection
- DNS enumeration and subdomain discovery using learned patterns
- Network topology mapping with adaptive scanning strategies
- OSINT gathering with context-aware information collection
- Technology stack identification with learning from previous scans

LEARNING FOCUS:
- Remember which ports are most likely to be open for different target types
- Learn which DNS enumeration techniques work best for different domains
- Adapt scanning intensity based on target response patterns
- Use learned patterns to prioritize reconnaissance activities

Focus on gathering comprehensive information about the target while being efficient and non-intrusive."""

class VulnerabilityAssessmentAgent(BaseAgent):
    """Agent specialized in vulnerability assessment with intelligent prioritization"""
    
    def __init__(self, tools, model):
        super().__init__(AgentType.VULNERABILITY_ASSESSMENT, tools, model)
    
    def get_system_prompt(self) -> str:
        return super().get_system_prompt() + """

SPECIFIC TASKS:
- Vulnerability scanning with intelligent tool selection based on target type
- SSL/TLS security assessment with learned configuration patterns
- Service-specific vulnerability checks using adaptive strategies
- CVE correlation and analysis with risk-based prioritization
- Risk assessment and prioritization using learned impact patterns

LEARNING FOCUS:
- Remember which vulnerabilities are most common for different service types
- Learn which scanning techniques are most effective for different targets
- Adapt scanning depth based on target characteristics and previous findings
- Use learned patterns to prioritize high-impact vulnerabilities first

Focus on identifying security weaknesses efficiently while minimizing false positives."""

class WebTestingAgent(BaseAgent):
    """Agent specialized in web application testing with adaptive strategies"""
    
    def __init__(self, tools, model):
        super().__init__(AgentType.WEB_TESTING, tools, model)
    
    def get_system_prompt(self) -> str:
        return super().get_system_prompt() + """

SPECIFIC TASKS:
- Web application enumeration with intelligent path discovery
- Directory and file discovery using learned common patterns
- SQL injection testing with adaptive payload selection
- XSS and other web vulnerabilities with context-aware testing
- CMS-specific testing (WordPress, etc.) with learned CMS patterns
- API endpoint discovery and testing with intelligent parameter analysis

LEARNING FOCUS:
- Remember which web paths are most commonly vulnerable for different frameworks
- Learn which injection techniques work best for different web technologies
- Adapt testing intensity based on web server responses and error patterns
- Use learned patterns to identify common web application weaknesses

Focus on web-specific security issues while being efficient and avoiding detection."""

class ExploitationAgent(BaseAgent):
    """Agent specialized in exploitation tasks with intelligent approach selection"""
    
    def __init__(self, tools, model):
        super().__init__(AgentType.EXPLOITATION, tools, model)
    
    def get_system_prompt(self) -> str:
        return super().get_system_prompt() + """

SPECIFIC TASKS:
- Password cracking and brute force with intelligent wordlist selection
- Exploiting identified vulnerabilities using learned exploitation patterns
- Privilege escalation attempts with adaptive strategy selection
- Post-exploitation activities with context-aware approach
- Proof of concept development with risk-aware execution

LEARNING FOCUS:
- Remember which exploitation techniques work best for different vulnerability types
- Learn which password cracking strategies are most effective for different targets
- Adapt exploitation approach based on target characteristics and previous attempts
- Use learned patterns to prioritize high-probability exploitation attempts

WARNING: Only perform exploitation on authorized targets and within scope.
Always consider the potential impact and risk before attempting exploitation."""

class CoordinatorAgent(BaseAgent):
    """Intelligent coordinator agent that manages the overall testing process with learning"""
    
    def __init__(self, tools, model):
        super().__init__(AgentType.COORDINATOR, tools, model)
        self.agents = {}
        self.task_history = []
        self.current_phase = "initial"
        self.strategy_memory = {}  # Store successful strategies for different target types
        self.agent_performance = defaultdict(list)  # Track agent performance over time
    
    def get_system_prompt(self) -> str:
        return """You are an intelligent penetration testing coordinator agent with learning capabilities.

Your role is to:
1. Analyze the overall testing situation using learned patterns
2. Coordinate between different specialized agents with intelligent task distribution
3. Prioritize tasks and findings based on learned risk patterns
4. Manage the testing workflow with adaptive strategies
5. Provide strategic guidance based on historical success patterns
6. Learn from successful coordination strategies and agent performance

LEARNING FOCUS:
- Remember which agent combinations work best for different target types
- Learn which task sequences lead to the most comprehensive findings
- Adapt coordination strategy based on target characteristics and agent performance
- Use learned patterns to optimize the testing workflow and resource allocation

RESPONSE FORMAT:
{
    "phase": "current_phase",
    "strategy": "Your chosen coordination strategy based on learning",
    "analysis": "Overall analysis considering learned patterns",
    "priorities": [
        {
            "agent_type": "agent_type",
            "reason": "Why this is important based on learned patterns",
            "urgency": "high/medium/low",
            "confidence": "high/medium/low"
        }
    ],
    "next_actions": [
        {
            "agent_type": "agent_type",
            "description": "What to do next",
            "parameters": {"param": "value"},
            "priority": 1,
            "reasoning": "Why this action is suggested"
        }
    ],
    "findings_summary": [
        {
            "type": "finding_type",
            "severity": "severity",
            "description": "Description",
            "confidence": "high/medium/low"
        }
    ],
    "learning_insights": "What you learned from this coordination",
    "status": "continuing/completed/paused"
}

Always respond in valid JSON format."""
    
    def register_agent(self, agent: BaseAgent):
        """Register an agent with the coordinator"""
        self.agents[agent.agent_type] = agent
        debug_print(f"Registered agent: {agent.agent_type.value}")
    
    def _learn_from_coordination(self, target: str, results: List[AgentResult]):
        """Learn from coordination results"""
        target_type = self._get_target_type(target)
        
        # Analyze agent performance
        for result in results:
            agent_type = result.agent_type.value
            performance = {
                'success': result.success,
                'findings_count': len(result.findings),
                'severity_distribution': self._analyze_severity_distribution(result.findings),
                'timestamp': datetime.now()
            }
            self.agent_performance[agent_type].append(performance)
        
        # Store successful strategy
        if any(r.success for r in results):
            strategy = {
                'target_type': target_type,
                'agent_sequence': [r.agent_type.value for r in results],
                'success_rate': len([r for r in results if r.success]) / len(results),
                'total_findings': sum(len(r.findings) for r in results),
                'timestamp': datetime.now()
            }
            
            if target_type not in self.strategy_memory:
                self.strategy_memory[target_type] = []
            self.strategy_memory[target_type].append(strategy)
    
    def _analyze_severity_distribution(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Analyze the distribution of finding severities"""
        distribution = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for finding in findings:
            severity = finding.get('severity', 'low')
            if severity in distribution:
                distribution[severity] += 1
        return distribution
    
    def _get_intelligent_coordination_strategy(self, target: str, target_type: str) -> Dict[str, Any]:
        """Get intelligent coordination strategy based on learning"""
        strategy = {
            'agent_priority': [],
            'expected_findings': 0,
            'confidence': 'medium'
        }
        
        # Use learned strategies if available
        if target_type in self.strategy_memory:
            strategies = self.strategy_memory[target_type]
            if strategies:
                # Find the most successful strategy
                best_strategy = max(strategies, key=lambda s: s['success_rate'])
                strategy['agent_priority'] = best_strategy['agent_sequence']
                strategy['expected_findings'] = best_strategy['total_findings']
                strategy['confidence'] = 'high' if best_strategy['success_rate'] > 0.8 else 'medium'
        
        # Fallback to default strategy
        if not strategy['agent_priority']:
            strategy['agent_priority'] = ['reconnaissance', 'vulnerability_assessment', 'web_testing']
        
        return strategy
    
    async def coordinate_testing(self, target: str, initial_scan_results: str = None) -> List[AgentResult]:
        """Coordinate the overall penetration testing process with intelligent learning"""
        debug_print(f"Starting intelligent coordinated testing for target: {target}")
        
        target_type = self._get_target_type(target)
        strategy = self._get_intelligent_coordination_strategy(target, target_type)
        
        # Create initial task with strategy information
        initial_task = AgentTask(
            id="coordinator_initial",
            agent_type=AgentType.COORDINATOR,
            target=target,
            description="Intelligent initial assessment and planning",
            parameters={
                "initial_scan": initial_scan_results,
                "phase": "initial",
                "target_type": target_type,
                "strategy": strategy,
                "agent_priority": strategy['agent_priority']
            }
        )
        
        # Execute initial coordination
        result = await self.execute_task(initial_task)
        self.task_history.append(result)
        
        # Process the coordination result and create next tasks
        all_results = [result]
        
        # Create tasks for other agents based on coordinator's intelligent analysis
        for next_action in result.next_tasks:
            if next_action.agent_type in self.agents:
                agent = self.agents[next_action.agent_type]
                agent_result = await agent.execute_task(next_action)
                all_results.append(agent_result)
                self.task_history.append(agent_result)
        
        # Learn from the coordination results
        self._learn_from_coordination(target, all_results)
        
        return all_results
    
    def get_coordination_summary(self) -> Dict[str, Any]:
        """Get a summary of coordination learning and performance"""
        summary = {
            'target_types_coordinated': list(self.strategy_memory.keys()),
            'total_strategies_learned': sum(len(strategies) for strategies in self.strategy_memory.values()),
            'agent_performance': {},
            'best_strategies': {}
        }
        
        # Analyze agent performance
        for agent_type, performances in self.agent_performance.items():
            if performances:
                success_rate = len([p for p in performances if p['success']]) / len(performances)
                avg_findings = sum(p['findings_count'] for p in performances) / len(performances)
                summary['agent_performance'][agent_type] = {
                    'success_rate': success_rate,
                    'avg_findings': avg_findings,
                    'total_executions': len(performances)
                }
        
        # Get best strategies for each target type
        for target_type, strategies in self.strategy_memory.items():
            if strategies:
                best_strategy = max(strategies, key=lambda s: s['success_rate'])
                summary['best_strategies'][target_type] = {
                    'agent_sequence': best_strategy['agent_sequence'],
                    'success_rate': best_strategy['success_rate'],
                    'avg_findings': best_strategy['total_findings']
                }
        
        return summary

class AgentManager:
    """Manages multiple agents and their coordination"""
    def __init__(self, tools, model, config: Config = None, concurrency_limit: int = 3):
        self.config = config or Config()
        self.tools = tools
        self.model = model
        self.agents = {}
        self.coordinator = None
        self.task_queue = queue.Queue()
        self.results = []
        self.concurrency_limit = concurrency_limit
        self._semaphore = asyncio.Semaphore(concurrency_limit)
        # Initialize agents
        self._initialize_agents()
    
    def _initialize_agents(self):
        """Initialize all available agents"""
        debug_print("Initializing agents...")
        
        # Create specialized agents
        self.agents[AgentType.RECONNAISSANCE] = ReconnaissanceAgent(self.tools, self.model)
        self.agents[AgentType.VULNERABILITY_ASSESSMENT] = VulnerabilityAssessmentAgent(self.tools, self.model)
        self.agents[AgentType.WEB_TESTING] = WebTestingAgent(self.tools, self.model)
        self.agents[AgentType.EXPLOITATION] = ExploitationAgent(self.tools, self.model)
        
        # Create coordinator
        self.coordinator = CoordinatorAgent(self.tools, self.model)
        
        # Register agents with coordinator
        for agent in self.agents.values():
            self.coordinator.register_agent(agent)
        
        debug_print(f"Initialized {len(self.agents)} agents plus coordinator")
    
    async def run_agent_testing(self, target: str, initial_scan_results: str = None) -> List[AgentResult]:
        debug_print(f"Starting agent-based testing for target: {target}")
        results = await self.coordinator.coordinate_testing(target, initial_scan_results)
        all_results = results.copy()
        max_iterations = 10  # Prevent infinite loops
        iteration = 0
        while iteration < max_iterations:
            iteration += 1
            debug_print(f"Agent testing iteration {iteration}")
            next_tasks = []
            for result in results:
                next_tasks.extend(result.next_tasks)
            if not next_tasks:
                debug_print("No more tasks to process")
                break
            # Execute next tasks concurrently with rate limiting
            new_results = []
            async def run_task_with_limit(agent, task):
                async with self._semaphore:
                    return await agent.execute_task(task)
            tasks = []
            for task in next_tasks:
                if task.agent_type in self.agents:
                    agent = self.agents[task.agent_type]
                    tasks.append(run_task_with_limit(agent, task))
            if tasks:
                new_results = await asyncio.gather(*tasks)
            if not new_results:
                debug_print("No new results generated")
                break
            results = new_results
            all_results.extend(results)
        debug_print(f"Agent testing completed with {len(all_results)} total results")
        return all_results
    
    def get_agent_status(self) -> Dict[str, Any]:
        """Get status of all agents"""
        status = {}
        for agent_type, agent in self.agents.items():
            status[agent_type.value] = {
                'status': agent.status.value,
                'results_count': len(agent.results)
            }
        
        if self.coordinator:
            status['coordinator'] = {
                'status': self.coordinator.status.value,
                'results_count': len(self.coordinator.results)
            }
        
        return status
    
    def get_findings_summary(self) -> List[Dict[str, Any]]:
        """Get a summary of all findings from all agents with learning insights"""
        findings = []
        
        for agent in self.agents.values():
            for result in agent.results:
                findings.extend(result.findings)
        
        if self.coordinator:
            for result in self.coordinator.results:
                findings.extend(result.findings)
        
        return findings
    
    def get_learning_summary(self) -> Dict[str, Any]:
        """Get a comprehensive learning summary from all agents"""
        summary = {
            'agents': {},
            'coordinator': None,
            'overall_insights': {}
        }
        
        # Get learning summaries from all agents
        for agent_type, agent in self.agents.items():
            summary['agents'][agent_type.value] = agent.get_learning_summary()
        
        # Get coordinator learning summary
        if self.coordinator:
            summary['coordinator'] = self.coordinator.get_coordination_summary()
        
        # Calculate overall insights
        total_successful_techniques = sum(
            agent_summary['total_successful_techniques'] 
            for agent_summary in summary['agents'].values()
        )
        total_failed_techniques = sum(
            agent_summary['total_failed_techniques'] 
            for agent_summary in summary['agents'].values()
        )
        
        summary['overall_insights'] = {
            'total_successful_techniques': total_successful_techniques,
            'total_failed_techniques': total_failed_techniques,
            'success_rate': total_successful_techniques / (total_successful_techniques + total_failed_techniques) if (total_successful_techniques + total_failed_techniques) > 0 else 0,
            'target_types_learned': set().union(*[set(agent_summary['target_types_learned']) for agent_summary in summary['agents'].values()])
        }
        
        return summary 
