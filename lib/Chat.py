import os
import json
import asyncio
from lib.Tools import Tools, CommandResult
from typing import Tuple, List, Dict, Optional
from .Model import Model
from .Agents import AgentManager, AgentType, AgentTask
from lib.logging_utils import debug_print
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
        
        # Initialize agent manager for enhanced capabilities
        self.agent_manager = AgentManager(tools, model)
        self.agent_results = []

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

    def _handle_agent_commands(self, user_input: str) -> bool:
        """Handle agent-specific commands and return True if handled"""
        input_lower = user_input.lower()
        
        # Agent-specific commands
        if input_lower.startswith('agent ') or input_lower.startswith('use agent '):
            return self._handle_agent_task(user_input)
        
        elif input_lower.startswith('agents') or input_lower == 'show agents':
            self._show_available_agents()
            return True
        
        elif input_lower.startswith('agent status') or input_lower == 'agents status':
            self._show_agent_status()
            return True
        
        elif input_lower.startswith('agent results') or input_lower == 'show agent results':
            self._show_agent_results()
            return True
        
        elif input_lower.startswith('coordinator') or input_lower == 'use coordinator':
            return self._handle_coordinator_task(user_input)
        
        elif input_lower.startswith('recon') or input_lower.startswith('reconnaissance'):
            return self._handle_reconnaissance_task(user_input)
        
        elif input_lower.startswith('vuln') or input_lower.startswith('vulnerability'):
            return self._handle_vulnerability_task(user_input)
        
        elif input_lower.startswith('web') or input_lower.startswith('web testing'):
            return self._handle_web_testing_task(user_input)
        
        elif input_lower.startswith('exploit') or input_lower.startswith('exploitation'):
            return self._handle_exploitation_task(user_input)
        
        return False

    def _handle_agent_task(self, user_input: str) -> bool:
        """Handle general agent task requests"""
        try:
            # Extract agent type and task description
            parts = user_input.split(' ', 2)
            if len(parts) < 3:
                print("Usage: agent <agent_type> <task_description>")
                print("Example: agent reconnaissance perform DNS enumeration")
                return True
            
            agent_type_str = parts[1].lower()
            task_description = parts[2]
            
            # Map agent type strings to AgentType enum
            agent_type_map = {
                'recon': AgentType.RECONNAISSANCE,
                'reconnaissance': AgentType.RECONNAISSANCE,
                'vuln': AgentType.VULNERABILITY_ASSESSMENT,
                'vulnerability': AgentType.VULNERABILITY_ASSESSMENT,
                'web': AgentType.WEB_TESTING,
                'exploit': AgentType.EXPLOITATION,
                'exploitation': AgentType.EXPLOITATION,
                'coordinator': AgentType.COORDINATOR
            }
            
            if agent_type_str not in agent_type_map:
                print(f"Unknown agent type: {agent_type_str}")
                print("Available agent types: recon, vulnerability, web, exploitation, coordinator")
                return True
            
            agent_type = agent_type_map[agent_type_str]
            return self._execute_agent_task(agent_type, task_description)
            
        except Exception as e:
            print(f"Error handling agent task: {e}")
            return True

    def _execute_agent_task(self, agent_type: AgentType, task_description: str) -> bool:
        """Execute a task with a specific agent"""
        try:
            print(f"\n🤖 Executing {agent_type.value} task: {task_description}")
            
            # Create task
            task = AgentTask(
                id=f"manual_{agent_type.value}_{len(self.agent_results)}",
                agent_type=agent_type,
                target=self.model.target,
                description=task_description,
                parameters={},
                priority=1
            )
            
            # Get the appropriate agent
            if agent_type == AgentType.COORDINATOR:
                agent = self.agent_manager.coordinator
            else:
                agent = self.agent_manager.agents[agent_type]
            
            # Execute task asynchronously
            async def run_task():
                result = await agent.execute_task(task)
                self.agent_results.append(result)
                
                # Display results
                print(f"\n✅ {agent_type.value.replace('_', ' ').title()} task completed")
                print(f"Success: {result.success}")
                print(f"Findings: {len(result.findings)}")
                
                if result.findings:
                    print("\n🔍 Findings:")
                    for finding in result.findings:
                        severity_emoji = {
                            'critical': '🔴',
                            'high': '🟠',
                            'medium': '🟡',
                            'low': '🟢'
                        }.get(finding.get('severity', 'low'), '⚪')
                        
                        print(f"  {severity_emoji} {finding.get('type', 'Unknown')}: {finding.get('description', 'No description')}")
                
                if result.next_tasks:
                    print(f"\n📋 Suggested next tasks ({len(result.next_tasks)}):")
                    for i, next_task in enumerate(result.next_tasks, 1):
                        print(f"  {i}. {next_task.description}")
            
            # Run the task
            asyncio.run(run_task())
            return True
            
        except Exception as e:
            print(f"Error executing agent task: {e}")
            return True

    def _handle_coordinator_task(self, user_input: str) -> bool:
        """Handle coordinator-specific tasks"""
        task_description = user_input.replace('coordinator', '').replace('use coordinator', '').strip()
        if not task_description:
            task_description = "Analyze current situation and suggest next steps"
        
        return self._execute_agent_task(AgentType.COORDINATOR, task_description)

    def _handle_reconnaissance_task(self, user_input: str) -> bool:
        """Handle reconnaissance-specific tasks"""
        task_description = user_input.replace('recon', '').replace('reconnaissance', '').strip()
        if not task_description:
            task_description = "Perform comprehensive reconnaissance"
        
        return self._execute_agent_task(AgentType.RECONNAISSANCE, task_description)

    def _handle_vulnerability_task(self, user_input: str) -> bool:
        """Handle vulnerability assessment tasks"""
        task_description = user_input.replace('vuln', '').replace('vulnerability', '').strip()
        if not task_description:
            task_description = "Perform vulnerability assessment"
        
        return self._execute_agent_task(AgentType.VULNERABILITY_ASSESSMENT, task_description)

    def _handle_web_testing_task(self, user_input: str) -> bool:
        """Handle web testing tasks"""
        task_description = user_input.replace('web', '').replace('web testing', '').strip()
        if not task_description:
            task_description = "Perform web application testing"
        
        return self._execute_agent_task(AgentType.WEB_TESTING, task_description)

    def _handle_exploitation_task(self, user_input: str) -> bool:
        """Handle exploitation tasks"""
        task_description = user_input.replace('exploit', '').replace('exploitation', '').strip()
        if not task_description:
            task_description = "Perform exploitation attempts"
        
        return self._execute_agent_task(AgentType.EXPLOITATION, task_description)

    def _show_available_agents(self):
        """Show available agents and their capabilities"""
        print("\n🤖 Available Agents:")
        print("=" * 40)
        
        agents = [
            ("Reconnaissance", "Port scanning, DNS enumeration, OSINT gathering"),
            ("Vulnerability Assessment", "Vulnerability scanning, SSL/TLS testing, CVE analysis"),
            ("Web Testing", "Web app testing, SQL injection, XSS, CMS testing"),
            ("Exploitation", "Password cracking, vulnerability exploitation, PoC development"),
            ("Coordinator", "Orchestrates all agents, manages workflow and strategy")
        ]
        
        for name, description in agents:
            print(f"\n🔍 {name} Agent:")
            print(f"   {description}")
        
        print("\n💡 Usage Examples:")
        print("  - agent reconnaissance perform DNS enumeration")
        print("  - agent vulnerability scan for common vulnerabilities")
        print("  - agent web test for SQL injection")
        print("  - agent exploitation attempt password cracking")
        print("  - coordinator analyze and plan next steps")

    def _show_agent_status(self):
        """Show status of all agents"""
        status = self.agent_manager.get_agent_status()
        
        print("\n🤖 Agent Status:")
        print("=" * 30)
        
        for agent_type, agent_status in status.items():
            status_emoji = {
                'idle': '⚪',
                'working': '🟡',
                'completed': '🟢',
                'failed': '🔴',
                'waiting': '🟠'
            }.get(agent_status['status'], '❓')
            
            print(f"{status_emoji} {agent_type.replace('_', ' ').title()}: {agent_status['status']} ({agent_status['results_count']} results)")

    def _show_agent_results(self):
        """Show results from all agent executions"""
        if not self.agent_results:
            print("\n📋 No agent results available yet.")
            print("Use agent commands to execute tasks.")
            return
        
        print(f"\n📊 Agent Results ({len(self.agent_results)} total):")
        print("=" * 50)
        
        for i, result in enumerate(self.agent_results, 1):
            status = "✅" if result.success else "❌"
            print(f"\n{i}. {status} {result.agent_type.value.replace('_', ' ').title()}")
            print(f"   Task: {result.task_id}")
            print(f"   Target: {result.target}")
            print(f"   Findings: {len(result.findings)}")
            
            if result.findings:
                print("   Key findings:")
                for finding in result.findings[:3]:  # Show first 3 findings
                    severity_emoji = {
                        'critical': '🔴',
                        'high': '🟠',
                        'medium': '🟡',
                        'low': '🟢'
                    }.get(finding.get('severity', 'low'), '⚪')
                    
                    print(f"     {severity_emoji} {finding.get('type', 'Unknown')}: {finding.get('description', 'No description')}")

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
        
        elif input_lower.startswith('correlations') or input_lower.startswith('correlate'):
            target = None
            if ' ' in user_input:
                target = user_input.split(' ', 1)[1]
            self._show_vulnerability_correlations(target)
            return True
        
        elif input_lower.startswith('temporal') or input_lower.startswith('trends'):
            target = None
            days = 30
            if ' ' in user_input:
                parts = user_input.split(' ')
                if len(parts) >= 2:
                    target = parts[1]
                if len(parts) >= 3 and parts[2].isdigit():
                    days = int(parts[2])
            self._show_temporal_analysis(target, days)
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
        """Show enhanced summary of all scan results with vulnerability analysis"""
        if not self.tools.is_rag_available():
            print("\n❌ RAG system not available.")
            return
        
        summary = self.tools.get_scan_summary()
        
        if "message" in summary:
            print(f"\n📋 {summary['message']}")
            return
        
        print(f"\n📊 Enhanced Scan Results Summary:")
        print(f"Total Documents: {summary['total_documents']}")
        print(f"Index Type: {summary['index_type']}")
        
        # Show vulnerability statistics if available
        if 'vulnerability_statistics' in summary:
            vuln_stats = summary['vulnerability_statistics']
            print(f"\n🔍 Vulnerability Analysis:")
            print(f"  Total Findings: {vuln_stats['total_findings']}")
            
            if 'by_severity' in vuln_stats:
                print(f"  By Severity:")
                for severity, count in vuln_stats['by_severity'].items():
                    severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(severity, '⚪')
                    print(f"    {severity_emoji} {severity.title()}: {count}")
            
            if 'by_type' in vuln_stats:
                print(f"  By Type (Top 5):")
                for vuln_type, count in list(vuln_stats['by_type'].items())[:5]:
                    print(f"    - {vuln_type.replace('_', ' ').title()}: {count}")
        
        # Show automated insights if available
        if 'automated_insights' in summary:
            insights = summary['automated_insights']
            if insights:
                print(f"\n🧠 Automated Insights:")
                for insight in insights[:3]:  # Show top 3 insights
                    priority_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(insight['priority'], '⚪')
                    print(f"  {priority_emoji} {insight['title']}")
                    print(f"    {insight['description']}")
                    if insight['details']:
                        for detail in insight['details'][:2]:  # Show first 2 details
                            print(f"    - {detail}")
        
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
    
    def _show_vulnerability_correlations(self, target: str = None):
        """Show vulnerability correlations"""
        if not self.tools.is_rag_available():
            print("\n❌ RAG system not available.")
            return
        
        correlations = self.tools.get_vulnerability_correlations(target)
        
        if not correlations:
            print(f"\n📊 No vulnerability correlations found{f' for {target}' if target else ''}")
            return
        
        print(f"\n🔗 Vulnerability Correlations{f' for {target}' if target else ''}:")
        for i, corr in enumerate(correlations, 1):
            print(f"\n{i}. Primary Finding:")
            primary = corr['primary_finding']
            severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(primary['severity'], '⚪')
            print(f"   {severity_emoji} {primary['type'].replace('_', ' ').title()} ({primary['severity']}) on {primary['target']}")
            print(f"   Description: {primary['description']}")
            
            if corr['correlated_findings']:
                print(f"   Correlated Findings ({len(corr['correlated_findings'])}):")
                for finding in corr['correlated_findings'][:3]:  # Show first 3
                    severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(finding['severity'], '⚪')
                    print(f"     {severity_emoji} {finding['type'].replace('_', ' ').title()} ({finding['severity']}) on {finding['target']}")
            
            print(f"   Correlation Strength: {corr['correlation_strength']:.2f}")
            print(f"   Correlation Type: {corr['correlation_type'].replace('_', ' ').title()}")
            if corr['attack_path']:
                print(f"   Attack Path: {' -> '.join(corr['attack_path'])}")
    
    def _show_temporal_analysis(self, target: str, days: int = 30):
        """Show temporal analysis for a target"""
        if not self.tools.is_rag_available():
            print("\n❌ RAG system not available.")
            return
        
        analysis = self.tools.get_temporal_analysis(target, days)
        
        if "message" in analysis:
            print(f"\n📊 {analysis['message']}")
            return
        
        print(f"\n📈 Temporal Analysis for {target} ({analysis['time_period']}):")
        print(f"  Scan Frequency: {analysis['scan_frequency']} scans")
        
        if analysis['vulnerability_trends']:
            print(f"  Vulnerability Trends:")
            for vuln_type, count in analysis['vulnerability_trends'].items():
                print(f"    - {vuln_type.replace('_', ' ').title()}: {count}")
        
        if analysis['tool_usage_trends']:
            print(f"  Tool Usage Trends:")
            for tool, count in analysis['tool_usage_trends'].items():
                print(f"    - {tool}: {count} scans")
        
        if analysis['risk_score_trend']:
            avg_risk = sum(analysis['risk_score_trend']) / len(analysis['risk_score_trend'])
            print(f"  Average Risk Score: {avg_risk:.2f}")
            print(f"  Risk Trend: {len(analysis['risk_score_trend'])} data points")

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

    async def start_chat(self, initial_prompt: str) -> str:
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
        response = await self.model.get_chat_completion(self.chat_history)
        self.chat_history.append({"role": "assistant", "content": response})
        
        # Display response and check for vulnerability
        data = self._display_response(response)
        self._check_for_vulnerability(data)
        
        # Process commands if not in interactive mode
        if not self.interactive_mode:
            commands = self._extract_commands(response)
            if commands:
                await self._execute_commands(commands, initial_prompt.split('\n')[0].replace('Target: ', ''))
        
        return response

    async def handle_user_input(self, user_input: str, target: str) -> str:
        """Handle user input and return model's response"""
        # Check if this is an agent command first
        if self._handle_agent_commands(user_input):
            return "Agent command handled"
        
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
        response = await self.model.get_chat_completion(self.chat_history)
        self.chat_history.append({"role": "assistant", "content": response})
        
        # Display response and check for vulnerability
        data = self._display_response(response)
        self._check_for_vulnerability(data)
        
        # Process commands
        commands = self._extract_commands(response)
        if commands:
            if self.interactive_mode:
                # In interactive mode, ask user for approval without blocking the event loop
                chosen_command = await asyncio.to_thread(
                    self._get_user_command_choice, commands
                )
                if chosen_command:
                    await self._execute_commands([chosen_command], target)
            else:
                # In automatic mode, execute all commands
                await self._execute_commands(commands, target)
        
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

    async def _execute_commands(self, commands: List[str], target: str):
        """Execute a list of commands asynchronously and get follow-up analysis"""
        for command in commands:
            print(f"\n🚀 Executing: {command}")
            result = await self.tools.async_execute_command(command, target)
            if result.success:
                print(f"\n✅ Command completed successfully")
                print(f"📄 Output:\n{result.output}")
            else:
                print(f"\n❌ Command failed: {result.error}")
            
            self.command_history.append((command, result.output)) # Store raw output
            
            # Always add the output (or error) to chat history as a user message BEFORE LLM follow-up
            self.chat_history.append({
                "role": "user",
                "content": f"Command output:\n{result.output}"
            })
            
            # Now get model's follow-up analysis, which will see the output
            print(f"\n🤖 Analyzing results...")
            follow_up = await self.model.get_chat_completion(self.chat_history)
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
            print("\n🤖 Agent Commands Available:")
            print("  - agents - Show available agents")
            print("  - agent status - Show agent status")
            print("  - agent results - Show agent results")
            print("  - agent <type> <task> - Execute agent task")
            print("  - coordinator <task> - Use coordinator agent")
            print("  - recon <task> - Use reconnaissance agent")
            print("  - vuln <task> - Use vulnerability assessment agent")
            print("  - web <task> - Use web testing agent")
            print("  - exploit <task> - Use exploitation agent")
        else:
            print("Commands will be automatically executed.")
        
        

if __name__ == "__main__":
    print("This module should be imported and used from main.py") 
