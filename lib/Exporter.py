import json
import requests

def generate_alpaca_dataset(agent_manager, rag):
    alpaca_data = []
    # Agent learning memory
    for agent_type, agent in agent_manager.agents.items():
        for target_type, memory in agent.learning_memory.items():
            for technique in memory.successful_techniques:
                instruction = f"Perform a {agent_type.value.replace('_', ' ')} task on a {target_type} target and summarize the findings."
                input_str = f"Target type: {target_type}\nTool: {technique.get('tool', 'unknown')}\nParameters: {technique.get('parameters', {})}"
                output_str = f"Finding: {technique.get('finding_type', 'unknown')} (Severity: {technique.get('severity', 'low')})"
                alpaca_data.append({
                    "instruction": instruction,
                    "input": input_str,
                    "output": output_str
                })
    # RAG vulnerability findings
    if hasattr(rag, 'vulnerability_findings'):
        for finding in getattr(rag, 'vulnerability_findings', []):
            instruction = f"Analyze scan results for {finding.target} and report vulnerabilities."
            input_str = f"Tool: {finding.tool}\nTimestamp: {finding.timestamp}\nEvidence: {finding.evidence}"
            output_str = f"{finding.vulnerability_type.replace('_', ' ').title()} (Severity: {finding.severity}): {finding.description}. Recommendation: {finding.remediation}"
            alpaca_data.append({
                "instruction": instruction,
                "input": input_str,
                "output": output_str
            })
    return alpaca_data

def export_alpaca_data(agent_manager, rag, server_url):
    data = generate_alpaca_dataset(agent_manager, rag)
    try:
        response = requests.post(server_url, json=data, timeout=10)
        print(f"✅ Exported Alpaca dataset to {server_url} (status: {response.status_code})")
    except Exception as e:
        print(f"❌ Failed to export Alpaca dataset: {e}")