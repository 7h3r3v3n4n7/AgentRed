# AgentRed - AI-Powered Penetration Testing Assistant

AgentRed is an intelligent penetration testing assistant that uses AI to automate and guide security testing. It combines large language models with real security tools for an interactive, multi-agent experience.

---

## 🚀 Features

- 🤖 AI-powered command suggestions and analysis
- 🎯 Multi-Agent System (Recon, Vuln, Web, Exploit, Coordinator)
- 🛠️ Integration with nmap, sqlmap, nuclei, hydra, etc.
- 🔍 Automatic vulnerability detection and reporting
- ⚡ Real-time command execution and analysis
- 📊 Memory-aware operation and persistent learning
- 🔒 JSON-based response format with grammar validation
- 🌐 Supports full URLs, IPs, and hostnames as targets

---

## 🤖 Enhanced AI Agent System

AgentRed includes a sophisticated multi-agent system with **intelligent learning capabilities** for automated penetration testing:

| Agent                | Specialization                                      | AI Enhancements                                      |
|----------------------|-----------------------------------------------------|------------------------------------------------------|
| **Reconnaissance**   | Port scanning, DNS, OSINT, topology mapping         | Intelligent port selection, adaptive scanning        |
| **Vulnerability**    | Vuln scanning, SSL/TLS, CVE analysis, risk assess.  | Smart tool selection, risk-based prioritization      |
| **Web Testing**      | Web app, SQLi, XSS, CMS, API discovery              | Adaptive payloads, context-aware testing             |
| **Exploitation**     | Password cracking, exploitation, PoC                | Learned exploitation patterns, risk-aware execution  |
| **Coordinator**      | Orchestrates all agents, manages workflow           | Strategic learning, adaptive coordination            |

### AI Learning Capabilities

- 🧠 **Persistent Learning Memory**: Remembers target types, techniques, tool effectiveness, and parameters.
- 🎯 **Adaptive Strategies**: Context-aware prompts, intelligent tool/parameter selection, risk-aware decisions.
- 📊 **Performance Analytics**: Tracks success rates, confidence scoring, and strategy optimization.

---

## 🛠️ Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/7h3R3v3n4n7/AgentRed.git
   cd AgentRed
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Download the GGUF model:**
   ```bash
   mkdir -p models
   cd models
   wget https://huggingface.co/7h3-R3v3n4n7/pentest-agent-q4_k_m-gguf/resolve/main/unsloth.Q4_K_M.gguf -O pentest-agent.gguf
   ```

5. **Install required security tools:**
   ```bash
   sudo apt update
   sudo apt install -y nmap masscan nikto gobuster sqlmap wpscan hydra nuclei
   ```

6. **(Optional) Install SecLists for wordlists:**
   ```bash
   sudo apt install -y seclists
   ```

---

## ⚙️ Configuration

Set environment variables as needed:
```bash
export DEBUG=1                    # Enable debug output
export COMMAND_TIMEOUT=300        # Command timeout in seconds
export MEMORY_THRESHOLD=0.8       # Memory usage threshold (0.0-1.0)
```

---

## 🚀 Usage

1. **Start the application:**
   ```bash
   python main.py
   ```

2. **Select execution mode:**
   - `1` for agent-based (automated) testing
   - `2` for interactive chat mode

3. **Enter the target** (URL, IP, or hostname).

### Modes

- **Agent-based:** Fully automated, coordinated multi-agent testing.
- **Chat mode:** Interactive, with agent integration and manual command approval.

---

## 🔍 RAG Features (Retrieval-Augmented Generation)

- Search previous scan results: `search open ports`
- Get scan summary: `summary`
- View available targets: `targets`
- Check tool results: `tool nmap results`
- Refresh the index: `refresh index`

---

## 📁 Project Structure

```
AgentRed/
├── lib/           # Core logic, agents, tools, model, RAG
├── models/        # GGUF model file (not included)
├── wordlists/     # Fallback wordlists (auto-created)
├── main.py        # Entry point
├── requirements.txt
└── README.md
```

---

## 🔧 Technical Details

- **AI Model:** Uses llama.cpp with GGUF format for local inference
- **Response Format:** Enforced JSON structure with grammar validation
- **Memory Management:** Dynamic token limits based on available system memory
- **Command Execution:** Automatic execution with real-time output analysis
- **Agent System:** Asynchronous multi-agent coordination with specialized roles
- **RAG System:** Semantic search and retrieval of previous scan results

---

## 🛡️ Safety & Disclaimer

- Automatic command execution with safety checks
- Memory usage monitoring and management
- Input validation and sanitization
- **Agent safety controls:** Exploitation agent includes warnings and scope checks

> **This tool is for authorized security testing and educational purposes only.**

---

## 🤝 Contributing

Contributions are welcome! Please submit a Pull Request.

## 📄 License

MIT License - see the LICENSE file for details.

## 👨‍💻 Author

Created by 7h3 R3v3n4n7 (CyberDeathSec) 