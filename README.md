# AgentRed - AI-Powered Penetration Testing Assistant

AgentRed is an intelligent penetration testing assistant that uses AI to help automate and guide security testing processes. It combines the power of large language models with real security tools to provide an interactive penetration testing experience.

## Features

- 🤖 AI-powered command suggestions and analysis
- 🛠️ Integration with popular security tools:
  - Network scanning (nmap, masscan)
  - Web testing (nikto, gobuster, sqlmap, wpscan)
  - Vulnerability assessment (nuclei)
  - Password testing (hydra)
  - And many more...
- 🔍 Automatic vulnerability detection and reporting
- ⚡ Real-time command execution with safety checks
- 📊 Memory-aware operation with resource management
- 🔒 Safe command execution with user approval

## Prerequisites

- Python 3.8+
- Virtual environment (recommended)
- Required security tools (see Installation)
- GGUF model file (see Installation)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/7h3r3v3n4n7/AgentRed.git
cd AgentRed
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Download the GGUF model:
```bash
mkdir -p models
cd models
wget https://huggingface.co/7h3-R3v3n4n7/pentest-agent-q4_k_m-gguf/resolve/main/unsloth.Q4_K_M.gguf -O pentest-agent.gguf
```

5. Install required security tools:
```bash
# Example for Debian/Ubuntu
sudo apt update
sudo apt install -y nmap masscan nikto gobuster sqlmap wpscan hydra nuclei
```

## Configuration

Environment variables can be set to configure the application:

```bash
export DEBUG=1                    # Enable debug output
export COMMAND_TIMEOUT=300        # Command timeout in seconds
export MEMORY_THRESHOLD=0.8       # Memory usage threshold (0.0-1.0)
```

## Usage

1. Start the application:
```bash
python main.py
```

2. Enter the target (hostname, IP address, or URL) when prompted

3. The assistant will:
   - Perform an initial port scan
   - Analyze the results
   - Suggest next steps
   - Execute commands with your approval

4. Interact with the assistant:
   - Type your questions or requests
   - Review and approve suggested commands
   - View vulnerability reports
   - Type 'exit' or 'quit' to end the session
   - Type 'clear' to clear the screen

## Tool Configurations

The assistant uses optimized configurations for various tools:

- **nmap**: `-sV -sC -p- --max-retries 2 --min-rate 1000`
- **nikto**: `-h <url> -maxtime 5m -Tuning 123457890 -Format txt -n`
- **gobuster**: `dir -u <url> -w <wordlist>`
- **sqlmap**: `-u <url> --batch --random-agent`
- **wpscan**: `--url <url> --enumerate p,t,u`
- **masscan**: `-p- --rate=1000`
- **hydra**: `-L /usr/share/wordlists/user.txt -P <wordlist>`
- **nuclei**: Uses provided arguments

## Safety Features

- Command execution requires user approval
- Memory usage monitoring and management
- Command timeout protection
- Safe tool configurations
- Input validation and sanitization

## Project Structure

```
AgentRed/
├── lib/
│   ├── App.py          # Main application logic
│   ├── Chat.py         # Chat interface handling
│   ├── Model.py        # AI model integration
│   └── Tools.py        # Security tools management
├── models/
│   └── pentest-agent.gguf  # AI model file
├── main.py             # Application entry point
├── requirements.txt    # Python dependencies
└── README.md          # This file
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for authorized security testing and educational purposes only.

## Author

Created by 7h3 R3v3n4n7 (CyberDeathSec) 