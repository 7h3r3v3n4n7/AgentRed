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
- ⚡ Automatic command execution with real-time analysis
- 📊 Memory-aware operation with resource management
- 🔒 JSON-based response format with grammar validation
- 🌐 Support for full URLs with ports and paths

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

6. Install wordlists (optional - fallback wordlists will be created automatically):
```bash
# Install SecLists (recommended)
sudo apt install -y seclists

# Or download manually
sudo mkdir -p /usr/share/wordlists
sudo wget https://github.com/danielmiessler/SecLists/archive/refs/heads/master.zip
sudo unzip master.zip -d /usr/share/seclists/
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
   - Supports full URLs: `http://example.com:8080/path/`
   - Supports IP addresses: `192.168.1.1`
   - Supports hostnames: `example.com`

3. The assistant will:
   - Perform an initial port scan using nmap
   - Analyze the results using AI
   - Suggest and automatically execute next steps
   - Provide real-time analysis of command outputs

4. Interact with the assistant:
   - Type your questions or requests
   - Commands are automatically executed and analyzed
   - View vulnerability reports when detected
   - Type 'exit' or 'quit' to end the session
   - Type 'clear' to clear the screen

## AI Response Format

The AI assistant responds in a structured JSON format:

```json
{
    "response": "Analysis of scan results and suggested next steps",
    "command": "specific command to execute"
}
```

For vulnerability detection:
```json
{
    "response": "Vulnerability description",
    "command": "Command to verify or exploit",
    "vulnerability": {
        "type": "Vulnerability type",
        "severity": "low/medium/high/critical",
        "description": "Detailed description",
        "exploitation": {
            "method": "How to exploit",
            "code": "Example code",
            "requirements": ["Required tools"]
        },
        "references": ["CVE numbers or guides"]
    }
}
```

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

- Automatic command execution with safety checks
- Memory usage monitoring and management
- Command timeout protection
- Safe tool configurations
- Input validation and sanitization
- JSON grammar validation for AI responses

## Project Structure

```
AgentRed/
├── lib/
│   ├── App.py          # Main application logic
│   ├── Chat.py         # Chat interface handling
│   ├── Model.py        # AI model integration
│   ├── Tools.py        # Security tools management
│   └── grammars/
│       └── json.gbnf   # JSON grammar for AI responses
├── models/
│   └── pentest-agent.gguf  # AI model file
├── wordlists/          # Fallback wordlists (auto-created)
│   ├── web_common.txt      # Web content wordlist
│   ├── passwords_common.txt # Password wordlist
│   └── usernames_common.txt # Username wordlist
├── main.py             # Application entry point
├── requirements.txt    # Python dependencies
└── README.md          # This file
```

## Technical Details

- **AI Model**: Uses llama.cpp with GGUF format for local inference
- **Response Format**: Enforced JSON structure with grammar validation
- **Memory Management**: Dynamic token limits based on available system memory
- **Command Execution**: Automatic execution with real-time output analysis
- **URL Support**: Full URL parsing with protocol, host, port, and path support

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for authorized security testing and educational purposes only.

## Author

Created by 7h3 R3v3n4n7 (CyberDeathSec) 

## Wordlist Management

AgentRed automatically manages wordlists for various security tools:

### Supported Wordlist Types:
- **Web Content**: Directory/file enumeration (gobuster, ffuf, wfuzz, dirb, feroxbuster)
- **Passwords**: Password cracking (hydra, john, hashcat)
- **Usernames**: Username enumeration (hydra, wpscan)

### Wordlist Sources:
- **Primary**: System-installed wordlists (`/usr/share/wordlists/`, `/usr/share/seclists/`)
- **Fallback**: Automatically created basic wordlists in `wordlists/` directory

### Automatic Fallback Creation:
If no wordlists are found, AgentRed will automatically create basic fallback wordlists:
- `wordlists/web_common.txt` - Common web paths and files
- `wordlists/passwords_common.txt` - Common passwords
- `wordlists/usernames_common.txt` - Common usernames

### Priority Order:
The system uses a priority-based selection:
1. **Web**: SecLists directory-list → SecLists common → dirb common → fallback
2. **Passwords**: rockyou → SecLists passwords → fallback
3. **Usernames**: SecLists usernames → SecLists names → fallback 