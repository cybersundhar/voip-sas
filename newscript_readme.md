# VoIP/SIP Security Assessment Tool

A comprehensive security assessment tool for VoIP/SIP infrastructure based on OWASP VoIP Security Guidelines. This tool performs automated security testing of SIP servers, identifying vulnerabilities, misconfigurations, and compliance gaps.

## Features

### Core Capabilities
- **SIP Protocol Analysis**: Parse and analyze SIP messages (INVITE, REGISTER, OPTIONS, etc.)
- **Server Fingerprinting**: Identify VoIP server types, versions, and configurations
- **Extension Enumeration**: Discover valid SIP extensions/accounts
- **Authentication Testing**: Detect weak credentials and authentication bypasses
- **Encryption Assessment**: Check for TLS/SRTP implementation
- **Vulnerability Detection**: Identify known CVEs in common VoIP platforms
- **OWASP Compliance**: Map findings to OWASP VoIP Security Top 10

### Supported Protocols & Ports
- SIP (UDP/TCP): 5060
- SIP over TLS: 5061
- RTP/RTCP: 10000-20000
- IAX2: 4569
- MGCP: 2427
- H.323: 1720
- SCCP: 2000

### Security Checks
1. **Authentication Security** - Weak/missing authentication, MD5 digest usage
2. **Transport Encryption** - Missing TLS/SRTP implementation
3. **Credential Testing** - Default and weak password detection
4. **Information Disclosure** - Version leakage in server banners
5. **Known Vulnerabilities** - CVE matching for Asterisk, FreeSWITCH, Cisco
6. **DoS Protection** - Rate limiting and request throttling
7. **Extension Enumeration** - User account discovery protection
8. **Method Security** - Dangerous SIP methods (MESSAGE, REFER, SUBSCRIBE)
9. **Network Exposure** - Public IP exposure assessment

## Installation

### Requirements
- Python 3.7 or higher
- Required libraries:
  - `requests` - HTTP library for API calls
  - `urllib3` - HTTP client library

### Setup

#### Linux (Ubuntu/Debian)
```bash
# Update package list
sudo apt update

# Install Python 3 and pip (if not already installed)
sudo apt install python3 python3-pip

# Clone or download the script
git clone <repository-url>
cd voip-security-tool

# Install required libraries
pip3 install requests urllib3

# Make executable
chmod +x newscript.py

# Run directly
./newscript.py -t <target> -o report.txt
```

#### Linux (RHEL/CentOS/Fedora)
```bash
# Install Python 3 and pip (if not already installed)
sudo dnf install python3 python3-pip

# Install required libraries
pip3 install requests urllib3

# Make executable
chmod +x newscript.py
```

#### Windows
```cmd
# Install Python from https://www.python.org/downloads/
# Ensure "Add Python to PATH" is checked during installation

# Open Command Prompt or PowerShell
# Navigate to script directory
cd voip-security-tool

# Install required libraries
pip install requests urllib3

# Run the script
python newscript.py -t <target> -o report.txt
```

#### Using Virtual Environment (Recommended)

**Linux:**
```bash
# Create virtual environment
python3 -m venv voip-env

# Activate virtual environment
source voip-env/bin/activate

# Install dependencies
pip install requests urllib3

# Run script
python newscript.py -t <target> -o report.txt

# Deactivate when done
deactivate
```

**Windows:**
```cmd
# Create virtual environment
python -m venv voip-env

# Activate virtual environment
voip-env\Scripts\activate

# Install dependencies
pip install requests urllib3

# Run script
python newscript.py -t <target> -o report.txt

# Deactivate when done
deactivate
```

#### Using requirements.txt
Create a `requirements.txt` file:
```
requests>=2.25.0
urllib3>=1.26.0
```

Then install:
```bash
# Linux
pip3 install -r requirements.txt

# Windows
pip install -r requirements.txt
```

## Usage

### Basic Passive Scan
Performs non-intrusive fingerprinting and security checks:
```bash
python newscript.py -t 192.168.1.100 -o report.txt
```

### Aggressive Scan
Includes extension enumeration and credential testing:
```bash
python newscript.py -t 192.168.1.100 -o report.txt --aggressive
```

### Custom Timeout
Adjust socket timeout for slower networks:
```bash
python newscript.py -t voip.example.com -o report.txt --timeout 10
```

### Using Exceptions File
Skip approved security deviations:
```bash
python newscript.py -t 192.168.1.100 -o report.txt --exceptions exceptions.json
```

## Command-Line Options

| Option | Description |
|--------|-------------|
| `-t, --target` | Target SIP server (IP address or hostname) **[Required]** |
| `-o, --output` | Output report file (default: voip_assessment_report.txt) |
| `--aggressive` | Enable aggressive testing (enumeration, credential testing) |
| `--timeout` | Socket timeout in seconds (default: 5) |
| `--exceptions` | Path to JSON exceptions file |
| `-v, --verbose` | Enable verbose output |

## Output Reports

The tool generates two report formats:

### Text Report (.txt)
Comprehensive human-readable report including:
- Executive summary with risk scoring
- Server fingerprinting results
- Detailed findings with evidence
- Remediation recommendations
- Prioritized action plan

### JSON Report (.json)
Machine-readable format containing:
- Scan metadata and configuration
- Server fingerprint data
- Extension enumeration results
- Risk metrics and statistics
- Structured findings array

## Exceptions File Format

Create a JSON file to skip approved security deviations:

```json
{
  "approved_deviations": [
    "V1",
    "V3"
  ],
  "notes": {
    "V1": "MD5 digest approved for legacy system compatibility",
    "V3": "SRTP deployment scheduled for Q2 2025"
  }
}
```

## Security Findings

### Severity Levels
- **CRITICAL**: Immediate action required (within 24 hours)
- **HIGH**: Remediate within 7 days
- **MEDIUM**: Address within 30 days
- **LOW**: Address during next maintenance window

### OWASP VoIP Controls Mapping
- **V1**: SIP Authentication Bypass
- **V2**: SIP Request Spoofing / Enumeration
- **V3**: Eavesdropping and Interception
- **V4**: Denial of Service
- **V5**: SIP Malformed Messages
- **V6**: VLAN Hopping / Network Segmentation
- **V7**: Credential Disclosure
- **V8**: DTMF Injection
- **V9**: Firmware/Software Vulnerabilities
- **V10**: Physical Security

## Examples

### Example 1: Quick Security Check
```bash
python newscript.py -t 10.0.0.50 -o quick_scan.txt
```

### Example 2: Full Penetration Test
```bash
python newscript.py -t pbx.company.local -o pentest.txt --aggressive --timeout 10
```

### Example 3: Compliance Audit with Exceptions
```bash
python newscript.py -t 192.168.10.5 -o audit.txt --exceptions approved.json
```

## Tested Platforms

The tool has been tested against:
- **Asterisk PBX** (versions 1.8, 11, 13, 16, 18)
- **FreeSWITCH** (versions 1.6, 1.8, 1.10)
- **Cisco Unified Communications Manager**
- **3CX Phone System**
- **Kamailio**
- **OpenSIPS**

## Exit Codes

- `0`: Success, no critical/high findings
- `1`: High severity findings detected
- `2`: Critical severity findings detected
- `3`: Assessment failed (target unreachable)

## Legal Notice

⚠️ **IMPORTANT**: This tool is designed for authorized security testing only.

- Obtain **written authorization** before testing any VoIP system
- Unauthorized access to VoIP systems may violate Indian laws including:
  - **Information Technology Act, 2000 (IT Act)**
    - Section 43: Penalty for damage to computer systems (up to ₹1 crore)
    - Section 66: Computer related offences (imprisonment up to 3 years and/or fine up to ₹5 lakh)
    - Section 66C: Identity theft and fraud
    - Section 66F: Cyber terrorism (life imprisonment)
  - **Indian Penal Code (IPC)**
    - Section 379: Theft of data
    - Section 406: Criminal breach of trust
    - Section 420: Cheating and fraud
  - **Telegraph Act, 1885**: Unauthorized interception of communications
- The authors assume no liability for misuse of this tool
- Users are responsible for compliance with all applicable Indian laws and regulations
- Violation may result in criminal prosecution, imprisonment, and substantial fines

## Limitations

- Does not perform actual call interception (only detects vulnerabilities)
- Cannot crack strong passwords (tests only common/default credentials)
- Aggressive mode may trigger IDS/IPS alerts
- Some checks require multiple network requests
- Rate limiting may affect scan completeness

## Best Practices

1. **Always get authorization** before scanning
2. Use **passive mode** for initial reconnaissance
3. Schedule **aggressive scans** during maintenance windows
4. Review and address **CRITICAL findings immediately**
5. Document all findings and remediation efforts
6. Re-scan after implementing fixes
7. Maintain an exceptions file for approved deviations

## Troubleshooting

### No SIP Services Detected
- Verify target IP/hostname is correct
- Check firewall rules allow UDP/TCP 5060
- Increase timeout with `--timeout 10`
- Try scanning from different network location

### Socket Timeout Errors
- Increase timeout value
- Check network connectivity
- Verify target is actually running SIP service

### Permission Errors (Linux)
- Binding to ports < 1024 may require sudo
- Running the script: `python3 newscript.py`

## Contributing

Contributions welcome! Please submit pull requests for:
- Additional vulnerability checks
- New VoIP platform support
- Enhanced reporting features
- Bug fixes and improvements

## License

This tool is provided for educational and authorized testing purposes only.

---

**Version**: 1.0  
**Last Updated**: 2025  
**Author**: VoIP Security Research Team