#!/usr/bin/env python3
"""
VoIP/SIP Security Assessment Tool
Context-Aware Analysis with OWASP VoIP Security Guidelines
Supports SIP, RTP, RTCP, and common VoIP protocols
"""

import re
import sys
import json
import socket
import hashlib
import argparse
import requests
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional
from collections import defaultdict
import urllib3
import random
import ipaddress
import string

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class VoIPDefaults:
    """Default VoIP/SIP values and vulnerable configurations"""
    
    DEFAULT_PORTS = {
        'sip_udp': 5060,
        'sip_tcp': 5060,
        'sip_tls': 5061,
        'rtp_start': 10000,
        'rtp_end': 20000,
        'rtcp': 5005,
        'iax2': 4569,
        'mgcp': 2427,
        'h323': 1720,
        'sccp': 2000
    }
    
    WEAK_CREDENTIALS = [
        ('admin', 'admin'), ('admin', 'password'), ('admin', '1234'),
        ('root', 'root'), ('root', 'password'), ('root', 'toor'),
        ('user', 'user'), ('user', 'password'), ('user', '1234'),
        ('test', 'test'), ('guest', 'guest'), ('asterisk', 'asterisk'),
        ('voip', 'voip'), ('sip', 'sip'), ('phone', 'phone'),
        ('1000', '1000'), ('2000', '2000'), ('100', '100'),
        ('101', '101'), ('102', '102'), ('200', '200')
    ]
    
    COMMON_EXTENSIONS = [
        '100', '101', '102', '103', '104', '105',
        '200', '201', '202', '203', '204', '205',
        '1000', '1001', '1002', '1003', '1004', '1005',
        '2000', '2001', '2002', '2003', '2004', '2005',
        '3000', '3001', '3002', '3003', '3004', '3005',
        'admin', 'sales', 'support', 'info', 'reception'
    ]
    
    VULNERABLE_USER_AGENTS = [
        'Asterisk PBX',
        'FreeSWITCH',
        'Cisco-SIPGateway',
        'Linksys',
        'Polycom',
        'Grandstream',
        'Yealink',
        'FPBX-',
        '3CX Phone System'
    ]
    
    KNOWN_VULNS = {
        'Asterisk PBX': {
            'versions': ['1.8.0', '11.0', '13.0'],
            'cves': ['CVE-2020-35652', 'CVE-2021-37706', 'CVE-2022-26498'],
            'description': 'Multiple vulnerabilities in older Asterisk versions'
        },
        'FreeSWITCH': {
            'versions': ['1.10.0', '1.10.5'],
            'cves': ['CVE-2021-41105', 'CVE-2021-37624'],
            'description': 'Authentication bypass and RCE vulnerabilities'
        },
        'Cisco-SIPGateway': {
            'versions': ['IOS 12.x', 'IOS 15.x'],
            'cves': ['CVE-2020-3452', 'CVE-2021-1480'],
            'description': 'Path traversal and authentication bypass'
        }
    }


class SIPParser:
    """SIP message parser with context awareness"""
    
    def __init__(self):
        self.methods = ['INVITE', 'ACK', 'BYE', 'CANCEL', 'OPTIONS', 
                       'REGISTER', 'INFO', 'SUBSCRIBE', 'NOTIFY', 'MESSAGE']
    
    def parse_message(self, data: str) -> Dict[str, Any]:
        """Parse SIP message"""
        if not data:
            return {}
        
        lines = data.split('\r\n')
        if not lines:
            return {}
        
        # Parse request/response line
        first_line = lines[0]
        message = {'raw': data, 'headers': {}, 'body': ''}
        
        if any(first_line.startswith(m) for m in self.methods):
            # Request
            parts = first_line.split()
            message['type'] = 'request'
            message['method'] = parts[0] if parts else ''
            message['uri'] = parts[1] if len(parts) > 1 else ''
            message['version'] = parts[2] if len(parts) > 2 else ''
        elif first_line.startswith('SIP/'):
            # Response
            parts = first_line.split(' ', 2)
            message['type'] = 'response'
            message['version'] = parts[0] if parts else ''
            message['status_code'] = parts[1] if len(parts) > 1 else ''
            message['status_text'] = parts[2] if len(parts) > 2 else ''
        
        # Parse headers
        body_start = -1
        for i, line in enumerate(lines[1:], 1):
            if line == '':
                body_start = i + 1
                break
            
            if ':' in line:
                key, value = line.split(':', 1)
                message['headers'][key.strip()] = value.strip()
        
        # Parse body
        if body_start > 0:
            message['body'] = '\r\n'.join(lines[body_start:])
        
        return message
    
    def extract_authentication(self, headers: Dict) -> Dict[str, str]:
        """Extract authentication details"""
        auth = {}
        
        for header in ['WWW-Authenticate', 'Proxy-Authenticate', 'Authorization']:
            if header in headers:
                auth_str = headers[header]
                
                # Parse Digest authentication
                if 'Digest' in auth_str:
                    auth['scheme'] = 'Digest'
                    
                    # Extract realm
                    realm_match = re.search(r'realm="([^"]+)"', auth_str)
                    if realm_match:
                        auth['realm'] = realm_match.group(1)
                    
                    # Extract nonce
                    nonce_match = re.search(r'nonce="([^"]+)"', auth_str)
                    if nonce_match:
                        auth['nonce'] = nonce_match.group(1)
                    
                    # Extract algorithm
                    algo_match = re.search(r'algorithm=(\w+)', auth_str)
                    if algo_match:
                        auth['algorithm'] = algo_match.group(1)
                    else:
                        auth['algorithm'] = 'MD5'  # Default
                
                elif 'Basic' in auth_str:
                    auth['scheme'] = 'Basic'
        
        return auth
    
    def extract_sdp(self, body: str) -> Dict[str, Any]:
        """Extract SDP (Session Description Protocol) information"""
        sdp = {'media': [], 'codecs': [], 'addresses': []}
        
        if not body:
            return sdp
        
        lines = body.split('\r\n')
        current_media = None
        
        for line in lines:
            if not line or '=' not in line:
                continue
            
            key, value = line.split('=', 1)
            
            # Connection information
            if key == 'c':
                parts = value.split()
                if len(parts) >= 3:
                    sdp['addresses'].append(parts[2])
            
            # Media description
            elif key == 'm':
                parts = value.split()
                if len(parts) >= 2:
                    current_media = {
                        'type': parts[0],
                        'port': parts[1],
                        'protocol': parts[2] if len(parts) > 2 else '',
                        'formats': parts[3:] if len(parts) > 3 else []
                    }
                    sdp['media'].append(current_media)
            
            # RTP Map (codec info)
            elif key == 'a' and value.startswith('rtpmap:'):
                codec_info = value[7:]  # Remove 'rtpmap:'
                sdp['codecs'].append(codec_info)
        
        return sdp


class VoIPScanner:
    """VoIP network scanner and enumeration"""
    
    def __init__(self, target: str, timeout: int = 5):
        self.target = target
        self.timeout = timeout
        self.findings = []
    
    def generate_sip_options(self, from_user: str = 'scanner') -> str:
        """Generate SIP OPTIONS request"""
        call_id = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        tag = ''.join(random.choices(string.digits, k=10))
        branch = 'z9hG4bK' + ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        
        request = f"""OPTIONS sip:{self.target} SIP/2.0\r
Via: SIP/2.0/UDP scanner:5060;branch={branch}\r
Max-Forwards: 70\r
From: <sip:{from_user}@scanner>;tag={tag}\r
To: <sip:{self.target}>\r
Call-ID: {call_id}@scanner\r
CSeq: 1 OPTIONS\r
Contact: <sip:{from_user}@scanner:5060>\r
Accept: application/sdp\r
Content-Length: 0\r
\r
"""
        return request
    
    def generate_sip_register(self, username: str, password: str = None, 
                             auth_response: Dict = None) -> str:
        """Generate SIP REGISTER request"""
        call_id = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        tag = ''.join(random.choices(string.digits, k=10))
        branch = 'z9hG4bK' + ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        
        auth_header = ""
        if auth_response and password:
            # Generate digest response
            realm = auth_response.get('realm', '')
            nonce = auth_response.get('nonce', '')
            algorithm = auth_response.get('algorithm', 'MD5')
            
            # Simplified digest (for demonstration)
            uri = f"sip:{self.target}"
            
            if algorithm == 'MD5':
                ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
                ha2 = hashlib.md5(f"REGISTER:{uri}".encode()).hexdigest()
                response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
            else:
                response = "00000000000000000000000000000000"
            
            auth_header = f'Authorization: Digest username="{username}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{response}", algorithm={algorithm}\r\n'
        
        request = f"""REGISTER sip:{self.target} SIP/2.0\r
Via: SIP/2.0/UDP scanner:5060;branch={branch}\r
Max-Forwards: 70\r
From: <sip:{username}@{self.target}>;tag={tag}\r
To: <sip:{username}@{self.target}>\r
Call-ID: {call_id}@scanner\r
CSeq: 1 REGISTER\r
Contact: <sip:{username}@scanner:5060>\r
{auth_header}Expires: 3600\r
Content-Length: 0\r
\r
"""
        return request
    
    def send_sip_message(self, message: str, port: int = 5060, 
                        protocol: str = 'udp') -> Optional[str]:
        """Send SIP message and receive response"""
        sock = None
        try:
            if protocol.lower() == 'udp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            sock.settimeout(self.timeout)
            
            if protocol.lower() == 'tcp':
                sock.connect((self.target, port))
            
            sock.sendto(message.encode(), (self.target, port))
            
            data, addr = sock.recvfrom(4096)
            
            return data.decode('utf-8', errors='ignore')
        
        except socket.timeout:
            return None
        except Exception as e:
            print(f"[!] Error sending SIP message: {e}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
    
    def fingerprint_server(self) -> Dict[str, Any]:
        """Fingerprint SIP server"""
        print(f"[*] Fingerprinting SIP server: {self.target}")
        
        fingerprint = {
            'target': self.target,
            'ports': {},
            'user_agent': None,
            'server': None,
            'methods': [],
            'vulnerabilities': []
        }
        
        # Check common ports
        for proto_name, port in VoIPDefaults.DEFAULT_PORTS.items():
            if 'sip' in proto_name:
                print(f"[*] Checking {proto_name} on port {port}")
                
                protocol = 'tcp' if 'tcp' in proto_name else 'udp'
                options = self.generate_sip_options()
                response = self.send_sip_message(options, port, protocol)
                
                if response:
                    fingerprint['ports'][proto_name] = {
                        'port': port,
                        'protocol': protocol,
                        'status': 'open'
                    }
                    
                    parser = SIPParser()
                    parsed = parser.parse_message(response)
                    
                    # Extract server information
                    if 'User-Agent' in parsed.get('headers', {}):
                        fingerprint['user_agent'] = parsed['headers']['User-Agent']
                    
                    if 'Server' in parsed.get('headers', {}):
                        fingerprint['server'] = parsed['headers']['Server']
                    
                    # Extract supported methods
                    if 'Allow' in parsed.get('headers', {}):
                        fingerprint['methods'] = parsed['headers']['Allow'].split(',')
                        fingerprint['methods'] = [m.strip() for m in fingerprint['methods']]
                    
                    print(f"[+] {proto_name} is open")
                    if fingerprint['user_agent']:
                        print(f"[+] User-Agent: {fingerprint['user_agent']}")
                    if fingerprint['server']:
                        print(f"[+] Server: {fingerprint['server']}")
        
        # Check for known vulnerabilities - FIXED
        server_info = fingerprint.get('user_agent') or fingerprint.get('server') or ''
        
        if server_info:  # Only check if we have server info
            for vuln_name, vuln_data in VoIPDefaults.KNOWN_VULNS.items():
                if vuln_name.lower() in server_info.lower():
                    fingerprint['vulnerabilities'].append({
                        'name': vuln_name,
                        'cves': vuln_data['cves'],
                        'description': vuln_data['description']
                    })
                    print(f"[!] Potentially vulnerable: {vuln_name}")
        
        return fingerprint
    
    def enumerate_extensions(self, ext_list: List[str] = None) -> List[str]:
        """Enumerate valid extensions"""
        print(f"[*] Enumerating extensions on {self.target}")
        
        if not ext_list:
            ext_list = VoIPDefaults.COMMON_EXTENSIONS[:20]  # Limit for demo
        
        valid_extensions = []
        
        for ext in ext_list:
            register = self.generate_sip_register(ext)
            response = self.send_sip_message(register)
            
            if response:
                parser = SIPParser()
                parsed = parser.parse_message(response)
                
                status = parsed.get('status_code', '')
                
                # 401/407 = Authentication required (valid extension)
                # 404 = Not found (invalid extension)
                if status in ['401', '407']:
                    valid_extensions.append(ext)
                    print(f"[+] Valid extension found: {ext}")
        
        print(f"[+] Found {len(valid_extensions)} valid extensions")
        return valid_extensions
    
    def test_weak_credentials(self, extensions: List[str]) -> List[Dict]:
        """Test for weak credentials"""
        print(f"[*] Testing weak credentials")
        
        compromised = []
        
        for ext in extensions[:5]:  # Limit for demo
            for username, password in VoIPDefaults.WEAK_CREDENTIALS[:10]:
                # First REGISTER to get challenge
                register1 = self.generate_sip_register(ext)
                response1 = self.send_sip_message(register1)
                
                if not response1:
                    continue
                
                parser = SIPParser()
                parsed1 = parser.parse_message(response1)
                
                if parsed1.get('status_code') in ['401', '407']:
                    auth = parser.extract_authentication(parsed1.get('headers', {}))
                    
                    # Second REGISTER with credentials
                    register2 = self.generate_sip_register(ext, password, auth)
                    response2 = self.send_sip_message(register2)
                    
                    if response2:
                        parsed2 = parser.parse_message(response2)
                        
                        if parsed2.get('status_code') == '200':
                            compromised.append({
                                'extension': ext,
                                'username': username,
                                'password': password
                            })
                            print(f"[!] COMPROMISED: {ext} / {username}:{password}")
                            break
        
        return compromised


class OWASPVoIPChecker:
    """OWASP VoIP Security Top 10 checker"""
    
    OWASP_CONTROLS = [
        {
            'id': 'V1',
            'title': 'SIP Authentication Bypass',
            'severity': 'CRITICAL',
            'description': 'SIP services allow unauthenticated access or weak authentication',
            'check_type': 'authentication'
        },
        {
            'id': 'V2',
            'title': 'SIP Request Spoofing',
            'severity': 'HIGH',
            'description': 'System vulnerable to caller ID spoofing and SIP header manipulation',
            'check_type': 'spoofing'
        },
        {
            'id': 'V3',
            'title': 'Eavesdropping and Interception',
            'severity': 'CRITICAL',
            'description': 'Media streams not encrypted (RTP without SRTP)',
            'check_type': 'encryption'
        },
        {
            'id': 'V4',
            'title': 'Denial of Service',
            'severity': 'HIGH',
            'description': 'SIP services vulnerable to DoS attacks',
            'check_type': 'dos'
        },
        {
            'id': 'V5',
            'title': 'SIP Malformed Messages',
            'severity': 'HIGH',
            'description': 'System crashes or behaves unexpectedly with malformed SIP messages',
            'check_type': 'fuzzing'
        },
        {
            'id': 'V6',
            'title': 'VLAN Hopping',
            'severity': 'MEDIUM',
            'description': 'VoIP traffic not properly segmented from data network',
            'check_type': 'network'
        },
        {
            'id': 'V7',
            'title': 'Credential Disclosure',
            'severity': 'CRITICAL',
            'description': 'Credentials stored in cleartext or weak hashing',
            'check_type': 'credentials'
        },
        {
            'id': 'V8',
            'title': 'DTMF Injection',
            'severity': 'MEDIUM',
            'description': 'System vulnerable to DTMF tone injection attacks',
            'check_type': 'dtmf'
        },
        {
            'id': 'V9',
            'title': 'Firmware/Software Vulnerabilities',
            'severity': 'CRITICAL',
            'description': 'Outdated firmware with known vulnerabilities',
            'check_type': 'version'
        },
        {
            'id': 'V10',
            'title': 'Physical Security',
            'severity': 'MEDIUM',
            'description': 'Physical access to VoIP devices not restricted',
            'check_type': 'physical'
        }
    ]


class VoIPAuditor:
    """Main VoIP security auditor"""
    
    def __init__(self, target: str, output_file: str = None, 
                 aggressive: bool = False, exceptions_file: str = None):
        self.target = target
        self.output_file = output_file
        self.aggressive = aggressive
        self.findings = []
        self.stats = defaultdict(int)
        self.scanner = VoIPScanner(target)
        self.fingerprint = {}
        self.extensions = []
        self.exceptions = self._load_exceptions(exceptions_file) if exceptions_file else {}
    
    def _load_exceptions(self, exceptions_file: str) -> Dict:
        """Load approved exceptions"""
        try:
            with open(exceptions_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Warning: Could not load exceptions file: {e}")
            return {}
    
    def is_exception(self, control_id: str) -> bool:
        """Check if finding is an approved exception"""
        return control_id in self.exceptions.get('approved_deviations', [])
    
    def add_finding(self, severity: str, category: str, title: str,
                   description: str, evidence: str, remediation: str,
                   control_id: str = "", confidence: str = "high"):
        """Add security finding"""
        
        if control_id and self.is_exception(control_id):
            print(f"[~] Skipping {control_id} - Approved exception")
            return
        
        finding = {
            'severity': severity,
            'category': category,
            'title': title,
            'description': description,
            'evidence': evidence,
            'remediation': remediation,
            'control_id': control_id,
            'confidence': confidence,
            'timestamp': datetime.now().isoformat()
        }
        
        self.findings.append(finding)
        self.stats[severity] += 1
    
    def check_authentication(self):
        """Check authentication security"""
        print("\n[*] Checking authentication security...")
        
        # Check if authentication is required
        register = self.scanner.generate_sip_register('testuser')
        response = self.scanner.send_sip_message(register)
        
        if response:
            parser = SIPParser()
            parsed = parser.parse_message(response)
            status = parsed.get('status_code', '')
            
            if status == '200':
                self.add_finding(
                    'CRITICAL',
                    'Authentication',
                    'SIP service allows unauthenticated registration',
                    f'SIP server at {self.target} accepted REGISTER without authentication',
                    f'Status: {status} OK\nNo authentication challenge received',
                    'Enable authentication:\n- Configure digest authentication\n- Enforce strong passwords\n- Implement IP-based access control\n- Use TLS for signaling',
                    'V1',
                    'high'
                )
            
            elif status in ['401', '407']:
                auth = parser.extract_authentication(parsed.get('headers', {}))
                
                if auth.get('scheme') == 'Basic':
                    self.add_finding(
                        'CRITICAL',
                        'Authentication',
                        'SIP service uses Basic authentication',
                        'Basic authentication transmits credentials in cleartext (base64 encoded)',
                        f'Authentication scheme: {auth.get("scheme")}\nRealm: {auth.get("realm")}',
                        'Migrate to Digest authentication:\n- Configure MD5 or SHA-256 digest\n- Use TLS/SRTP for transport security',
                        'V1',
                        'high'
                    )
                
                elif auth.get('scheme') == 'Digest':
                    algo = auth.get('algorithm', 'MD5')
                    
                    if algo == 'MD5':
                        self.add_finding(
                            'HIGH',
                            'Authentication',
                            'SIP digest authentication uses MD5',
                            'MD5 is cryptographically weak and vulnerable to collision attacks',
                            f'Algorithm: {algo}\nRealm: {auth.get("realm")}',
                            'Upgrade to stronger algorithm:\n- Use SHA-256 or SHA-512\n- Implement TLS for additional security',
                            'V1',
                            'medium'
                        )
    
    def check_encryption(self):
        """Check encryption and transport security"""
        print("\n[*] Checking encryption and transport security...")
        
        # Check if TLS is available
        tls_available = 'sip_tls' in self.fingerprint.get('ports', {})
        
        if not tls_available:
            self.add_finding(
                'CRITICAL',
                'Encryption',
                'TLS not available for SIP signaling',
                f'SIP server does not support TLS on port 5061. All signaling in cleartext.',
                'No TLS support detected',
                'Enable TLS:\n- Configure TLS on port 5061\n- Deploy valid certificates\n- Enforce SIPS URIs\n- Disable cleartext fallback',
                'V3',
                'high'
            )
        
        # Check SDP for SRTP
        options = self.scanner.generate_sip_options()
        response = self.scanner.send_sip_message(options)
        
        if response:
            parser = SIPParser()
            parsed = parser.parse_message(response)
            sdp = parser.extract_sdp(parsed.get('body', ''))
            
            has_srtp = False
            for media in sdp.get('media', []):
                if 'SAVP' in media.get('protocol', '') or 'SAVPF' in media.get('protocol', ''):
                    has_srtp = True
                    break
            
            if not has_srtp and sdp.get('media'):
                self.add_finding(
                    'CRITICAL',
                    'Encryption',
                    'RTP media streams not encrypted',
                    'SDP offers RTP without SRTP. Audio/video can be intercepted.',
                    f'Media protocols: {", ".join([m.get("protocol", "") for m in sdp.get("media", [])])}',
                    'Enable SRTP:\n- Configure SRTP/SAVP profiles\n- Use DTLS for key exchange\n- Implement ZRTP for peer-to-peer encryption',
                    'V3',
                    'high'
                )
    
    def check_weak_credentials(self):
        """Check for weak credentials"""
        print("\n[*] Checking for weak credentials...")
        
        if not self.extensions:
            print("[*] Enumerating extensions first...")
            self.extensions = self.scanner.enumerate_extensions()
        
        if self.aggressive and self.extensions:
            compromised = self.scanner.test_weak_credentials(self.extensions)
            
            if compromised:
                for cred in compromised:
                    self.add_finding(
                        'CRITICAL',
                        'Credentials',
                        f'Weak credentials on extension {cred["extension"]}',
                        f'Extension {cred["extension"]} uses default/weak credentials',
                        f'Username: {cred["username"]}\nPassword: {cred["password"]}',
                        f'Immediately change credentials:\n- Extension: {cred["extension"]}\n- Enforce password policy (12+ chars, complexity)\n- Enable account lockout\n- Monitor for unauthorized access',
                        'V7',
                        'high'
                    )
    
    def check_information_disclosure(self):
        """Check for information disclosure"""
        print("\n[*] Checking for information disclosure...")
        
        server_info = self.fingerprint.get('user_agent') or self.fingerprint.get('server') or ''
        
        if server_info:
            # Check if version info is disclosed
            version_pattern = r'\d+\.\d+(\.\d+)?'
            if re.search(version_pattern, server_info):
                self.add_finding(
                    'MEDIUM',
                    'Information Disclosure',
                    'Server version information disclosed',
                    f'Server banner reveals version: {server_info}',
                    f'User-Agent/Server: {server_info}',
                    'Hide version information:\n- Configure minimal server banner\n- Remove version from User-Agent\n- Use generic identifiers',
                    'V9',
                    'medium'
                )
    
    def check_vulnerabilities(self):
        """Check for known vulnerabilities"""
        print("\n[*] Checking for known vulnerabilities...")
        
        vulns = self.fingerprint.get('vulnerabilities', [])
        
        for vuln in vulns:
            cve_list = ', '.join(vuln['cves'][:3])
            
            self.add_finding(
                'CRITICAL',
                'Vulnerability',
                f'Vulnerable {vuln["name"]} detected',
                f'{vuln["description"]}\nKnown CVEs: {cve_list}',
                f'Server: {vuln["name"]}\nCVEs: {cve_list}',
                f'Update immediately:\n- Check vendor security advisories\n- Apply latest patches\n- Consider migration to supported version\n- Implement compensating controls',
                'V9',
                'high'
            )
    
    def check_dos_protection(self):
        """Check DoS protection"""
        print("\n[*] Checking DoS protection...")
        
        # Check rate limiting
        success_count = 0
        for i in range(10):
            options = self.scanner.generate_sip_options()
            response = self.scanner.send_sip_message(options)
            if response:
                success_count += 1
        
        if success_count == 10:
            self.add_finding(
                'HIGH',
                'DoS Protection',
                'No rate limiting detected',
                'SIP server accepted 10 rapid requests without rate limiting',
                f'Successful requests: {success_count}/10',
                'Implement rate limiting:\n- Configure SIP request rate limits\n- Enable connection throttling\n- Implement IP-based blocking\n- Deploy SIP firewall/SBC',
                'V4',
                'medium'
            )
    
    def check_enumeration_protection(self):
        """Check extension enumeration protection"""
        print("\n[*] Checking enumeration protection...")
        
        # Test if server reveals valid vs invalid extensions
        test_valid = self.scanner.generate_sip_register('100')  # Likely valid
        response_valid = self.scanner.send_sip_message(test_valid)
        
        test_invalid = self.scanner.generate_sip_register('9999999')  # Likely invalid
        response_invalid = self.scanner.send_sip_message(test_invalid)
        
        if response_valid and response_invalid:
            parser = SIPParser()
            parsed_valid = parser.parse_message(response_valid)
            parsed_invalid = parser.parse_message(response_invalid)
            
            status_valid = parsed_valid.get('status_code', '')
            status_invalid = parsed_invalid.get('status_code', '')
            
            # If different responses, enumeration is possible
            if status_valid != status_invalid:
                self.add_finding(
                    'MEDIUM',
                    'Enumeration',
                    'Extension enumeration possible',
                    f'Server returns different responses for valid/invalid extensions',
                    f'Valid extension: {status_valid}\nInvalid extension: {status_invalid}',
                    'Prevent enumeration:\n- Return consistent responses\n- Use 401/407 for all REGISTER attempts\n- Implement CAPTCHA for repeated failures\n- Monitor for scanning activity',
                    'V2',
                    'medium'
                )
    
    def check_allowed_methods(self):
        """Check for dangerous SIP methods"""
        print("\n[*] Checking allowed SIP methods...")
        
        methods = self.fingerprint.get('methods', [])
        
        dangerous_methods = ['MESSAGE', 'SUBSCRIBE', 'NOTIFY', 'REFER']
        enabled_dangerous = [m for m in methods if m in dangerous_methods]
        
        if enabled_dangerous:
            self.add_finding(
                'MEDIUM',
                'Configuration',
                f'Potentially dangerous SIP methods enabled',
                f'Methods {", ".join(enabled_dangerous)} are enabled and may increase attack surface',
                f'Allowed methods: {", ".join(methods)}',
                'Review method usage:\n- Disable unused methods\n- Restrict MESSAGE for spam prevention\n- Control REFER for call transfer security\n- Monitor SUBSCRIBE/NOTIFY abuse',
                'V2',
                'low'
            )
    
    def check_network_exposure(self):
        """Check network exposure"""
        print("\n[*] Checking network exposure...")
        
        # Check if running on public IP
        try:
            ip = ipaddress.ip_address(self.target)
            
            if not ip.is_private:
                # Check if common ports are open
                open_ports = list(self.fingerprint.get('ports', {}).keys())
                
                if 'sip_udp' in open_ports or 'sip_tcp' in open_ports:
                    self.add_finding(
                        'HIGH',
                        'Network Security',
                        'SIP service exposed on public IP',
                        f'SIP service accessible from Internet on {self.target}',
                        f'Public IP: {self.target}\nOpen ports: {", ".join(open_ports)}',
                        'Restrict exposure:\n- Use VPN for remote access\n- Implement SIP ALG/SBC at edge\n- Whitelist known IP addresses\n- Use geo-blocking\n- Deploy DDoS protection',
                        'V6',
                        'high'
                    )
        except ValueError:
            pass  # Not an IP address, might be hostname
    
    def generate_executive_summary(self) -> str:
        """Generate executive summary"""
        risk_score = (self.stats['CRITICAL'] * 10 + self.stats['HIGH'] * 5 +
                     self.stats['MEDIUM'] * 2 + self.stats['LOW'] * 1)
        
        if risk_score > 50:
            risk_level = "CRITICAL"
            risk_description = "Immediate action required - VoIP infrastructure highly vulnerable"
        elif risk_score > 20:
            risk_level = "HIGH"
            risk_description = "Remediation needed within 7 days - Significant security gaps"
        elif risk_score > 10:
            risk_level = "MEDIUM"
            risk_description = "Address within 30 days - Moderate security concerns"
        else:
            risk_level = "LOW"
            risk_description = "Address during next maintenance - Minor issues identified"
        
        server_info = self.fingerprint.get('user_agent') or self.fingerprint.get('server', 'Unknown')
        
        summary = f"""
EXECUTIVE SUMMARY
{'=' * 80}

Overall Risk Level: {risk_level}
Risk Score: {risk_score}
Assessment: {risk_description}

Target Information:
  • Target: {self.target}
  • Server: {server_info}
  • Open Ports: {len(self.fingerprint.get('ports', {}))}
  • Valid Extensions Found: {len(self.extensions)}

Total Findings: {len(self.findings)}
  • CRITICAL: {self.stats['CRITICAL']} (Immediate action required)
  • HIGH:     {self.stats['HIGH']} (Remediate within 7 days)
  • MEDIUM:   {self.stats['MEDIUM']} (Address within 30 days)
  • LOW:      {self.stats['LOW']} (Address during maintenance)

Top Security Concerns:
"""
        
        critical_high = [f for f in self.findings if f['severity'] in ['CRITICAL', 'HIGH']]
        critical_high.sort(key=lambda x: 0 if x['severity'] == 'CRITICAL' else 1)
        
        for i, finding in enumerate(critical_high[:5], 1):
            summary += f"  {i}. [{finding['severity']}] {finding['title']}\n"
        
        if not critical_high:
            summary += "  None - VoIP infrastructure meets basic security standards\n"
        
        return summary
    
    def generate_report(self):
        """Generate comprehensive security report"""
        
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_findings = sorted(self.findings, 
                               key=lambda x: (severity_order.get(x['severity'], 999), 
                                            x.get('confidence') != 'high'))
        
        report = []
        report.append("=" * 80)
        report.append("VoIP/SIP Security Assessment Report")
        report.append("OWASP VoIP Security Guidelines Compliance")
        report.append("=" * 80)
        report.append(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Target: {self.target}")
        report.append(f"Assessment Mode: {'Aggressive' if self.aggressive else 'Passive'}")
        
        report.append("\n" + self.generate_executive_summary())
        
        report.append("\n" + "=" * 80)
        report.append("FINGERPRINTING RESULTS")
        report.append("=" * 80)
        
        report.append(f"\nServer Information:")
        if self.fingerprint.get('user_agent'):
            report.append(f"  User-Agent: {self.fingerprint['user_agent']}")
        if self.fingerprint.get('server'):
            report.append(f"  Server: {self.fingerprint['server']}")
        
        report.append(f"\nOpen Ports:")
        for proto, info in self.fingerprint.get('ports', {}).items():
            report.append(f"  • {proto}: {info['port']}/{info['protocol']} - {info['status']}")
        
        if self.fingerprint.get('methods'):
            report.append(f"\nSupported SIP Methods:")
            report.append(f"  {', '.join(self.fingerprint['methods'])}")
        
        if self.extensions:
            report.append(f"\nValid Extensions Discovered: {len(self.extensions)}")
            report.append(f"  {', '.join(self.extensions[:20])}")
            if len(self.extensions) > 20:
                report.append(f"  ... and {len(self.extensions) - 20} more")
        
        if self.fingerprint.get('vulnerabilities'):
            report.append(f"\nKnown Vulnerabilities:")
            for vuln in self.fingerprint['vulnerabilities']:
                report.append(f"  • {vuln['name']}")
                report.append(f"    CVEs: {', '.join(vuln['cves'])}")
        
        report.append("\n\n" + "=" * 80)
        report.append("DETAILED FINDINGS")
        report.append("=" * 80)
        
        for idx, finding in enumerate(sorted_findings, 1):
            confidence = f" [{finding.get('confidence', 'medium').upper()} CONFIDENCE]"
            
            report.append(f"\n\n{'=' * 80}")
            report.append(f"Finding #{idx}: {finding['severity']}{confidence}")
            report.append(f"{finding['title']}")
            report.append("=" * 80)
            
            report.append(f"\nCategory: {finding['category']}")
            if finding.get('control_id'):
                report.append(f"OWASP VoIP Control: {finding['control_id']}")
            
            report.append(f"\nDescription:")
            report.append(f"{finding['description']}")
            
            report.append(f"\nEvidence:")
            report.append(f"{finding['evidence']}")
            
            report.append(f"\nRemediation:")
            report.append(f"{finding['remediation']}")
        
        report.append("\n\n" + "=" * 80)
        report.append("PRIORITIZED ACTION PLAN")
        report.append("=" * 80)
        
        critical = [f for f in sorted_findings if f['severity'] == 'CRITICAL']
        high = [f for f in sorted_findings if f['severity'] == 'HIGH']
        medium = [f for f in sorted_findings if f['severity'] == 'MEDIUM']
        
        if critical:
            report.append("\n+-- PRIORITY 1: IMMEDIATE ACTION (Within 24 hours)")
            report.append("|")
            for i, f in enumerate(critical, 1):
                report.append(f"|  {i}. {f['title']}")
                report.append(f"|     Impact: {f['description'].split('.')[0]}")
            report.append("+--" + "-" * 77)
        
        if high:
            report.append("\n+-- PRIORITY 2: HIGH PRIORITY (Within 7 days)")
            report.append("|")
            for i, f in enumerate(high, 1):
                report.append(f"|  {i}. {f['title']}")
            report.append("+--" + "-" * 77)
        
        if medium:
            report.append("\n+-- PRIORITY 3: MEDIUM PRIORITY (Within 30 days)")
            report.append("|")
            for i, f in enumerate(medium[:5], 1):
                report.append(f"|  {i}. {f['title']}")
            if len(medium) > 5:
                report.append(f"|  ... and {len(medium) - 5} more")
            report.append("+--" + "-" * 77)
        
        report.append("\n\n" + "=" * 80)
        report.append("Report End")
        report.append("=" * 80)
        report.append(f"\nThis report contains security-sensitive information")
        report.append(f"Distribution: CONFIDENTIAL - For authorized personnel only")
        
        report_text = "\n".join(report)
        
        print("\n" + report_text)
        
        if self.output_file:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                f.write(report_text)
            print(f"\n[+] Report saved to: {self.output_file}")
        
        # Generate JSON report
        json_file = self.output_file.replace('.txt', '.json') if self.output_file else 'voip_assessment.json'
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump({
                'metadata': {
                    'target': self.target,
                    'scan_time': datetime.now().isoformat(),
                    'mode': 'aggressive' if self.aggressive else 'passive',
                    'server': self.fingerprint.get('user_agent') or self.fingerprint.get('server'),
                    'extensions_found': len(self.extensions)
                },
                'fingerprint': self.fingerprint,
                'extensions': self.extensions,
                'summary': {
                    'total_findings': len(self.findings),
                    'critical': self.stats['CRITICAL'],
                    'high': self.stats['HIGH'],
                    'medium': self.stats['MEDIUM'],
                    'low': self.stats['LOW'],
                    'risk_score': (self.stats['CRITICAL'] * 10 + self.stats['HIGH'] * 5 +
                                 self.stats['MEDIUM'] * 2 + self.stats['LOW'] * 1)
                },
                'findings': sorted_findings
            }, f, indent=2)
        print(f"[+] JSON report saved to: {json_file}")
    
    def run_assessment(self):
        """Run full VoIP security assessment"""
        print("\n" + "=" * 80)
        print("VoIP/SIP Security Assessment Tool")
        print("OWASP VoIP Security Guidelines & Best Practices")
        print("=" * 80)
        print(f"\nTarget: {self.target}")
        print(f"Mode: {'Aggressive' if self.aggressive else 'Passive'}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Fingerprinting
        print("\n[*] Phase 1: Fingerprinting and Reconnaissance")
        self.fingerprint = self.scanner.fingerprint_server()
        
        if not self.fingerprint.get('ports'):
            print("\n[!] No SIP services detected. Assessment cannot continue.")
            return False
        
        # Extension enumeration
        print("\n[*] Phase 2: Extension Enumeration")
        if self.aggressive:
            self.extensions = self.scanner.enumerate_extensions()
        else:
            print("[*] Skipping extension enumeration (passive mode)")
            print("[*] Use --aggressive flag to enable enumeration")
        
        # Security checks
        print("\n[*] Phase 3: Security Assessment")
        self.check_authentication()
        self.check_encryption()
        self.check_information_disclosure()
        self.check_vulnerabilities()
        self.check_dos_protection()
        self.check_enumeration_protection()
        self.check_allowed_methods()
        self.check_network_exposure()
        
        if self.aggressive:
            self.check_weak_credentials()
        
        print("\n[+] Assessment complete!")
        print(f"[+] Total findings: {len(self.findings)}")
        print(f"    CRITICAL: {self.stats['CRITICAL']}")
        print(f"    HIGH:     {self.stats['HIGH']}")
        print(f"    MEDIUM:   {self.stats['MEDIUM']}")
        print(f"    LOW:      {self.stats['LOW']}")
        
        return True


def main():
    parser = argparse.ArgumentParser(
        description='VoIP/SIP Security Assessment Tool - OWASP Compliance Testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic passive scan
  python voip_pentest.py -t 192.168.1.100 -o report.txt

  # Aggressive scan with extension enumeration
  python voip_pentest.py -t 192.168.1.100 -o report.txt --aggressive

  # Scan with timeout and exceptions
  python voip_pentest.py -t voip.example.com -o report.txt --timeout 10 --exceptions exceptions.json

IMPORTANT LEGAL NOTICE:
  This tool is for authorized security testing only.
  Unauthorized testing of VoIP systems may violate laws.
  Always obtain written authorization before testing.
        """
    )
    
    parser.add_argument('-t', '--target', required=True,
                       help='Target SIP server (IP or hostname)')
    parser.add_argument('-o', '--output', default='voip_assessment_report.txt',
                       help='Output report file')
    parser.add_argument('--aggressive', action='store_true',
                       help='Enable aggressive testing (extension enum, credential testing)')
    parser.add_argument('--timeout', type=int, default=5,
                       help='Socket timeout in seconds (default: 5)')
    parser.add_argument('--exceptions', 
                       help='Path to exceptions file (JSON)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Warning for aggressive mode
    if args.aggressive:
        print("\n" + "!" * 80)
        print("WARNING: Aggressive mode enabled")
        print("This will perform active enumeration and credential testing")
        print("Ensure you have written authorization to test this target")
        print("!" * 80)
        
        confirm = input("\nType 'YES' to continue with aggressive testing: ")
        if confirm != 'YES':
            print("[!] Aggressive testing cancelled. Exiting.")
            sys.exit(0)
    
    # Create auditor
    auditor = VoIPAuditor(
        target=args.target,
        output_file=args.output,
        aggressive=args.aggressive,
        exceptions_file=args.exceptions
    )
    
    # Run assessment
    if auditor.run_assessment():
        auditor.generate_report()
        
        # Exit codes based on findings
        if auditor.stats['CRITICAL'] > 0:
            sys.exit(2)
        elif auditor.stats['HIGH'] > 0:
            sys.exit(1)
        else:
            sys.exit(0)
    else:
        sys.exit(3)


if __name__ == '__main__':
    main()
