#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                    LX-BOT ULTIMATE RESOURCE MANAGER v5.0                  ║
║         Complete Offensive Security Toolkit Installation (2026)           ║
║                                                                           ║
║  • 60+ Offensive Tools    • Metasploit Framework    • Auto-Installation  ║
║  • CMS Scanners (WP/Joomla/Drupal/Magento)  • Service Exploitation       ║
║  • Perfect Integration    • Zero Config Required    • Production Ready    ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import subprocess
import platform
import shutil
import time
from pathlib import Path
from typing import Dict, Any, Callable, Optional

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
except ImportError:
    subprocess.run([sys.executable, '-m', 'pip', 'install', 'rich', '--break-system-packages', '-q'], check=True)
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.panel import Panel
    from rich import box

console = Console()


class UltimateResourceManager:
    """
    Ultimate Offensive Security Toolkit Manager
    Installs and manages 60+ penetration testing tools including:
    - Metasploit Framework (exploitation)
    - CMS-specific scanners (WordPress, Joomla, Drupal, Magento)
    - Network scanners (Nmap, Masscan, RustScan)
    - Vulnerability scanners (Nuclei, Nikto, Jaeles)
    - Injection tools (SQLmap, Commix, Dalfox, XSStrike)
    - OSINT tools (theHarvester, TruffleHog, GitLeaks)
    - And much more...
    """

    def __init__(self):
        self.system = platform.system().lower()
        self.home = Path.home()
        self._setup_go_path()

        # ═══════════════════════════════════════════════════════════════════
        # COMPLETE OFFENSIVE SECURITY TOOLKIT (60+ TOOLS)
        # ═══════════════════════════════════════════════════════════════════

        self.tools: Dict[str, Dict[str, Any]] = {
            
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # EXPLOITATION FRAMEWORKS
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            
            'msfconsole': {
                'check': 'msfconsole --version',
                'install': {
                    'linux': self._install_metasploit_linux,
                    'darwin': 'brew install metasploit',
                },
                'description': '🎯 Metasploit Framework - Complete Exploitation Platform',
                'category': 'exploitation',
                'priority': 1,
                'critical': True,
            },
            
            'msfvenom': {
                'check': 'msfvenom --version',
                'install': {
                    'linux': 'echo "Installed with Metasploit"',
                    'darwin': 'echo "Installed with Metasploit"',
                },
                'description': '💣 Msfvenom - Payload Generator',
                'category': 'exploitation',
                'priority': 1,
                'critical': True,
            },
            
            'searchsploit': {
                'check': 'searchsploit --help',
                'install': {
                    'linux': (
                        'git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git '
                        '/opt/exploitdb && sudo ln -sf /opt/exploitdb/searchsploit '
                        '/usr/local/bin/searchsploit && sudo chmod +x /usr/local/bin/searchsploit'
                    ),
                    'darwin': 'brew install exploitdb',
                },
                'description': '🗃️ SearchSploit - Exploit Database Search',
                'category': 'exploitation',
                'priority': 2,
                'critical': True,
            },

            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # CMS-SPECIFIC SCANNERS
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            
            'wpscan': {
                'check': 'wpscan --version',
                'install': {
                    'linux': 'sudo gem install wpscan',
                    'darwin': 'gem install wpscan',
                },
                'description': '📰 WPScan - WordPress Security Scanner',
                'category': 'cms',
                'priority': 1,
                'critical': True,
            },
            
            'joomscan': {
                'check': 'joomscan --version',
                'install': {
                    'linux': (
                        'git clone --depth 1 https://github.com/OWASP/joomscan.git /opt/joomscan '
                        '&& sudo ln -sf /opt/joomscan/joomscan.pl /usr/local/bin/joomscan '
                        '&& sudo chmod +x /usr/local/bin/joomscan'
                    ),
                    'darwin': (
                        'git clone --depth 1 https://github.com/OWASP/joomscan.git ~/joomscan '
                        '&& ln -sf ~/joomscan/joomscan.pl /usr/local/bin/joomscan '
                        '&& chmod +x /usr/local/bin/joomscan'
                    ),
                },
                'description': '🔮 JoomScan - Joomla Vulnerability Scanner',
                'category': 'cms',
                'priority': 1,
                'critical': True,
            },
            
            'droopescan': {
                'check': 'droopescan --version',
                'install': {
                    'linux': 'sudo pip3 install droopescan --break-system-packages',
                    'darwin': 'pip3 install droopescan',
                },
                'description': '💧 DroopeScan - Drupal/SilverStripe/Moodle Scanner',
                'category': 'cms',
                'priority': 1,
                'critical': True,
            },
            
            'magescan': {
                'check': 'magescan.phar --version',
                'install': {
                    'linux': (
                        'wget -q https://github.com/steverobbins/magescan/releases/download/v1.12.9/magescan.phar '
                        '-O /usr/local/bin/magescan.phar && sudo chmod +x /usr/local/bin/magescan.phar'
                    ),
                    'darwin': (
                        'wget -q https://github.com/steverobbins/magescan/releases/download/v1.12.9/magescan.phar '
                        '-O /usr/local/bin/magescan.phar && chmod +x /usr/local/bin/magescan.phar'
                    ),
                },
                'description': '🛒 MageScan - Magento Security Scanner',
                'category': 'cms',
                'priority': 2,
            },

            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # NETWORK & PORT SCANNING
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            
            'nmap': {
                'check': 'nmap --version',
                'install': {
                    'linux': 'sudo apt-get install -y nmap nmap-common',
                    'darwin': 'brew install nmap',
                },
                'description': '🔍 Nmap - Network Discovery & Security Auditing',
                'category': 'network',
                'priority': 1,
                'critical': True,
            },
            
            'masscan': {
                'check': 'masscan --version',
                'install': {
                    'linux': 'sudo apt-get install -y masscan',
                    'darwin': 'brew install masscan',
                },
                'description': '⚡ Masscan - Ultra-Fast Port Scanner',
                'category': 'network',
                'priority': 2,
            },
            
            'rustscan': {
                'check': 'rustscan --version',
                'install': {
                    'linux': (
                        'wget -q https://github.com/RustScan/RustScan/releases/download/2.1.1/rustscan_2.1.1_amd64.deb '
                        '-O /tmp/rustscan.deb && sudo dpkg -i /tmp/rustscan.deb; rm /tmp/rustscan.deb'
                    ),
                    'darwin': 'brew install rustscan',
                },
                'description': '🦀 RustScan - Modern Fast Port Scanner',
                'category': 'network',
                'priority': 3,
            },

            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # SUBDOMAIN ENUMERATION
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            
            'subfinder': {
                'check': 'subfinder -version',
                'install': {
                    'linux': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
                    'darwin': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
                },
                'description': '🔎 Subfinder - Passive Subdomain Discovery',
                'category': 'recon',
                'priority': 1,
                'critical': True,
            },
            
            'assetfinder': {
                'check': 'assetfinder --help',
                'install': {
                    'linux': 'go install github.com/tomnomnom/assetfinder@latest',
                    'darwin': 'go install github.com/tomnomnom/assetfinder@latest',
                },
                'description': '🎯 Assetfinder - Asset & Subdomain Discovery',
                'category': 'recon',
                'priority': 2,
            },
            
            'amass': {
                'check': 'amass version',
                'install': {
                    'linux': 'go install -v github.com/owasp-amass/amass/v4/...@master',
                    'darwin': 'brew install amass',
                },
                'description': '🕸️ OWASP Amass - In-depth DNS Enumeration',
                'category': 'recon',
                'priority': 1,
                'critical': True,
            },
            
            'findomain': {
                'check': 'findomain --version',
                'install': {
                    'linux': (
                        'wget -q https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux '
                        '-O /usr/local/bin/findomain && sudo chmod +x /usr/local/bin/findomain'
                    ),
                    'darwin': 'brew install findomain',
                },
                'description': '🌐 Findomain - Fast Subdomain Enumerator',
                'category': 'recon',
                'priority': 2,
            },
            
            'chaos': {
                'check': 'chaos -version',
                'install': {
                    'linux': 'go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest',
                    'darwin': 'go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest',
                },
                'description': '⚡ Chaos - ProjectDiscovery DNS Dataset',
                'category': 'recon',
                'priority': 3,
            },
            
            'subjack': {
                'check': 'subjack --help',
                'install': {
                    'linux': 'go install github.com/haccer/subjack@latest',
                    'darwin': 'go install github.com/haccer/subjack@latest',
                },
                'description': '🎣 Subjack - Subdomain Takeover Detection',
                'category': 'recon',
                'priority': 2,
            },
            
            'subover': {
                'check': 'subover --help',
                'install': {
                    'linux': 'go install github.com/Ice3man543/SubOver@latest',
                    'darwin': 'go install github.com/Ice3man543/SubOver@latest',
                },
                'description': '🔱 SubOver - Subdomain Takeover Tool',
                'category': 'recon',
                'priority': 3,
            },

            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # HTTP PROBING & WEB ANALYSIS
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            
            'httpx': {
                'check': 'httpx -version',
                'install': {
                    'linux': 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
                    'darwin': 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
                },
                'description': '🌐 HTTPx - HTTP Probe & Web Analysis',
                'category': 'web',
                'priority': 1,
                'critical': True,
            },
            
            'whatweb': {
                'check': 'whatweb --version',
                'install': {
                    'linux': 'sudo apt-get install -y whatweb',
                    'darwin': 'brew install whatweb',
                },
                'description': '🕷️ WhatWeb - Web Technology Identifier',
                'category': 'web',
                'priority': 1,
            },
            
            'wafw00f': {
                'check': 'wafw00f -h',
                'install': {
                    'linux': 'sudo pip3 install wafw00f --break-system-packages',
                    'darwin': 'pip3 install wafw00f',
                },
                'description': '🛡️ Wafw00f - WAF Detection & Fingerprinting',
                'category': 'web',
                'priority': 1,
                'critical': True,
            },
            
            'nikto': {
                'check': 'nikto -Version',
                'install': {
                    'linux': 'sudo apt-get install -y nikto',
                    'darwin': 'brew install nikto',
                },
                'description': '🔨 Nikto - Web Server Vulnerability Scanner',
                'category': 'web',
                'priority': 2,
            },
            
            'webanalyze': {
                'check': 'webanalyze --help',
                'install': {
                    'linux': 'go install github.com/rverton/webanalyze/cmd/webanalyze@latest',
                    'darwin': 'go install github.com/rverton/webanalyze/cmd/webanalyze@latest',
                },
                'description': '🔬 WebAnalyze - Technology Detection',
                'category': 'web',
                'priority': 3,
            },

            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # CRAWLING & SPIDERING
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            
            'katana': {
                'check': 'katana -version',
                'install': {
                    'linux': 'go install github.com/projectdiscovery/katana/cmd/katana@latest',
                    'darwin': 'go install github.com/projectdiscovery/katana/cmd/katana@latest',
                },
                'description': '🗡️ Katana - Next-Gen Crawling Framework',
                'category': 'web',
                'priority': 1,
                'critical': True,
            },
            
            'gospider': {
                'check': 'gospider --help',
                'install': {
                    'linux': 'go install github.com/jaeles-project/gospider@latest',
                    'darwin': 'go install github.com/jaeles-project/gospider@latest',
                },
                'description': '🕷️ GoSpider - Fast Web Crawler',
                'category': 'web',
                'priority': 2,
            },
            
            'hakrawler': {
                'check': 'hakrawler --help',
                'install': {
                    'linux': 'go install github.com/hakluke/hakrawler@latest',
                    'darwin': 'go install github.com/hakluke/hakrawler@latest',
                },
                'description': '🦎 Hakrawler - Simple Fast Crawler',
                'category': 'web',
                'priority': 2,
            },

            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # JAVASCRIPT ANALYSIS
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            
            'subjs': {
                'check': 'subjs --help',
                'install': {
                    'linux': 'go install github.com/lc/subjs@latest',
                    'darwin': 'go install github.com/lc/subjs@latest',
                },
                'description': '📜 Subjs - JavaScript File Extractor',
                'category': 'web',
                'priority': 2,
            },
            
            'getJS': {
                'check': 'getJS --help',
                'install': {
                    'linux': 'go install github.com/003random/getJS@latest',
                    'darwin': 'go install github.com/003random/getJS@latest',
                },
                'description': '📝 GetJS - JavaScript Fetcher',
                'category': 'web',
                'priority': 3,
            },

            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # DIRECTORY & CONTENT DISCOVERY
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            
            'ffuf': {
                'check': 'ffuf -V',
                'install': {
                    'linux': 'go install github.com/ffuf/ffuf/v2@latest',
                    'darwin': 'go install github.com/ffuf/ffuf/v2@latest',
                },
                'description': '🎯 Ffuf - Fast Web Fuzzer',
                'category': 'fuzzing',
                'priority': 1,
                'critical': True,
            },
            
            'feroxbuster': {
                'check': 'feroxbuster --version',
                'install': {
                    'linux': (
                        'curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh '
                        '| bash -s -- /usr/local/bin'
                    ),
                    'darwin': 'brew install feroxbuster',
                },
                'description': '🦀 Feroxbuster - Recursive Content Discovery',
                'category': 'fuzzing',
                'priority': 1,
                'critical': True,
            },
            
            'dirsearch': {
                'check': 'dirsearch --version',
                'install': {
                    'linux': (
                        'git clone --depth 1 https://github.com/maurosoria/dirsearch.git /opt/dirsearch '
                        '&& sudo ln -sf /opt/dirsearch/dirsearch.py /usr/local/bin/dirsearch '
                        '&& sudo chmod +x /usr/local/bin/dirsearch'
                    ),
                    'darwin': (
                        'git clone --depth 1 https://github.com/maurosoria/dirsearch.git ~/dirsearch '
                        '&& ln -sf ~/dirsearch/dirsearch.py /usr/local/bin/dirsearch'
                    ),
                },
                'description': '📂 Dirsearch - Web Path Scanner',
                'category': 'fuzzing',
                'priority': 2,
            },
            
            'gobuster': {
                'check': 'gobuster version',
                'install': {
                    'linux': 'go install github.com/OJ/gobuster/v3@latest',
                    'darwin': 'go install github.com/OJ/gobuster/v3@latest',
                },
                'description': '🔍 Gobuster - Directory/DNS Bruteforcing',
                'category': 'fuzzing',
                'priority': 2,
            },

            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # VULNERABILITY SCANNING
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            
            'nuclei': {
                'check': 'nuclei -version',
                'install': {
                    'linux': 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
                    'darwin': 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
                },
                'description': '☢️ Nuclei - Template-Based Vulnerability Scanner',
                'category': 'vulnerability',
                'priority': 1,
                'critical': True,
            },
            
            'jaeles': {
                'check': 'jaeles version',
                'install': {
                    'linux': 'go install github.com/jaeles-project/jaeles@latest',
                    'darwin': 'go install github.com/jaeles-project/jaeles@latest',
                },
                'description': '⚔️ Jaeles - Automated Web Application Scanner',
                'category': 'vulnerability',
                'priority': 2,
            },

            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # INJECTION TESTING
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            
            'sqlmap': {
                'check': 'sqlmap --version',
                'install': {
                    'linux': 'sudo apt-get install -y sqlmap',
                    'darwin': 'brew install sqlmap',
                },
                'description': '💉 SQLmap - SQL Injection Automation',
                'category': 'injection',
                'priority': 1,
                'critical': True,
            },
            
            'dalfox': {
                'check': 'dalfox version',
                'install': {
                    'linux': 'go install github.com/hahwul/dalfox/v2@latest',
                    'darwin': 'go install github.com/hahwul/dalfox/v2@latest',
                },
                'description': '🦊 Dalfox - Advanced XSS Scanner',
                'category': 'injection',
                'priority': 1,
                'critical': True,
            },
            
            'commix': {
                'check': 'commix --version',
                'install': {
                    'linux': (
                        'git clone --depth 1 https://github.com/commixproject/commix.git /opt/commix '
                        '&& sudo ln -sf /opt/commix/commix.py /usr/local/bin/commix '
                        '&& sudo chmod +x /usr/local/bin/commix'
                    ),
                    'darwin': (
                        'git clone --depth 1 https://github.com/commixproject/commix.git ~/commix '
                        '&& ln -sf ~/commix/commix.py /usr/local/bin/commix'
                    ),
                },
                'description': '💻 Commix - Command Injection Exploitation',
                'category': 'injection',
                'priority': 1,
                'critical': True,
            },
            
            'nosqlmap': {
                'check': 'python3 -c "import nosqlmap"',
                'install': {
                    'linux': (
                        'git clone --depth 1 https://github.com/codingo/NoSQLMap.git /opt/nosqlmap '
                        '&& sudo pip3 install -r /opt/nosqlmap/requirements.txt --break-system-packages'
                    ),
                    'darwin': (
                        'git clone --depth 1 https://github.com/codingo/NoSQLMap.git ~/nosqlmap '
                        '&& pip3 install -r ~/nosqlmap/requirements.txt'
                    ),
                },
                'description': '🗄️ NoSQLMap - NoSQL Injection Scanner',
                'category': 'injection',
                'priority': 2,
            },

            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # SSL/TLS TESTING
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            
            'testssl': {
                'check': 'testssl.sh --version',
                'install': {
                    'linux': (
                        'git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl '
                        '&& sudo ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl.sh'
                    ),
                    'darwin': 'brew install testssl',
                },
                'description': '🔐 Testssl.sh - SSL/TLS Configuration Scanner',
                'category': 'web',
                'priority': 2,
            },
            
            'sslscan': {
                'check': 'sslscan --version',
                'install': {
                    'linux': 'sudo apt-get install -y sslscan',
                    'darwin': 'brew install sslscan',
                },
                'description': '🔒 SSLScan - SSL/TLS Vulnerability Scanner',
                'category': 'web',
                'priority': 3,
            },

            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # SCREENSHOTS & VISUAL RECON
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            
            'gowitness': {
                'check': 'gowitness version',
                'install': {
                    'linux': 'go install github.com/sensepost/gowitness@latest',
                    'darwin': 'go install github.com/sensepost/gowitness@latest',
                },
                'description': '📸 Gowitness - Web Screenshot Utility',
                'category': 'recon',
                'priority': 3,
            },
            
            'aquatone': {
                'check': 'aquatone --version',
                'install': {
                    'linux': (
                        'wget -q https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip '
                        '-O /tmp/aquatone.zip && unzip -q /tmp/aquatone.zip -d /tmp/ '
                        '&& sudo mv /tmp/aquatone /usr/local/bin/ && rm /tmp/aquatone.zip'
                    ),
                    'darwin': 'brew install aquatone',
                },
                'description': '🌊 Aquatone - Visual Inspection Tool',
                'category': 'recon',
                'priority': 3,
            },

            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # OSINT & INTELLIGENCE GATHERING
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            
            'theHarvester': {
                'check': 'theHarvester -h',
                'install': {
                    'linux': 'sudo pip3 install theHarvester --break-system-packages',
                    'darwin': 'pip3 install theHarvester',
                },
                'description': '🔍 theHarvester - Email/OSINT Gathering',
                'category': 'osint',
                'priority': 1,
                'critical': True,
            },
            
            'trufflehog': {
                'check': 'trufflehog --version',
                'install': {
                    'linux': (
                        'curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh '
                        '| sudo sh -s -- -b /usr/local/bin'
                    ),
                    'darwin': 'brew install trufflehog',
                },
                'description': '🔑 TruffleHog - Secret Scanner (Git/Files/S3)',
                'category': 'osint',
                'priority': 1,
                'critical': True,
            },
            
            'gitleaks': {
                'check': 'gitleaks version',
                'install': {
                    'linux': 'go install github.com/gitleaks/gitleaks/v8@latest',
                    'darwin': 'brew install gitleaks',
                },
                'description': '🔐 GitLeaks - Git Secret Detection',
                'category': 'osint',
                'priority': 2,
            },
            
            'gitrob': {
                'check': 'gitrob --version',
                'install': {
                    'linux': 'go install github.com/michenriksen/gitrob@latest',
                    'darwin': 'go install github.com/michenriksen/gitrob@latest',
                },
                'description': '🕵️ Gitrob - GitHub Reconnaissance',
                'category': 'osint',
                'priority': 3,
            },

            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # UTILITIES & HELPERS
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            
            'jq': {
                'check': 'jq --version',
                'install': {
                    'linux': 'sudo apt-get install -y jq',
                    'darwin': 'brew install jq',
                },
                'description': '📋 jq - JSON Command-Line Processor',
                'category': 'utility',
                'priority': 1,
            },
            
            'anew': {
                'check': 'anew --help',
                'install': {
                    'linux': 'go install github.com/tomnomnom/anew@latest',
                    'darwin': 'go install github.com/tomnomnom/anew@latest',
                },
                'description': '📝 Anew - Add New Lines (Deduplication)',
                'category': 'utility',
                'priority': 2,
            },
            
            'gau': {
                'check': 'gau --help',
                'install': {
                    'linux': 'go install github.com/lc/gau/v2/cmd/gau@latest',
                    'darwin': 'go install github.com/lc/gau/v2/cmd/gau@latest',
                },
                'description': '🌐 GAU - Get All URLs (Wayback/AlienVault)',
                'category': 'recon',
                'priority': 2,
            },
            
            'waybackurls': {
                'check': 'waybackurls --help',
                'install': {
                    'linux': 'go install github.com/tomnomnom/waybackurls@latest',
                    'darwin': 'go install github.com/tomnomnom/waybackurls@latest',
                },
                'description': '📚 Waybackurls - Wayback Machine URL Fetcher',
                'category': 'recon',
                'priority': 2,
            },
            
            'gf': {
                'check': 'gf --help',
                'install': {
                    'linux': 'go install github.com/tomnomnom/gf@latest',
                    'darwin': 'go install github.com/tomnomnom/gf@latest',
                },
                'description': '🔎 GF - Grep Wrapper for Offensive Patterns',
                'category': 'utility',
                'priority': 2,
            },
            
            'notify': {
                'check': 'notify -version',
                'install': {
                    'linux': 'go install -v github.com/projectdiscovery/notify/cmd/notify@latest',
                    'darwin': 'go install -v github.com/projectdiscovery/notify/cmd/notify@latest',
                },
                'description': '📢 Notify - Send Findings to Slack/Discord/Telegram',
                'category': 'utility',
                'priority': 3,
            },
            
            'interactsh-client': {
                'check': 'interactsh-client -version',
                'install': {
                    'linux': 'go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest',
                    'darwin': 'go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest',
                },
                'description': '🔄 Interactsh - OOB Interaction Server (SSRF/Blind)',
                'category': 'utility',
                'priority': 2,
            },
            
            'unfurl': {
                'check': 'unfurl --help',
                'install': {
                    'linux': 'go install github.com/tomnomnom/unfurl@latest',
                    'darwin': 'go install github.com/tomnomnom/unfurl@latest',
                },
                'description': '🔗 Unfurl - URL Analysis Tool',
                'category': 'utility',
                'priority': 3,
            },
            
            'qsreplace': {
                'check': 'qsreplace --help',
                'install': {
                    'linux': 'go install github.com/tomnomnom/qsreplace@latest',
                    'darwin': 'go install github.com/tomnomnom/qsreplace@latest',
                },
                'description': '🔧 Qsreplace - Query String Replacer',
                'category': 'utility',
                'priority': 3,
            },

            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # AUXILIARY TOOLS
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            
            'whois': {
                'check': 'whois --version',
                'install': {
                    'linux': 'sudo apt-get install -y whois',
                    'darwin': 'brew install whois',
                },
                'description': '📇 Whois - Domain Information Lookup',
                'category': 'recon',
                'priority': 3,
            },
            
            'dig': {
                'check': 'dig -v',
                'install': {
                    'linux': 'sudo apt-get install -y dnsutils',
                    'darwin': 'echo "dig pre-installed"',
                },
                'description': '🔎 Dig - DNS Lookup Utility',
                'category': 'recon',
                'priority': 3,
            },
            
            'host': {
                'check': 'host -V',
                'install': {
                    'linux': 'sudo apt-get install -y bind9-host',
                    'darwin': 'echo "host pre-installed"',
                },
                'description': '🌍 Host - DNS Lookup',
                'category': 'recon',
                'priority': 3,
            },
        }

        self.python_packages = {
            'rich': 'Rich terminal UI framework',
            'requests': 'HTTP library for Python',
            'beautifulsoup4': 'HTML/XML parsing',
            'lxml': 'XML and HTML processing',
            'dnspython': 'DNS toolkit for Python',
            'aiohttp': 'Async HTTP client/server',
            'jinja2': 'Template engine',
            'matplotlib': 'Plotting and graphs',
            'numpy': 'Numerical computing',
            'plotly': 'Interactive graphing',
            'pandas': 'Data analysis',
            'pyyaml': 'YAML parser',
        }

        self.wordlists = {
            'SecLists': {
                'url': 'https://github.com/danielmiessler/SecLists.git',
                'path': '/usr/share/seclists',
                'description': 'The Penetration Tester\'s Companion',
            }
        }

    # ══════════════════════════════════════════════════════════════════════
    # PATH MANAGEMENT
    # ══════════════════════════════════════════════════════════════════════

    def _setup_go_path(self):
        """Ensure Go bin directories are in PATH for current session."""
        go_paths = [
            self.home / 'go' / 'bin',
            Path('/usr/local/go/bin'),
        ]
        for path in go_paths:
            if path.exists() and str(path) not in os.environ.get('PATH', ''):
                os.environ['PATH'] = f"{path}:{os.environ.get('PATH', '')}"

    def _persist_go_path(self):
        """Add Go paths to shell profile permanently."""
        go_bin = self.home / 'go' / 'bin'
        
        # Determine shell config file
        shell_rc = self.home / '.bashrc'
        if (self.home / '.zshrc').exists():
            shell_rc = self.home / '.zshrc'
        
        marker = f'export PATH="$PATH:{go_bin}"'
        
        try:
            if shell_rc.exists():
                content = shell_rc.read_text()
                if marker not in content:
                    with open(shell_rc, 'a') as f:
                        f.write(f'\n# LX-BOT Go binaries PATH\n{marker}\n')
                        f.write(f'export PATH="$PATH:/usr/local/go/bin"\n')
        except Exception:
            pass

    # ══════════════════════════════════════════════════════════════════════
    # METASPLOIT INSTALLATION (SPECIAL HANDLER)
    # ══════════════════════════════════════════════════════════════════════

    def _install_metasploit_linux(self):
        """
        Install Metasploit Framework on Linux using official installer.
        Handles both installation and database initialization.
        """
        console.print('[bold cyan]═══ Installing Metasploit Framework ═══[/bold cyan]')
        console.print('[yellow]This may take several minutes...[/yellow]\n')
        
        # Method 1: Official rapid7 installer
        console.print('[cyan]▸ Downloading official Metasploit installer...[/cyan]')
        installer_url = 'https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb'
        
        cmds_official = [
            f'curl -sL {installer_url} > /tmp/msfinstall',
            'chmod +x /tmp/msfinstall',
            'sudo /tmp/msfinstall',
        ]
        
        success = True
        for cmd in cmds_official:
            console.print(f'[dim]→ {cmd}[/dim]')
            try:
                result = subprocess.run(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=900,  # 15 minutes
                )
                if result.returncode != 0:
                    console.print(f'[yellow]⚠ Command failed, trying apt method...[/yellow]')
                    success = False
                    break
            except subprocess.TimeoutExpired:
                console.print('[yellow]⚠ Installer timeout, trying apt method...[/yellow]')
                success = False
                break
            except Exception as exc:
                console.print(f'[yellow]⚠ Error: {exc}, trying apt method...[/yellow]')
                success = False
                break
        
        # Method 2: Fallback to apt
        if not success:
            console.print('\n[cyan]▸ Installing via apt package manager...[/cyan]')
            apt_cmds = [
                'sudo apt-get update -qq',
                'sudo apt-get install -y metasploit-framework',
            ]
            for cmd in apt_cmds:
                console.print(f'[dim]→ {cmd}[/dim]')
                try:
                    subprocess.run(cmd, shell=True, check=True, timeout=900)
                except Exception as exc:
                    console.print(f'[red]✗ Failed: {exc}[/red]')
                    raise
        
        # Initialize Metasploit database
        console.print('\n[cyan]▸ Initializing Metasploit database...[/cyan]')
        try:
            subprocess.run('sudo msfdb init', shell=True, timeout=300)
            console.print('[green]✓ Metasploit database initialized[/green]')
        except Exception as exc:
            console.print(f'[yellow]⚠ Database init failed (non-critical): {exc}[/yellow]')
        
        # Verify installation
        console.print('\n[cyan]▸ Verifying Metasploit installation...[/cyan]')
        try:
            result = subprocess.run(
                'msfconsole --version',
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
            )
            if result.returncode == 0:
                version = result.stdout.decode().strip()
                console.print(f'[bold green]✓ Metasploit Framework installed successfully![/bold green]')
                console.print(f'[dim]Version: {version}[/dim]')
            else:
                console.print('[red]✗ Installation verification failed[/red]')
        except Exception as exc:
            console.print(f'[yellow]⚠ Could not verify installation: {exc}[/yellow]')

    # ══════════════════════════════════════════════════════════════════════
    # TOOL MANAGEMENT
    # ══════════════════════════════════════════════════════════════════════

    def check_tool(self, tool_name: str) -> bool:
        """Check if a tool is installed and accessible."""
        if tool_name not in self.tools:
            return False
        
        # Fast path: check if binary is in PATH
        check_cmd = self.tools[tool_name]['check']
        binary = check_cmd.split()[0]
        
        if shutil.which(binary):
            return True
        
        # Subprocess check for more complex checks
        try:
            result = subprocess.run(
                check_cmd,
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            return result.returncode == 0
        except Exception:
            return False

    def install_tool(self, tool_name: str) -> bool:
        """Install a specific tool."""
        if tool_name not in self.tools:
            console.print(f'[red]✗ Unknown tool: {tool_name}[/red]')
            return False

        tool_info = self.tools[tool_name]
        
        if self.system not in tool_info['install']:
            console.print(f'[red]✗ {tool_name}: No installer for {self.system}[/red]')
            return False

        install_cmd = tool_info['install'][self.system]
        
        # Handle callable installers (like Metasploit)
        if callable(install_cmd):
            try:
                install_cmd()
                return True
            except Exception as exc:
                console.print(f'[red]✗ {tool_name} installation failed: {exc}[/red]')
                return False

        # Handle string commands
        console.print(f'[yellow]⚙ Installing {tool_name}...[/yellow]')
        
        try:
            result = subprocess.run(
                install_cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=900,  # 15 minutes max
                env=os.environ,  # Pass current environment with updated PATH
            )
            
            if result.returncode == 0:
                console.print(f'[green]✓ {tool_name}[/green]')
                
                # If Go tool, persist PATH
                if 'go install' in install_cmd:
                    self._persist_go_path()
                
                return True
            else:
                err_msg = result.stderr.decode(errors='ignore')[:300]
                console.print(f'[red]✗ {tool_name}: {err_msg}[/red]')
                return False
                
        except subprocess.TimeoutExpired:
            console.print(f'[red]✗ {tool_name}: Installation timeout[/red]')
            return False
        except Exception as exc:
            console.print(f'[red]✗ {tool_name}: {exc}[/red]')
            return False

    # ══════════════════════════════════════════════════════════════════════
    # GO INSTALLATION
    # ══════════════════════════════════════════════════════════════════════

    def check_go_installed(self) -> bool:
        """Check if Go is installed."""
        try:
            result = subprocess.run(
                'go version',
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def install_go(self) -> bool:
        """Install Go programming language."""
        if self.check_go_installed():
            console.print('[green]✓ Go already installed[/green]')
            return True
        
        console.print('[yellow]Installing Go 1.22.0...[/yellow]')
        
        if self.system == 'linux':
            cmds = [
                'wget -q https://go.dev/dl/go1.22.0.linux-amd64.tar.gz -O /tmp/go.tar.gz',
                'sudo rm -rf /usr/local/go',
                'sudo tar -C /usr/local -xzf /tmp/go.tar.gz',
                'rm /tmp/go.tar.gz',
            ]
        elif self.system == 'darwin':
            cmds = ['brew install go']
        else:
            console.print(f'[red]Go installation not supported on {self.system}[/red]')
            return False

        for cmd in cmds:
            console.print(f'[dim]→ {cmd}[/dim]')
            try:
                subprocess.run(cmd, shell=True, check=True, timeout=600)
            except Exception as exc:
                console.print(f'[red]Failed: {cmd}: {exc}[/red]')
                return False

        self._persist_go_path()
        self._setup_go_path()
        
        console.print('[green]✓ Go installed successfully[/green]')
        return True

    # ══════════════════════════════════════════════════════════════════════
    # PYTHON PACKAGES
    # ══════════════════════════════════════════════════════════════════════

    def check_python_packages(self) -> Dict[str, bool]:
        """Check which Python packages are installed."""
        status = {}
        for pkg in self.python_packages:
            try:
                __import__(pkg.replace('-', '_'))
                status[pkg] = True
            except ImportError:
                status[pkg] = False
        return status

    def install_python_packages(self):
        """Install missing Python packages."""
        console.print('\n[bold cyan]═══ Python Packages ═══[/bold cyan]')
        
        status = self.check_python_packages()
        missing = [pkg for pkg, installed in status.items() if not installed]
        
        if not missing:
            console.print('[green]✓ All Python packages already installed[/green]')
            return
        
        console.print(f'[yellow]Installing {len(missing)} package(s)...[/yellow]')
        
        for pkg in missing:
            console.print(f'[dim]→ pip3 install {pkg}[/dim]')
            try:
                subprocess.run(
                    f'pip3 install {pkg} --break-system-packages -q',
                    shell=True,
                    check=True,
                    timeout=300,
                )
                console.print(f'[green]✓ {pkg}[/green]')
            except Exception as exc:
                console.print(f'[red]✗ {pkg}: {exc}[/red]')

    # ══════════════════════════════════════════════════════════════════════
    # WORDLISTS
    # ══════════════════════════════════════════════════════════════════════

    def install_wordlists(self):
        """Install SecLists wordlist collection."""
        console.print('\n[bold cyan]═══ Wordlists ═══[/bold cyan]')
        
        seclists_path = Path(self.wordlists['SecLists']['path'])
        
        if seclists_path.exists():
            console.print('[green]✓ SecLists already installed[/green]')
            return True
        
        console.print('[yellow]Cloning SecLists (this will take a few minutes)...[/yellow]')
        
        try:
            cmd = f"sudo git clone --depth 1 {self.wordlists['SecLists']['url']} {seclists_path}"
            console.print(f'[dim]→ {cmd}[/dim]')
            subprocess.run(cmd, shell=True, check=True, timeout=1200)
            console.print('[green]✓ SecLists installed successfully[/green]')
            return True
        except Exception as exc:
            console.print(f'[red]✗ SecLists installation failed: {exc}[/red]')
            console.print('[yellow]Manual install:[/yellow]')
            console.print(f'[dim]sudo git clone {self.wordlists["SecLists"]["url"]} {seclists_path}[/dim]')
            return False

    # ══════════════════════════════════════════════════════════════════════
    # STATUS DISPLAY
    # ══════════════════════════════════════════════════════════════════════

    def display_status(self):
        """Display comprehensive tool installation status."""
        console.print('\n[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]')
        console.print('[bold cyan]       OFFENSIVE SECURITY TOOLKIT STATUS               [/bold cyan]')
        console.print('[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]\n')
        
        # Group tools by category
        categories: Dict[str, list] = {}
        for tool_name, tool_info in self.tools.items():
            cat = tool_info.get('category', 'other')
            if cat not in categories:
                categories[cat] = []
            categories[cat].append((tool_name, tool_info))
        
        total_tools = 0
        installed_count = 0
        critical_missing = []
        
        # Display by category
        for category_name in sorted(categories.keys()):
            tools_in_category = categories[category_name]
            
            console.print(f'\n[bold magenta]▸ {category_name.upper()}[/bold magenta]')
            
            table = Table(show_header=True, header_style='bold cyan', box=box.MINIMAL)
            table.add_column('Tool', style='cyan', width=24)
            table.add_column('Status', width=14)
            table.add_column('Description', style='dim', width=60)
            
            # Sort by priority
            for tool_name, tool_info in sorted(tools_in_category, 
                                              key=lambda x: x[1].get('priority', 99)):
                is_installed = self.check_tool(tool_name)
                status = '[green]✓ Installed[/green]' if is_installed else '[red]✗ Missing[/red]'
                
                if is_installed:
                    installed_count += 1
                elif tool_info.get('critical'):
                    critical_missing.append(tool_name)
                
                total_tools += 1
                
                # Add critical indicator
                desc = tool_info['description']
                if tool_info.get('critical'):
                    desc += ' [bold red](CRITICAL)[/bold red]'
                
                table.add_row(tool_name, status, desc)
            
            console.print(table)
        
        # Summary
        console.print('\n[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]')
        pct = (installed_count / total_tools * 100) if total_tools else 0
        console.print(f'[bold]Summary: {installed_count}/{total_tools} tools installed ({pct:.1f}%)[/bold]')
        
        if critical_missing:
            console.print(f'\n[bold red]⚠ {len(critical_missing)} CRITICAL tools missing:[/bold red]')
            for tool in critical_missing:
                console.print(f'  [red]• {tool}[/red]')
        
        if installed_count < total_tools:
            console.print('\n[yellow]Run with --install to install all missing tools:[/yellow]')
            console.print('[dim]python3 resource_manager.py --install[/dim]')

    # ══════════════════════════════════════════════════════════════════════
    # MASTER INSTALLATION
    # ══════════════════════════════════════════════════════════════════════

    def check_and_install_all(self):
        """
        Master installation function.
        Installs all dependencies in order:
        1. Python packages
        2. Go programming language
        3. Wordlists
        4. All security tools (prioritized)
        """
        console.print(Panel.fit(
            '[bold cyan]╔═══════════════════════════════════════════════════════════╗\n'
            '║     LX-BOT ULTIMATE RESOURCE MANAGER v5.0                 ║\n'
            '║     Complete Offensive Security Toolkit Installation     ║\n'
            '╚═══════════════════════════════════════════════════════════╝[/bold cyan]\n\n'
            f'[white]System: {platform.system()} {platform.release()}[/white]\n'
            f'[white]Architecture: {platform.machine()}[/white]\n'
            f'[white]Total Tools: {len(self.tools)}[/white]',
            border_style='cyan',
            box=box.DOUBLE,
        ))
        
        start_time = time.time()
        
        # Step 1: Python packages
        self.install_python_packages()
        
        # Step 2: Go
        console.print('\n[bold cyan]═══ Go Programming Language ═══[/bold cyan]')
        self.install_go()
        self._setup_go_path()
        
        # Step 3: Wordlists
        self.install_wordlists()
        
        # Step 4: Security tools
        console.print('\n[bold cyan]═══ Security Tools Installation ═══[/bold cyan]')
        
        missing_tools = [name for name in self.tools if not self.check_tool(name)]
        
        if not missing_tools:
            console.print('[green]✓ All tools already installed![/green]')
        else:
            console.print(f'\n[yellow]{len(missing_tools)} tool(s) to install[/yellow]')
            
            # Sort by priority (critical tools first)
            missing_tools.sort(key=lambda x: (
                not self.tools[x].get('critical', False),  # Critical first
                self.tools[x].get('priority', 99)  # Then by priority
            ))
            
            with Progress(
                SpinnerColumn(),
                TextColumn('[progress.description]{task.description}'),
                BarColumn(),
                TextColumn('{task.completed}/{task.total}'),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task('Installing tools...', total=len(missing_tools))
                
                for tool in missing_tools:
                    progress.update(task, description=f'Installing {tool}...')
                    self.install_tool(tool)
                    progress.advance(task)
        
        # Final status display
        console.print('\n')
        self.display_status()
        
        # Summary
        elapsed = time.time() - start_time
        console.print(f'\n[bold green]✓ Setup completed in {elapsed/60:.1f} minutes[/bold green]')
        console.print('\n[yellow]Important:[/yellow]')
        console.print('[white]• Restart your terminal or run: source ~/.bashrc (or ~/.zshrc)[/white]')
        console.print('[white]• Some tools may require additional API keys or configuration[/white]')
        console.print('[white]• Ready to use with: python3 lx-bot-v5.py -t target.com[/white]')


# Backward compatibility alias
ResourceManager = UltimateResourceManager


def main():
    """Main entry point for standalone execution."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='LX-BOT Ultimate Resource Manager v5.0 - Complete Offensive Security Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 resource_manager.py --install    # Install all tools
  python3 resource_manager.py --check      # Check installation status
        """
    )
    
    parser.add_argument('--check', action='store_true', 
                       help='Check tool installation status')
    parser.add_argument('--install', action='store_true', 
                       help='Install all missing tools and dependencies')
    
    args = parser.parse_args()
    
    manager = UltimateResourceManager()
    
    if args.check:
        manager.display_status()
    else:
        # Default action is install
        manager.check_and_install_all()


if __name__ == '__main__':
    main()
