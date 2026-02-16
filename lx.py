#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║              LX-BOT ULTIMATE v5.0 — CORE ENGINE MODULE                      ║
║         Next-Gen Enterprise Penetration Testing & Bug Bounty Framework      ║
║                                                                              ║
║  • Phase 1: Reconnaissance (12 tools)   • Phase 4: API & Endpoint Discovery ║
║  • Phase 2: Port Scanning (3 tools)     • Phase 5: Content Discovery        ║
║  • Phase 3: Web Analysis & CMS (8+)     • Full Async Execution Engine       ║
║                                                                              ║
║  lx.py  ← Core Engine (this file)                                           ║
║  lx-bot.py ← Phases 6-10, CLI, Orchestrator                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

USAGE (via lx-bot.py):
    python3 lx-bot.py -t https://target.com
    python3 lx-bot.py -t https://target.com --proxy http://127.0.0.1:8080
"""

import os
import sys
import json
import asyncio
import subprocess
import threading
import re
import time
import socket
import hashlib
import ipaddress
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Set
from urllib.parse import urlparse, urljoin, quote

# ─── Rich imports ───────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import (
        Progress, SpinnerColumn, TextColumn, BarColumn,
        TimeElapsedColumn, TaskProgressColumn
    )
    from rich.live import Live
    from rich.layout import Layout
    from rich.text import Text
    from rich.columns import Columns
    from rich import box
    from rich.markup import escape
    from rich.rule import Rule
    from rich.style import Style
    from rich.prompt import Prompt
except ImportError:
    subprocess.run([sys.executable, '-m', 'pip', 'install', 'rich', '--break-system-packages', '-q'])
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import (
        Progress, SpinnerColumn, TextColumn, BarColumn,
        TimeElapsedColumn, TaskProgressColumn
    )
    from rich.live import Live
    from rich.layout import Layout
    from rich.text import Text
    from rich.columns import Columns
    from rich import box
    from rich.markup import escape
    from rich.rule import Rule
    from rich.style import Style
    from rich.prompt import Prompt

# ─── Global console ─────────────────────────────────────────────────────────
console = Console(highlight=False)

# ═══════════════════════════════════════════════════════════════════════════
# CONSTANTS & SIGNATURES
# ═══════════════════════════════════════════════════════════════════════════

BANNER = r"""
[bold cyan]
 ██╗     ██╗  ██╗      ██████╗  ██████╗ ████████╗
 ██║     ╚██╗██╔╝      ██╔══██╗██╔═══██╗╚══██╔══╝
 ██║      ╚███╔╝ █████╗██████╔╝██║   ██║   ██║   
 ██║      ██╔██╗ ╚════╝██╔══██╗██║   ██║   ██║   
 ███████╗██╔╝ ██╗       ██████╔╝╚██████╔╝   ██║   
 ╚══════╝╚═╝  ╚═╝       ╚═════╝  ╚═════╝    ╚═╝   
[/bold cyan]
[bold magenta]       ULTIMATE v5.0 — Next-Gen Enterprise Security Framework[/bold magenta]
[dim]       Bug Bounty • Red Team • Pentest Automation • 60+ Tools[/dim]
"""

VERSION = "5.0.0"
AUTHOR  = "Enterprise Security Team"
YEAR    = "2026"

# Severity colours
SEV_COLOR = {
    'critical': 'bold red',
    'high':     'bold orange1',
    'medium':   'bold yellow',
    'low':      'bold green',
    'info':     'bold cyan',
    'none':     'dim',
}

# OWASP Top 10 2021 mapping
OWASP_MAP = {
    'sql injection':                ('A03:2021', 'Injection'),
    'sqli':                         ('A03:2021', 'Injection'),
    'xss':                          ('A03:2021', 'Injection'),
    'cross-site scripting':         ('A03:2021', 'Injection'),
    'command injection':            ('A03:2021', 'Injection'),
    'ssti':                         ('A03:2021', 'Injection'),
    'xxe':                          ('A05:2021', 'Security Misconfiguration'),
    'idor':                         ('A01:2021', 'Broken Access Control'),
    'lfi':                          ('A01:2021', 'Broken Access Control'),
    'path traversal':               ('A01:2021', 'Broken Access Control'),
    'ssrf':                         ('A10:2021', 'Server-Side Request Forgery'),
    'authentication bypass':        ('A07:2021', 'Identification & Auth Failures'),
    'default credentials':          ('A07:2021', 'Identification & Auth Failures'),
    'open redirect':                ('A01:2021', 'Broken Access Control'),
    'csrf':                         ('A01:2021', 'Broken Access Control'),
    'cors':                         ('A05:2021', 'Security Misconfiguration'),
    'exposure':                     ('A02:2021', 'Cryptographic Failures'),
    'secrets':                      ('A02:2021', 'Cryptographic Failures'),
    'ssl':                          ('A02:2021', 'Cryptographic Failures'),
    'outdated':                     ('A06:2021', 'Vulnerable Components'),
    'cve':                          ('A06:2021', 'Vulnerable Components'),
}

# Default credential pairs to test
DEFAULT_CREDS = [
    ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
    ('admin', 'admin123'), ('administrator', 'administrator'),
    ('root', 'root'), ('root', 'toor'), ('root', ''),
    ('test', 'test'), ('guest', 'guest'), ('user', 'user'),
    ('admin', ''), ('', 'admin'), ('admin', 'pass'),
    ('demo', 'demo'), ('info', 'info'), ('manager', 'manager'),
    ('support', 'support'), ('operator', 'operator'),
    ('admin', 'admin@123'), ('admin', 'P@ssw0rd'),
]

# Common API endpoints to probe
API_ENDPOINTS = [
    '/api', '/api/v1', '/api/v2', '/api/v3', '/api/v4',
    '/rest', '/rest/v1', '/graphql', '/gql',
    '/swagger.json', '/swagger.yaml', '/openapi.json', '/openapi.yaml',
    '/api-docs', '/api/docs', '/v1/api-docs',
    '/.well-known/openid-configuration',
    '/api/users', '/api/admin', '/api/config',
    '/api/health', '/health', '/healthz', '/ping',
    '/actuator', '/actuator/env', '/actuator/health',
    '/actuator/mappings', '/actuator/beans',
    '/metrics', '/debug', '/debug/pprof',
    '/jsonrpc', '/xmlrpc', '/soap', '/wsdl',
    '/__debug__', '/_debug', '/console',
]

# Interesting paths for content discovery
JUICY_PATHS = [
    '/.git/config', '/.git/HEAD', '/.git/COMMIT_EDITMSG',
    '/.svn/entries', '/.hg/hgrc',
    '/.env', '/.env.local', '/.env.backup', '/.env.bak',
    '/config.php', '/wp-config.php', '/config.yml', '/config.yaml',
    '/database.yml', '/db.php', '/settings.py', '/settings.php',
    '/admin', '/admin/', '/administrator', '/phpmyadmin',
    '/backup', '/backup.zip', '/backup.tar.gz', '/backup.sql',
    '/robots.txt', '/sitemap.xml', '/.htaccess', '/.htpasswd',
    '/web.config', '/crossdomain.xml', '/clientaccesspolicy.xml',
    '/server-status', '/server-info', '/nginx_status',
    '/phpinfo.php', '/info.php', '/test.php',
    '/uploads', '/files', '/assets', '/static', '/media',
    '/logs', '/log', '/error.log', '/access.log',
    '/api/swagger-ui.html', '/swagger-ui', '/redoc',
    '/jenkins', '/jenkins/script', '/hudson',
    '/wp-json/wp/v2/users',
]

# Secret patterns for OSINT/JS analysis
SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,64})', 'API Key'),
    (r'(?i)(secret[_-]?key|secret)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,64})', 'Secret Key'),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\'&]{6,})', 'Password'),
    (r'(?i)(access[_-]?token|auth[_-]?token|bearer)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{16,})', 'Token'),
    (r'(?i)aws[_-]?(access[_-]?key[_-]?id)\s*[=:]\s*["\']?(AKIA[A-Z0-9]{16})', 'AWS Key'),
    (r'(?i)aws[_-]?(secret[_-]?access[_-]?key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})', 'AWS Secret'),
    (r'(?i)(private[_-]?key|rsa[_-]?key)\s*[=:]\s*["\']?(-----BEGIN)', 'Private Key'),
    (r'(?i)(client[_-]?secret|app[_-]?secret)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,64})', 'Client Secret'),
    (r'(?i)(database[_-]?url|db[_-]?url|connection[_-]?string)\s*[=:]\s*["\']?([^\s"\']+)', 'DB Connection'),
    (r'(?i)([A-Za-z0-9]{24}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27})', 'Discord Token'),
    (r'ghp_[A-Za-z0-9]{36}', 'GitHub Personal Token'),
    (r'gho_[A-Za-z0-9]{36}', 'GitHub OAuth Token'),
    (r'(?i)(slack[_-]?token|xoxb-[0-9\-A-Za-z]+)', 'Slack Token'),
    (r'ya29\.[0-9A-Za-z_\-]+', 'Google OAuth Token'),
    (r'(?i)(sendgrid[_-]?api[_-]?key)\s*[=:]\s*["\']?(SG\.[A-Za-z0-9_\-\.]+)', 'SendGrid Key'),
    (r'(?i)(stripe[_-]?(sk|pk)_?(live|test)_[A-Za-z0-9]{24})', 'Stripe Key'),
]

# ═══════════════════════════════════════════════════════════════════════════
# ASYNC EXECUTION ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class AsyncRunner:
    """
    Thread-safe async subprocess execution engine.
    Handles semaphore throttling, proxy injection, timeout, and output parsing.
    """

    def __init__(self, semaphore: int = 10):
        self._sem = asyncio.Semaphore(semaphore)
        self._lock = threading.Lock()
        self.stats: Dict[str, int] = {
            'commands_run': 0,
            'commands_ok':  0,
            'commands_err': 0,
            'commands_timeout': 0,
        }

    def _inc(self, key: str, n: int = 1):
        with self._lock:
            self.stats[key] = self.stats.get(key, 0) + n

    async def run(
        self,
        cmd: str,
        timeout: int = 300,
        proxy: Optional[str] = None,
        use_proxy_env: bool = False,
        tag: str = '',
        cwd: Optional[str] = None,
    ) -> Tuple[int, str, str]:
        """
        Execute a shell command asynchronously.
        Returns (returncode, stdout, stderr).
        """
        async with self._sem:
            self._inc('commands_run')

            env = os.environ.copy()

            # Inject proxy environment
            if proxy and use_proxy_env:
                env.update({
                    'http_proxy':  proxy, 'HTTP_PROXY':  proxy,
                    'https_proxy': proxy, 'HTTPS_PROXY': proxy,
                    'ALL_PROXY':   proxy,
                })

            # Inject proxy into curl commands
            if proxy and 'curl ' in cmd and use_proxy_env:
                cmd = cmd.replace('curl ', f'curl -x {proxy} -k ', 1)

            try:
                proc = await asyncio.wait_for(
                    asyncio.create_subprocess_shell(
                        cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        env=env,
                        cwd=cwd,
                    ),
                    timeout=timeout,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
                rc = proc.returncode or 0
                out = stdout.decode('utf-8', errors='replace')
                err = stderr.decode('utf-8', errors='replace')
                if rc == 0:
                    self._inc('commands_ok')
                else:
                    self._inc('commands_err')
                return rc, out, err

            except asyncio.TimeoutError:
                self._inc('commands_timeout')
                try:
                    proc.kill()
                except Exception:
                    pass
                return -1, '', f'[TIMEOUT] {tag or cmd[:80]}'

            except Exception as exc:
                self._inc('commands_err')
                return -2, '', f'[ERROR] {exc}'

    async def run_json(self, cmd: str, **kwargs) -> Optional[Any]:
        """Run command and parse JSON output."""
        rc, out, _ = await self.run(cmd, **kwargs)
        if rc == 0 and out.strip():
            try:
                return json.loads(out)
            except json.JSONDecodeError:
                # Try to find JSON in output
                match = re.search(r'(\{.*\}|\[.*\])', out, re.DOTALL)
                if match:
                    try:
                        return json.loads(match.group(1))
                    except Exception:
                        pass
        return None

    async def run_lines(self, cmd: str, **kwargs) -> List[str]:
        """Run command and return non-empty lines."""
        rc, out, _ = await self.run(cmd, **kwargs)
        return [ln.strip() for ln in out.splitlines() if ln.strip()]


# ═══════════════════════════════════════════════════════════════════════════
# RESULTS STORE
# ═══════════════════════════════════════════════════════════════════════════

class ResultsStore:
    """
    Thread-safe results aggregator.
    All phase findings are stored here for report generation.
    """

    def __init__(self, target: str, domain: str, output_dir: Path):
        self._lock = threading.Lock()
        self.target = target
        self.domain = domain
        self.output_dir = output_dir
        self.scan_time = datetime.now().isoformat()
        self.scan_start = time.time()

        self.data: Dict[str, Any] = {
            'target': target,
            'domain': domain,
            'scan_time': self.scan_time,
            # Phase 1 – Recon
            'whois': {},
            'dns_records': {},
            'subdomains': [],
            'live_hosts': [],
            'subdomain_takeover': [],
            'screenshots': [],
            # Phase 2 – Ports
            'open_ports': [],
            'services': [],
            'nmap_raw': '',
            # Phase 3 – Web
            'web_technologies': [],
            'waf_info': {},
            'headers': {},
            'ssl_findings': [],
            'cors_issues': [],
            'cookie_issues': [],
            'cms_type': None,
            'cms_findings': [],
            # Phase 4 – API
            'api_endpoints': [],
            'graphql_findings': [],
            'js_secrets': [],
            'wayback_urls': [],
            'crawled_urls': [],
            # Phase 5 – Content
            'directories': [],
            'git_exposure': [],
            'exposed_files': [],
            'backup_files': [],
            # Phase 6 – Nuclei
            'nuclei_findings': [],
            # Phase 7 – Injections
            'xss_results': [],
            'sqli_results': [],
            'command_injection': [],
            'ssrf_results': [],
            'lfi_rfi_results': [],
            'ssti_results': [],
            'xxe_results': [],
            'open_redirects': [],
            'idor_results': [],
            # Phase 8 – OSINT
            'emails': [],
            'leaked_credentials': [],
            's3_buckets': [],
            'github_secrets': [],
            'breach_data': [],
            # Phase 9 – Exploits
            'searchsploit_results': [],
            'metasploit_modules': [],
            'cve_matches': [],
            # Phase 10 – Advanced
            'race_conditions': [],
            'auth_bypass': [],
            'default_creds': [],
            'vulnerabilities': [],  # unified vuln list
        }

        self.stats: Dict[str, int] = {
            'subdomains':       0,
            'live_hosts':       0,
            'open_ports':       0,
            'vulnerabilities':  0,
            'critical':         0,
            'high':             0,
            'medium':           0,
            'low':              0,
            'info':             0,
            'secrets':          0,
            'exploits':         0,
        }

    # ── write helpers ────────────────────────────────────────────────────

    def add(self, key: str, items):
        """Append item(s) to a list key."""
        with self._lock:
            if not isinstance(self.data.get(key), list):
                self.data[key] = []
            if isinstance(items, list):
                self.data[key].extend(items)
            else:
                self.data[key].append(items)

    def set(self, key: str, value: Any):
        """Set a scalar or dict key."""
        with self._lock:
            self.data[key] = value

    def inc(self, key: str, n: int = 1):
        """Increment a stats counter."""
        with self._lock:
            self.stats[key] = self.stats.get(key, 0) + n

    def add_vuln(self, vuln: Dict[str, Any]):
        """
        Add a unified vulnerability finding with deduplication.
        Also updates severity stats.
        """
        with self._lock:
            # Dedup by name+url
            sig = hashlib.md5(
                f"{vuln.get('name','')}{vuln.get('url','')}".encode()
            ).hexdigest()
            vuln['_sig'] = sig

            existing = {v.get('_sig') for v in self.data['vulnerabilities']}
            if sig not in existing:
                self.data['vulnerabilities'].append(vuln)
                sev = str(vuln.get('severity', 'info')).lower()
                self.stats['vulnerabilities'] += 1
                if sev in self.stats:
                    self.stats[sev] += 1

    # ── read helpers ─────────────────────────────────────────────────────

    def get(self, key: str, default=None):
        with self._lock:
            return self.data.get(key, default)

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            d = dict(self.data)
            d['scan_duration'] = time.time() - self.scan_start
            return d

    def save_json(self):
        """Persist results to disk as JSON."""
        path = self.output_dir / f'{self.domain}_results.json'
        snap = self.snapshot()
        path.write_text(json.dumps(snap, indent=2, default=str), encoding='utf-8')
        return path

    # ── vuln accessors ───────────────────────────────────────────────────

    def vulns_by_severity(self) -> Dict[str, List]:
        """Return vulnerabilities grouped by severity."""
        groups: Dict[str, List] = {s: [] for s in ['critical','high','medium','low','info']}
        for v in self.data.get('vulnerabilities', []):
            sev = str(v.get('severity','info')).lower()
            groups.setdefault(sev, []).append(v)
        return groups

    def top_vulns(self, n: int = 10) -> List[Dict]:
        """Return top-n vulnerabilities sorted by CVSS."""
        vulns = list(self.data.get('vulnerabilities', []))
        vulns.sort(key=lambda v: float(v.get('cvss_score', 0)), reverse=True)
        return vulns[:n]


# ═══════════════════════════════════════════════════════════════════════════
# DISPLAY HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def print_phase_header(phase_num: int, title: str, tools: List[str]):
    """Print a phase start banner."""
    tool_str = ' • '.join(tools)
    console.print(f'\n[bold cyan]{"═"*70}[/bold cyan]')
    console.print(
        f'[bold cyan] PHASE {phase_num}[/bold cyan] [bold white]{title}[/bold white]'
    )
    console.print(f'[dim] Tools: {tool_str}[/dim]')
    console.print(f'[bold cyan]{"═"*70}[/bold cyan]')


def print_finding(severity: str, name: str, url: str = '', detail: str = ''):
    """Print a coloured finding to console."""
    col = SEV_COLOR.get(severity.lower(), 'white')
    sev_tag = f'[{col}][{severity.upper()}][/{col}]'
    url_part = f' [dim]{escape(url[:80])}[/dim]' if url else ''
    det_part = f'\n         [dim]{escape(detail[:120])}[/dim]' if detail else ''
    console.print(f'  {sev_tag} {escape(name)}{url_part}{det_part}')


def print_ok(msg: str):
    console.print(f'  [green]✓[/green] {msg}')


def print_warn(msg: str):
    console.print(f'  [yellow]⚠[/yellow] {msg}')


def print_err(msg: str):
    console.print(f'  [red]✗[/red] {msg}')


def print_info(msg: str):
    console.print(f'  [cyan]ℹ[/cyan] {msg}')


def print_tool(tool: str, msg: str):
    console.print(f'  [bold magenta][{tool}][/bold magenta] {msg}')


def severity_bar(counts: Dict[str, int]) -> str:
    parts = []
    for sev, col in [('critical','red'),('high','orange1'),('medium','yellow'),('low','green'),('info','cyan')]:
        n = counts.get(sev, 0)
        if n:
            parts.append(f'[bold {col}]{n} {sev.upper()}[/bold {col}]')
    return '  '.join(parts) if parts else '[dim]No findings[/dim]'


# ═══════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def extract_domain(target: str) -> str:
    """Extract clean domain from URL or hostname."""
    parsed = urlparse(target if '://' in target else f'https://{target}')
    host = parsed.hostname or parsed.path.split('/')[0]
    return host.lstrip('www.').lower()


def normalise_url(target: str) -> str:
    """Ensure target has a scheme."""
    if not target.startswith(('http://', 'https://')):
        return f'https://{target}'
    return target


def is_valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def tool_exists(name: str) -> bool:
    """Check if a tool binary is on PATH."""
    import shutil
    return shutil.which(name) is not None


def parse_nmap_xml(xml_path: str) -> List[Dict[str, Any]]:
    """Parse nmap XML output into structured port list."""
    ports = []
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for host in root.findall('.//host'):
            addr_el = host.find('address[@addrtype="ipv4"]')
            if addr_el is None:
                addr_el = host.find('address')
            ip = addr_el.get('addr', '') if addr_el is not None else ''
            for port_el in host.findall('.//port'):
                state_el = port_el.find('state')
                if state_el is None or state_el.get('state') != 'open':
                    continue
                service_el = port_el.find('service')
                svc_name    = service_el.get('name', '') if service_el is not None else ''
                svc_product = service_el.get('product', '') if service_el is not None else ''
                svc_version = service_el.get('version', '') if service_el is not None else ''
                port_num    = int(port_el.get('portid', 0))
                protocol    = port_el.get('protocol', 'tcp')
                ports.append({
                    'ip':       ip,
                    'port':     port_num,
                    'protocol': protocol,
                    'service':  svc_name,
                    'product':  svc_product,
                    'version':  svc_version,
                    'banner':   f'{svc_product} {svc_version}'.strip(),
                })
    except Exception as exc:
        console.print(f'[dim]nmap XML parse: {exc}[/dim]')
    return ports


def parse_nuclei_output(output: str) -> List[Dict[str, Any]]:
    """Parse nuclei JSON-lines output."""
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            # Try to extract structured data from coloured output
            m = re.search(
                r'\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)',
                line
            )
            if m:
                item = {
                    'templateID': m.group(1),
                    'info':       {'name': m.group(1), 'severity': m.group(2)},
                    'type':       m.group(3),
                    'matched-at': m.group(4),
                }
            else:
                continue

        info   = item.get('info', {})
        sev    = str(info.get('severity', 'info')).lower()
        name   = info.get('name', item.get('templateID', 'Unknown'))
        url    = item.get('matched-at', item.get('host', ''))
        cve    = item.get('info', {}).get('classification', {}).get('cve-id', [])
        cvss   = item.get('info', {}).get('classification', {}).get('cvss-score', None)

        findings.append({
            'name':         name,
            'severity':     sev,
            'url':          url,
            'template_id':  item.get('templateID', ''),
            'cve':          cve if isinstance(cve, list) else [cve] if cve else [],
            'cvss_score':   float(cvss) if cvss else None,
            'description':  info.get('description', ''),
            'tags':         info.get('tags', []),
            'matcher':      item.get('matcher-name', ''),
            'extracted':    item.get('extracted-results', []),
        })
    return findings


def scan_js_secrets(content: str, source: str = '') -> List[Dict[str, Any]]:
    """Scan JavaScript / HTML content for exposed secrets."""
    secrets = []
    for pattern, label in SECRET_PATTERNS:
        for m in re.finditer(pattern, content):
            val = m.group(0)[:100]
            if len(val) > 4:
                secrets.append({
                    'type':   label,
                    'value':  val,
                    'source': source,
                    'line':   content[:m.start()].count('\n') + 1,
                })
    return secrets


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 1 — RECONNAISSANCE
# ═══════════════════════════════════════════════════════════════════════════

class Phase1Recon:
    """
    Phase 1: Full-spectrum reconnaissance.
    Tools: whois, dig, subfinder, assetfinder, amass, findomain,
           chaos, httpx, subjack, subover, gowitness/aquatone
    """

    def __init__(
        self,
        runner: AsyncRunner,
        store:  ResultsStore,
        proxy:  Optional[str] = None,
        threads: int = 20,
    ):
        self.runner  = runner
        self.store   = store
        self.proxy   = proxy
        self.threads = threads
        self.domain  = store.domain
        self.target  = store.target
        self.outdir  = store.output_dir

    async def run(self):
        print_phase_header(
            1, 'RECONNAISSANCE',
            ['whois', 'dig', 'subfinder', 'assetfinder', 'amass', 'findomain',
             'httpx', 'subjack', 'subover', 'gowitness', 'aquatone']
        )

        await asyncio.gather(
            self._whois(),
            self._dns_enum(),
        )

        await asyncio.gather(
            self._subfinder(),
            self._assetfinder(),
            self._amass(),
            self._findomain(),
            self._chaos(),
        )

        await self._dedupe_and_save_subdomains()
        await self._http_probe()
        await asyncio.gather(
            self._subdomain_takeover_subjack(),
            self._subdomain_takeover_subover(),
        )
        await self._screenshots()
        self._print_summary()

    # ── whois ────────────────────────────────────────────────────────────

    async def _whois(self):
        print_tool('whois', f'Querying {self.domain}')
        rc, out, _ = await self.runner.run(f'whois {self.domain}', timeout=30, tag='whois')
        if out:
            info: Dict[str, str] = {}
            for line in out.splitlines():
                for key in ['Registrar', 'Creation Date', 'Expiry Date',
                            'Registrant', 'Name Server', 'DNSSEC']:
                    if line.strip().startswith(key + ':'):
                        info[key] = line.split(':', 1)[-1].strip()
            self.store.set('whois', info)
            print_ok(f'WHOIS: {len(info)} fields')
        else:
            print_warn('WHOIS: no response')

    # ── DNS enumeration ───────────────────────────────────────────────────

    async def _dns_enum(self):
        print_tool('dig', f'DNS enumeration for {self.domain}')
        records: Dict[str, List[str]] = {}

        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'CAA']:
            rc, out, _ = await self.runner.run(
                f'dig +short {rtype} {self.domain}', timeout=15, tag=f'dig-{rtype}'
            )
            vals = [l.strip() for l in out.splitlines() if l.strip()]
            if vals:
                records[rtype] = vals

        # Zone transfer attempt
        ns_list = records.get('NS', [])
        for ns in ns_list[:2]:
            rc, out, _ = await self.runner.run(
                f'dig axfr {self.domain} @{ns}', timeout=20, tag='axfr'
            )
            if out and 'Transfer failed' not in out and len(out) > 100:
                records['AXFR'] = [f'Zone transfer succeeded from {ns}!']
                self.store.add_vuln({
                    'name':        'DNS Zone Transfer',
                    'severity':    'high',
                    'url':         self.domain,
                    'description': f'DNS zone transfer allowed from {ns}',
                    'tool':        'dig',
                })
                print_finding('high', 'DNS Zone Transfer possible!', self.domain)

        self.store.set('dns_records', records)
        print_ok(f'DNS: {sum(len(v) for v in records.values())} records across {len(records)} types')

    # ── subdomain enumeration ─────────────────────────────────────────────

    async def _subfinder(self):
        if not tool_exists('subfinder'):
            return
        print_tool('subfinder', f'Passive subdomain discovery: {self.domain}')
        rc, out, _ = await self.runner.run(
            f'subfinder -d {self.domain} -silent -all -t {self.threads}',
            timeout=240, tag='subfinder'
        )
        subs = [l.strip() for l in out.splitlines() if l.strip() and self.domain in l]
        if subs:
            self.store.add('subdomains', subs)
            print_ok(f'subfinder: {len(subs)} subdomains')

    async def _assetfinder(self):
        if not tool_exists('assetfinder'):
            return
        print_tool('assetfinder', f'Asset discovery: {self.domain}')
        rc, out, _ = await self.runner.run(
            f'assetfinder --subs-only {self.domain}',
            timeout=120, tag='assetfinder'
        )
        subs = [l.strip() for l in out.splitlines() if l.strip() and self.domain in l]
        if subs:
            self.store.add('subdomains', subs)
            print_ok(f'assetfinder: {len(subs)} assets')

    async def _amass(self):
        if not tool_exists('amass'):
            return
        print_tool('amass', f'In-depth DNS enumeration: {self.domain}')
        outfile = self.outdir / 'amass.txt'
        rc, out, _ = await self.runner.run(
            f'amass enum -passive -d {self.domain} -o {outfile} -timeout 5',
            timeout=360, tag='amass'
        )
        if outfile.exists():
            subs = [l.strip() for l in outfile.read_text().splitlines() if l.strip()]
            if subs:
                self.store.add('subdomains', subs)
                print_ok(f'amass: {len(subs)} subdomains')

    async def _findomain(self):
        if not tool_exists('findomain'):
            return
        print_tool('findomain', f'Fast subdomain enum: {self.domain}')
        outfile = self.outdir / 'findomain.txt'
        rc, out, _ = await self.runner.run(
            f'findomain -t {self.domain} -o -u {outfile}',
            timeout=120, tag='findomain'
        )
        if outfile.exists():
            subs = [l.strip() for l in outfile.read_text().splitlines() if l.strip()]
            if subs:
                self.store.add('subdomains', subs)
                print_ok(f'findomain: {len(subs)} subdomains')

    async def _chaos(self):
        if not tool_exists('chaos'):
            return
        print_tool('chaos', f'ProjectDiscovery dataset: {self.domain}')
        rc, out, _ = await self.runner.run(
            f'chaos -d {self.domain} -silent', timeout=60, tag='chaos'
        )
        subs = [l.strip() for l in out.splitlines() if l.strip() and self.domain in l]
        if subs:
            self.store.add('subdomains', subs)
            print_ok(f'chaos: {len(subs)} subdomains')

    async def _dedupe_and_save_subdomains(self):
        """Deduplicate all collected subdomains and save to file."""
        subs: List[str] = self.store.get('subdomains', [])
        unique = sorted(set(s.lower().strip() for s in subs if s.strip()))
        self.store.set('subdomains', unique)
        self.store.inc('subdomains', len(unique))

        outfile = self.outdir / 'subdomains.txt'
        outfile.write_text('\n'.join(unique), encoding='utf-8')
        console.print(f'\n  [bold green]Total unique subdomains: {len(unique)}[/bold green]')

    # ── HTTP probe ────────────────────────────────────────────────────────

    async def _http_probe(self):
        subs: List[str] = self.store.get('subdomains', [])
        if not subs:
            subs = [self.domain]

        sub_file = self.outdir / 'subdomains.txt'
        live_file = self.outdir / 'live.txt'

        if not tool_exists('httpx'):
            print_warn('httpx not found – using fallback')
            self.store.set('live_hosts', [self.target])
            return

        print_tool('httpx', f'Probing {len(subs)} hosts for live HTTP services')

        cmd = (
            f'httpx -l {sub_file} -silent -threads {self.threads} '
            f'-timeout 10 -status-code -title -tech-detect -json '
            f'-o {live_file}'
        )
        if self.proxy:
            cmd += f' -http-proxy {self.proxy}'

        await self.runner.run(cmd, timeout=600, tag='httpx')

        live_hosts = []
        if live_file.exists():
            for line in live_file.read_text().splitlines():
                try:
                    item = json.loads(line)
                    live_hosts.append({
                        'url':          item.get('url', ''),
                        'status':       item.get('status-code', 0),
                        'title':        item.get('title', ''),
                        'technologies': item.get('tech', []),
                        'content_len':  item.get('content-length', 0),
                        'ip':           item.get('host', ''),
                        'cdn':          item.get('cdn', False),
                    })
                except (json.JSONDecodeError, KeyError):
                    url = line.strip()
                    if url:
                        live_hosts.append({'url': url, 'status': 200})

        self.store.set('live_hosts', live_hosts)
        self.store.inc('live_hosts', len(live_hosts))
        print_ok(f'httpx: {len(live_hosts)} live hosts')

    # ── subdomain takeover ────────────────────────────────────────────────

    async def _subdomain_takeover_subjack(self):
        if not tool_exists('subjack'):
            return
        sub_file = self.outdir / 'subdomains.txt'
        if not sub_file.exists():
            return

        print_tool('subjack', 'Subdomain takeover detection')
        out_file = self.outdir / 'takeover_subjack.txt'
        rc, out, _ = await self.runner.run(
            f'subjack -w {sub_file} -t {self.threads} -timeout 30 '
            f'-o {out_file} -ssl -c /root/go/pkg/mod/github.com/haccer/subjack*/fingerprints.json 2>/dev/null || '
            f'subjack -w {sub_file} -t {self.threads} -timeout 30 -o {out_file} -ssl',
            timeout=300, tag='subjack'
        )
        if out_file.exists():
            findings = [l.strip() for l in out_file.read_text().splitlines() if l.strip()]
            for f in findings:
                self.store.add('subdomain_takeover', f)
                self.store.add_vuln({
                    'name':     'Subdomain Takeover',
                    'severity': 'high',
                    'url':      f,
                    'tool':     'subjack',
                })
                print_finding('high', 'Subdomain Takeover!', f)

    async def _subdomain_takeover_subover(self):
        if not tool_exists('SubOver'):
            return
        sub_file = self.outdir / 'subdomains.txt'
        if not sub_file.exists():
            return

        print_tool('subover', 'Additional takeover check')
        rc, out, _ = await self.runner.run(
            f'SubOver -l {sub_file} -t {self.threads} -timeout 30 -v',
            timeout=300, tag='subover'
        )
        for line in out.splitlines():
            if 'Vulnerable' in line or 'VULNERABLE' in line:
                self.store.add('subdomain_takeover', line.strip())
                print_finding('high', line.strip()[:80])

    # ── screenshots ───────────────────────────────────────────────────────

    async def _screenshots(self):
        live_hosts  = self.store.get('live_hosts', [])
        if not live_hosts:
            return

        screenshots_dir = self.outdir / 'screenshots'
        screenshots_dir.mkdir(exist_ok=True)

        if tool_exists('gowitness'):
            print_tool('gowitness', f'Screenshots of {len(live_hosts)} hosts')
            live_file = self.outdir / 'live_urls.txt'
            urls = [h.get('url', h) if isinstance(h, dict) else h for h in live_hosts]
            live_file.write_text('\n'.join(urls), encoding='utf-8')

            rc, out, _ = await self.runner.run(
                f'gowitness file -f {live_file} --disable-db '
                f'--screenshot-path {screenshots_dir} --timeout 10',
                timeout=600, tag='gowitness'
            )
            shots = list(screenshots_dir.glob('*.png'))
            self.store.set('screenshots', [str(s) for s in shots])
            print_ok(f'gowitness: {len(shots)} screenshots')

        elif tool_exists('aquatone'):
            print_tool('aquatone', 'Visual reconnaissance')
            live_file = self.outdir / 'live_urls.txt'
            urls = [h.get('url', h) if isinstance(h, dict) else h for h in live_hosts]
            live_file.write_text('\n'.join(urls), encoding='utf-8')
            rc, out, _ = await self.runner.run(
                f'cat {live_file} | aquatone -out {screenshots_dir} -threads {self.threads} -timeout 3000',
                timeout=600, tag='aquatone'
            )

    def _print_summary(self):
        subs  = len(self.store.get('subdomains', []))
        live  = len(self.store.get('live_hosts', []))
        taken = len(self.store.get('subdomain_takeover', []))
        shots = len(self.store.get('screenshots', []))

        tbl = Table(title='Phase 1 Summary', box=box.ROUNDED, border_style='cyan')
        tbl.add_column('Metric', style='bold cyan')
        tbl.add_column('Count', style='bold white', justify='right')
        tbl.add_row('Subdomains Discovered', str(subs))
        tbl.add_row('Live Hosts', str(live))
        tbl.add_row('Takeover Candidates', f'[bold red]{taken}[/bold red]' if taken else '0')
        tbl.add_row('Screenshots', str(shots))
        console.print(tbl)


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 2 — PORT SCANNING
# ═══════════════════════════════════════════════════════════════════════════

class Phase2Ports:
    """
    Phase 2: Multi-tool port scanning with service detection.
    Tools: masscan (fast sweep), nmap (deep scan + scripts), rustscan
    """

    def __init__(
        self,
        runner: AsyncRunner,
        store:  ResultsStore,
        proxy:  Optional[str] = None,
        threads: int = 10,
    ):
        self.runner  = runner
        self.store   = store
        self.proxy   = proxy
        self.threads = threads
        self.domain  = store.domain
        self.target  = store.target
        self.outdir  = store.output_dir

    async def run(self):
        print_phase_header(
            2, 'PORT SCANNING & SERVICE DETECTION',
            ['masscan', 'nmap', 'rustscan']
        )

        # Resolve target IP(s)
        targets = await self._resolve_targets()

        open_ports: Set[int] = set()

        # Fast discovery with masscan or rustscan
        if tool_exists('rustscan'):
            ports = await self._rustscan(targets)
            open_ports.update(ports)
        elif tool_exists('masscan'):
            ports = await self._masscan(targets)
            open_ports.update(ports)

        # Deep scan with nmap
        await self._nmap_deep(targets, sorted(open_ports))
        self._print_summary()

    async def _resolve_targets(self) -> List[str]:
        """Resolve domain to IPs, include in-scope IPs."""
        targets = []
        parsed = urlparse(self.target if '://' in self.target else f'https://{self.target}')
        host = parsed.hostname or self.domain
        try:
            ip = socket.gethostbyname(host)
            targets.append(ip)
            print_ok(f'Resolved {host} → {ip}')
        except socket.gaierror:
            targets.append(host)
        return targets

    async def _rustscan(self, targets: List[str]) -> List[int]:
        """Fast initial scan with RustScan."""
        print_tool('rustscan', f'Fast port scan on {len(targets)} target(s)')
        ports_found = []
        for target in targets:
            rc, out, _ = await self.runner.run(
                f'rustscan -a {target} --ulimit 5000 -b 2500 --timeout 2000 '
                f'-- -sV --script-timeout 30s 2>/dev/null | grep "^[0-9]"',
                timeout=300, tag='rustscan'
            )
            for line in out.splitlines():
                m = re.match(r'(\d+)/tcp', line)
                if m:
                    ports_found.append(int(m.group(1)))

        print_ok(f'rustscan: {len(ports_found)} open ports discovered')
        return ports_found

    async def _masscan(self, targets: List[str]) -> List[int]:
        """Ultra-fast mass scanning."""
        print_tool('masscan', 'Ultra-fast port sweep (requires root)')
        outfile = self.outdir / 'masscan.json'
        ports_found = []
        for target in targets[:1]:  # masscan on primary target
            rc, out, _ = await self.runner.run(
                f'sudo masscan {target} -p1-65535 --rate=10000 '
                f'--output-format json --output-filename {outfile} 2>/dev/null',
                timeout=600, tag='masscan'
            )
            if outfile.exists():
                try:
                    data = json.loads(outfile.read_text())
                    for entry in data:
                        for port_info in entry.get('ports', []):
                            ports_found.append(int(port_info.get('port', 0)))
                except Exception:
                    pass

        print_ok(f'masscan: {len(ports_found)} open ports')
        return ports_found

    async def _nmap_deep(self, targets: List[str], open_ports: List[int]):
        """Comprehensive nmap scan with version + script detection."""
        print_tool('nmap', 'Deep service detection & vulnerability scripts')

        if not tool_exists('nmap'):
            print_warn('nmap not found')
            return

        # Build port list
        if open_ports:
            port_str = ','.join(str(p) for p in open_ports[:200])
        else:
            port_str = '21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,9200,27017'

        outfile_xml  = self.outdir / 'nmap.xml'
        outfile_gnmap = self.outdir / 'nmap.gnmap'

        for target in targets[:3]:
            print_info(f'nmap deep scan on {target} [{len(open_ports)} ports]')
            cmd = (
                f'nmap -sV -sC -O --version-intensity 7 '
                f'-p {port_str} '
                f'--script vuln,exploit,auth,default,discovery,safe '
                f'--script-timeout 60s '
                f'-oX {outfile_xml} -oG {outfile_gnmap} '
                f'--min-rate 500 -T4 {target} 2>/dev/null'
            )
            rc, out, _ = await self.runner.run(cmd, timeout=900, tag='nmap')
            self.store.set('nmap_raw', out)

            # Parse XML results
            if outfile_xml.exists():
                port_data = parse_nmap_xml(str(outfile_xml))
                self.store.set('open_ports', port_data)
                self.store.inc('open_ports', len(port_data))
                self._process_nmap_results(port_data)

    def _process_nmap_results(self, ports: List[Dict[str, Any]]):
        """Process nmap results and flag risky services."""
        risky_services = {
            21:    ('FTP',        'medium',  'FTP allows unencrypted file transfer'),
            23:    ('Telnet',     'high',    'Telnet transmits data in plaintext'),
            25:    ('SMTP',       'medium',  'SMTP open relay possible'),
            111:   ('RPC',        'medium',  'Remote Procedure Call exposed'),
            135:   ('MS-RPC',     'medium',  'Microsoft RPC exposed'),
            139:   ('NetBIOS',    'medium',  'NetBIOS session service exposed'),
            445:   ('SMB',        'high',    'SMB could be vulnerable to EternalBlue'),
            1433:  ('MSSQL',      'high',    'Microsoft SQL Server exposed to internet'),
            1521:  ('Oracle',     'high',    'Oracle DB exposed to internet'),
            3306:  ('MySQL',      'high',    'MySQL exposed to internet'),
            3389:  ('RDP',        'high',    'RDP exposed – brute-force/BlueKeep risk'),
            5432:  ('PostgreSQL', 'high',    'PostgreSQL exposed to internet'),
            5900:  ('VNC',        'high',    'VNC remote desktop exposed'),
            6379:  ('Redis',      'critical','Redis without auth exposed to internet'),
            9200:  ('Elasticsearch','critical','Elasticsearch potentially unauthenticated'),
            27017: ('MongoDB',    'critical','MongoDB potentially unauthenticated'),
            2375:  ('Docker API', 'critical','Docker API exposed without TLS'),
            2379:  ('etcd',       'critical','etcd cluster API exposed'),
        }

        services = []
        for p in ports:
            port = p['port']
            svc_name = p.get('service', '')
            version  = p.get('version', '')
            product  = p.get('product', '')

            entry = {**p, 'full_service': f'{product} {version}'.strip()}
            services.append(entry)

            if port in risky_services:
                label, sev, desc = risky_services[port]
                self.store.add_vuln({
                    'name':        f'Exposed {label} Service (port {port})',
                    'severity':    sev,
                    'url':         f'{p["ip"]}:{port}',
                    'description': f'{desc}. Version: {product} {version}',
                    'tool':        'nmap',
                    'port':        port,
                })
                print_finding(sev, f'Exposed {label}', f'{p["ip"]}:{port}',
                              f'{product} {version}')

        self.store.set('services', services)

    def _print_summary(self):
        ports = self.store.get('open_ports', [])
        svcs  = {p.get('service','?') for p in ports}

        tbl = Table(title='Phase 2 Summary', box=box.ROUNDED, border_style='cyan')
        tbl.add_column('Port', style='cyan', justify='right')
        tbl.add_column('Protocol')
        tbl.add_column('Service', style='bold white')
        tbl.add_column('Version', style='dim')

        for p in sorted(ports, key=lambda x: x.get('port', 0))[:30]:
            tbl.add_row(
                str(p.get('port', '')),
                p.get('protocol', 'tcp'),
                p.get('service', ''),
                p.get('banner', '')[:50],
            )

        if ports:
            console.print(tbl)
        console.print(f'\n  [bold green]Total open ports: {len(ports)}[/bold green]')


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 3 — WEB ANALYSIS & CMS DETECTION
# ═══════════════════════════════════════════════════════════════════════════

class Phase3Web:
    """
    Phase 3: Web technology fingerprinting, WAF detection, header analysis,
    SSL/TLS auditing, CMS detection & specialised scanning.
    Tools: whatweb, wafw00f, webanalyze, nikto, testssl.sh, sslscan,
           wpscan, joomscan, droopescan, magescan
    """

    def __init__(
        self,
        runner: AsyncRunner,
        store:  ResultsStore,
        proxy:  Optional[str] = None,
        threads: int = 10,
    ):
        self.runner  = runner
        self.store   = store
        self.proxy   = proxy
        self.threads = threads
        self.domain  = store.domain
        self.target  = store.target
        self.outdir  = store.output_dir

    async def run(self):
        print_phase_header(
            3, 'WEB ANALYSIS, WAF & CMS DETECTION',
            ['whatweb', 'wafw00f', 'webanalyze', 'nikto',
             'testssl.sh', 'sslscan', 'wpscan', 'joomscan',
             'droopescan', 'magescan']
        )

        live_hosts = self.store.get('live_hosts', [])
        target_urls = [
            h.get('url', h) if isinstance(h, dict) else h
            for h in live_hosts[:10]
        ] or [self.target]

        await asyncio.gather(
            self._whatweb(target_urls),
            self._wafw00f(target_urls),
            self._webanalyze(target_urls),
        )

        await asyncio.gather(
            self._header_analysis(target_urls),
            self._ssl_tls_scan(),
        )

        await self._nikto(target_urls)
        await self._cms_detect_and_scan()
        self._print_summary()

    # ── technology fingerprinting ─────────────────────────────────────────

    async def _whatweb(self, urls: List[str]):
        if not tool_exists('whatweb'):
            return
        print_tool('whatweb', f'Technology detection on {len(urls)} URLs')
        tech_found = []
        for url in urls[:5]:
            proxy_opt = f'--proxy={self.proxy}' if self.proxy else ''
            rc, out, _ = await self.runner.run(
                f'whatweb --color=never --aggression=3 {proxy_opt} {url} 2>/dev/null',
                timeout=60, tag='whatweb'
            )
            if out:
                tech_found.append({'url': url, 'output': out.strip()[:500]})
        self.store.set('web_technologies', tech_found)
        print_ok(f'whatweb: {len(tech_found)} URLs analysed')

    async def _wafw00f(self, urls: List[str]):
        if not tool_exists('wafw00f'):
            return
        print_tool('wafw00f', 'WAF detection')
        waf_info = {}
        for url in urls[:3]:
            rc, out, _ = await self.runner.run(
                f'wafw00f {url} --format=json 2>/dev/null',
                timeout=60, tag='wafw00f'
            )
            waf_match = re.search(r'is behind (.+?) WAF', out, re.IGNORECASE)
            if waf_match:
                waf_name = waf_match.group(1)
                waf_info[url] = waf_name
                print_info(f'WAF detected: [bold yellow]{waf_name}[/bold yellow] on {url}')
            elif 'No WAF detected' in out or 'Generic' in out:
                waf_info[url] = None
        self.store.set('waf_info', waf_info)

    async def _webanalyze(self, urls: List[str]):
        if not tool_exists('webanalyze'):
            return
        print_tool('webanalyze', 'Deep technology analysis')
        for url in urls[:3]:
            rc, out, _ = await self.runner.run(
                f'webanalyze -host {url} -output json 2>/dev/null',
                timeout=60, tag='webanalyze'
            )
            try:
                data = json.loads(out) if out.strip() else {}
                if data:
                    current_tech = self.store.get('web_technologies', [])
                    current_tech.append({'url': url, 'webanalyze': data})
            except Exception:
                pass

    # ── HTTP header analysis ──────────────────────────────────────────────

    async def _header_analysis(self, urls: List[str]):
        print_tool('curl', 'HTTP header security analysis')
        all_headers = {}

        for url in urls[:5]:
            proxy_opt = f'-x {self.proxy}' if self.proxy else ''
            rc, out, _ = await self.runner.run(
                f'curl -skI --max-time 15 {proxy_opt} -A "Mozilla/5.0" {url} 2>/dev/null',
                timeout=30, tag='headers'
            )
            if not out:
                continue

            headers = {}
            status_line = out.splitlines()[0] if out.splitlines() else ''
            for line in out.splitlines()[1:]:
                if ':' in line:
                    k, _, v = line.partition(':')
                    headers[k.strip().lower()] = v.strip()

            all_headers[url] = headers
            self._check_security_headers(url, headers)
            self._check_cors(url, headers)
            self._check_cookies(url, headers)

        self.store.set('headers', all_headers)

    def _check_security_headers(self, url: str, headers: Dict[str, str]):
        """Flag missing / misconfigured security headers."""
        required = {
            'strict-transport-security': 'HSTS not present',
            'x-frame-options':           'Clickjacking protection missing',
            'x-content-type-options':    'MIME sniffing protection missing',
            'content-security-policy':   'CSP not configured',
            'referrer-policy':           'Referrer-Policy header missing',
            'permissions-policy':        'Permissions-Policy not set',
        }
        for header, desc in required.items():
            if header not in headers:
                self.store.add_vuln({
                    'name':        f'Missing Security Header: {header.title()}',
                    'severity':    'low',
                    'url':         url,
                    'description': desc,
                    'tool':        'header-analysis',
                    'owasp':       'A05:2021',
                })
                print_finding('low', f'Missing {header}', url)

        # Check HSTS values
        hsts = headers.get('strict-transport-security', '')
        if hsts:
            m = re.search(r'max-age=(\d+)', hsts)
            if m and int(m.group(1)) < 31536000:
                print_finding('low', 'HSTS max-age too short', url)

    def _check_cors(self, url: str, headers: Dict[str, str]):
        """Detect CORS misconfiguration."""
        acao = headers.get('access-control-allow-origin', '')
        acac = headers.get('access-control-allow-credentials', '').lower()
        if acao == '*':
            self.store.add_vuln({
                'name':        'CORS Wildcard Origin',
                'severity':    'medium',
                'url':         url,
                'description': 'Access-Control-Allow-Origin: * exposes API to any origin',
                'tool':        'header-analysis',
            })
            print_finding('medium', 'CORS Wildcard (*)', url)
        elif acao and acac == 'true':
            self.store.add_vuln({
                'name':        'CORS Misconfiguration (with Credentials)',
                'severity':    'high',
                'url':         url,
                'description': 'Arbitrary origin with credentials=true allows session hijacking',
                'tool':        'header-analysis',
            })
            print_finding('high', 'CORS + Credentials vulnerability!', url)

        self.store.add('cors_issues', {'url': url, 'acao': acao, 'acac': acac})

    def _check_cookies(self, url: str, headers: Dict[str, str]):
        """Audit session cookies."""
        set_cookie = headers.get('set-cookie', '')
        if set_cookie:
            issues = []
            if 'httponly' not in set_cookie.lower():
                issues.append('Missing HttpOnly flag')
            if 'secure' not in set_cookie.lower() and 'https' in url:
                issues.append('Missing Secure flag')
            if 'samesite' not in set_cookie.lower():
                issues.append('Missing SameSite attribute')

            for issue in issues:
                self.store.add_vuln({
                    'name':        f'Cookie Misconfiguration: {issue}',
                    'severity':    'low',
                    'url':         url,
                    'description': f'Session cookie is missing security attribute: {issue}',
                    'tool':        'header-analysis',
                })
            self.store.add('cookie_issues', {'url': url, 'issues': issues})

    # ── SSL / TLS ─────────────────────────────────────────────────────────

    async def _ssl_tls_scan(self):
        parsed = urlparse(self.target if '://' in self.target else f'https://{self.target}')
        if parsed.scheme != 'https' and '443' not in self.target:
            return

        host = parsed.hostname or self.domain

        if tool_exists('testssl.sh') or tool_exists('testssl'):
            print_tool('testssl.sh', f'TLS audit: {host}')
            binary = 'testssl.sh' if tool_exists('testssl.sh') else 'testssl'
            outfile = self.outdir / 'ssl.json'
            rc, out, _ = await self.runner.run(
                f'{binary} --jsonfile {outfile} --quiet --color 0 '
                f'--severity LOW --fast {host}:443 2>/dev/null',
                timeout=300, tag='testssl'
            )
            if outfile.exists():
                self._parse_testssl_json(str(outfile))

        elif tool_exists('sslscan'):
            print_tool('sslscan', f'SSL scan: {host}')
            outfile = self.outdir / 'sslscan.xml'
            rc, out, _ = await self.runner.run(
                f'sslscan --xml={outfile} --no-colour {host}:443 2>/dev/null',
                timeout=120, tag='sslscan'
            )
            self._parse_sslscan_output(out)

    def _parse_testssl_json(self, path: str):
        try:
            data = json.loads(Path(path).read_text())
            ssl_findings = []
            for entry in data if isinstance(data, list) else data.get('scanResult', [{}])[0].get('findings', []):
                severity_map = {
                    'CRITICAL': 'critical',
                    'HIGH':     'high',
                    'MEDIUM':   'medium',
                    'LOW':      'low',
                    'INFO':     'info',
                    'OK':       'info',
                    'WARN':     'medium',
                }
                sev_raw = entry.get('severity', 'INFO')
                sev = severity_map.get(sev_raw.upper(), 'info')
                finding = {
                    'id':       entry.get('id', ''),
                    'finding':  entry.get('finding', ''),
                    'severity': sev,
                }
                ssl_findings.append(finding)
                if sev in ('critical', 'high', 'medium'):
                    self.store.add_vuln({
                        'name':     f'TLS/SSL: {entry.get("id","")}',
                        'severity': sev,
                        'url':      self.target,
                        'description': entry.get('finding',''),
                        'tool':    'testssl.sh',
                    })
                    print_finding(sev, f'TLS: {entry.get("id","")}', self.target)
            self.store.set('ssl_findings', ssl_findings)
        except Exception as exc:
            print_warn(f'testssl parse: {exc}')

    def _parse_sslscan_output(self, output: str):
        ssl_findings = []
        for line in output.splitlines():
            if any(x in line for x in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']):
                protocol = line.strip().split()[0] if line.strip() else 'Unknown'
                ssl_findings.append({'finding': f'Deprecated protocol enabled: {protocol}', 'severity': 'medium'})
                self.store.add_vuln({
                    'name':        f'Weak TLS Protocol: {protocol}',
                    'severity':    'medium',
                    'url':         self.target,
                    'description': f'Deprecated protocol {protocol} is enabled',
                    'tool':        'sslscan',
                })
                print_finding('medium', f'Weak protocol: {protocol}', self.target)

    # ── nikto ─────────────────────────────────────────────────────────────

    async def _nikto(self, urls: List[str]):
        if not tool_exists('nikto'):
            return
        print_tool('nikto', f'Web vulnerability scanner')
        for url in urls[:2]:
            proxy_opt = f'-useproxy {self.proxy}' if self.proxy else ''
            outfile = self.outdir / 'nikto.txt'
            rc, out, _ = await self.runner.run(
                f'nikto -h {url} {proxy_opt} -Format txt -output {outfile} '
                f'-Tuning 123456789abcde -timeout 10 -Display V 2>/dev/null',
                timeout=600, tag='nikto'
            )
            self._parse_nikto_output(out, url)

    def _parse_nikto_output(self, output: str, url: str):
        for line in output.splitlines():
            if line.startswith('+ ') and 'OSVDB' not in line and len(line) > 10:
                self.store.add_vuln({
                    'name':        line[2:80],
                    'severity':    'medium',
                    'url':         url,
                    'description': line[2:],
                    'tool':        'nikto',
                })

    # ── CMS detection ─────────────────────────────────────────────────────

    async def _cms_detect_and_scan(self):
        print_tool('cms-detect', 'CMS fingerprinting')
        cms_type = await self._detect_cms()
        self.store.set('cms_type', cms_type)

        if cms_type:
            print_ok(f'CMS detected: [bold yellow]{cms_type.upper()}[/bold yellow]')
            await self._run_cms_scanner(cms_type)
        else:
            print_info('No common CMS detected')

    async def _detect_cms(self) -> Optional[str]:
        """Fingerprint the CMS by fetching target content."""
        proxy_opt = f'-x {self.proxy}' if self.proxy else ''
        rc, out, _ = await self.runner.run(
            f'curl -sk --max-time 15 {proxy_opt} -A "Mozilla/5.0" {self.target} 2>/dev/null',
            timeout=30, tag='cms-probe'
        )
        content = out.lower()

        cms_indicators = {
            'wordpress': [
                '/wp-content/', '/wp-includes/', 'wp-json',
                'generator.*wordpress', 'wp-login.php',
            ],
            'joomla': [
                '/components/', '/modules/', 'generator.*joomla',
                'joomla!', '/media/system/',
            ],
            'drupal': [
                '/sites/default/', '/modules/', 'drupal.settings',
                'drupal.behaviors', 'generator.*drupal',
            ],
            'magento': [
                'mage/', '/skin/frontend/', '/js/mage/',
                'magentoSomeStorefrontConfig',
            ],
            'shopify': ['cdn.shopify.com', 'shopify.com'],
            'wix':     ['wix.com', 'wixsite.com'],
            'typo3':   ['typo3', 'fileadmin'],
            'laravel': ['laravel_session', 'x-powered-by.*laravel'],
        }

        for cms, indicators in cms_indicators.items():
            for indicator in indicators:
                if re.search(indicator, content, re.IGNORECASE):
                    return cms
        return None

    async def _run_cms_scanner(self, cms: str):
        runners = {
            'wordpress': self._wpscan,
            'joomla':    self._joomscan,
            'drupal':    self._droopescan,
            'magento':   self._magescan,
        }
        fn = runners.get(cms)
        if fn:
            await fn()

    async def _wpscan(self):
        if not tool_exists('wpscan'):
            print_warn('wpscan not installed')
            return
        print_tool('wpscan', f'WordPress security scan: {self.target}')
        outfile = self.outdir / 'wpscan.json'
        api_flag = ''
        wpscan_api = os.environ.get('WPSCAN_API', '')
        if wpscan_api:
            api_flag = f'--api-token {wpscan_api}'

        proxy_opt = f'--proxy {self.proxy}' if self.proxy else ''
        rc, out, _ = await self.runner.run(
            f'wpscan --url {self.target} {proxy_opt} {api_flag} '
            f'--enumerate vp,vt,u,ap,at,tt,cb,dbe '
            f'--plugins-detection aggressive '
            f'--format json --output {outfile} --no-banner 2>/dev/null',
            timeout=600, tag='wpscan'
        )
        if outfile.exists():
            self._parse_wpscan_json(str(outfile))

    def _parse_wpscan_json(self, path: str):
        try:
            data = json.loads(Path(path).read_text())
            findings = []
            wp_ver = data.get('version', {})
            if wp_ver:
                ver_str = wp_ver.get('number', 'unknown')
                findings.append({'name': f'WordPress {ver_str}', 'type': 'version'})

            for vuln in data.get('vulnerabilities', []):
                sev = 'high' if vuln.get('cvss', {}).get('score', 0) >= 7 else 'medium'
                self.store.add_vuln({
                    'name':        vuln.get('title', 'WP Vulnerability'),
                    'severity':    sev,
                    'url':         self.target,
                    'description': vuln.get('description', ''),
                    'cve':         vuln.get('references', {}).get('cve', []),
                    'tool':        'wpscan',
                })
                print_finding(sev, vuln.get('title','WP Vuln')[:80], self.target)

            for plugin_name, plugin_data in data.get('plugins', {}).items():
                for vuln in plugin_data.get('vulnerabilities', []):
                    self.store.add_vuln({
                        'name':        f'WP Plugin: {plugin_name} – {vuln.get("title","")}',
                        'severity':    'high',
                        'url':         self.target,
                        'description': vuln.get('description', ''),
                        'tool':        'wpscan',
                    })
                    print_finding('high', f'Plugin vuln: {plugin_name}', self.target)

            self.store.set('cms_findings', findings)
            print_ok(f'wpscan: {len(findings)} findings')
        except Exception as exc:
            print_warn(f'wpscan parse: {exc}')

    async def _joomscan(self):
        if not tool_exists('joomscan'):
            return
        print_tool('joomscan', f'Joomla scan: {self.target}')
        outfile = self.outdir / 'joomscan.txt'
        rc, out, _ = await self.runner.run(
            f'joomscan --url {self.target} --report {outfile} 2>/dev/null',
            timeout=300, tag='joomscan'
        )
        for line in out.splitlines():
            if '[++]' in line or 'Vulnerable' in line.lower():
                self.store.add_vuln({
                    'name':     line.strip()[:80],
                    'severity': 'medium',
                    'url':      self.target,
                    'tool':     'joomscan',
                })
                print_finding('medium', line.strip()[:80], self.target)

    async def _droopescan(self):
        if not tool_exists('droopescan'):
            return
        print_tool('droopescan', f'Drupal/Moodle scan: {self.target}')
        rc, out, _ = await self.runner.run(
            f'droopescan scan drupal -u {self.target} -t {self.threads} 2>/dev/null',
            timeout=300, tag='droopescan'
        )
        for line in out.splitlines():
            if line.strip() and not line.startswith('[*]'):
                self.store.add_vuln({
                    'name':     line.strip()[:80],
                    'severity': 'medium',
                    'url':      self.target,
                    'tool':     'droopescan',
                })

    async def _magescan(self):
        print_tool('magescan', f'Magento scan: {self.target}')
        rc, out, _ = await self.runner.run(
            f'php /usr/local/bin/magescan.phar scan:all {self.target} 2>/dev/null || '
            f'magescan.phar scan:all {self.target} 2>/dev/null',
            timeout=300, tag='magescan'
        )
        for line in out.splitlines():
            if line.strip():
                self.store.add_vuln({
                    'name':     line.strip()[:80],
                    'severity': 'low',
                    'url':      self.target,
                    'tool':     'magescan',
                })

    def _print_summary(self):
        techs = self.store.get('web_technologies', [])
        waf   = self.store.get('waf_info', {})
        cms   = self.store.get('cms_type', 'None')
        ssl   = len(self.store.get('ssl_findings', []))
        console.print(
            f'\n  [bold green]Web Tech: {len(techs)} URLs analysed  '
            f'WAF: {", ".join(v for v in waf.values() if v) or "None"}  '
            f'CMS: {cms or "Unknown"}  '
            f'SSL Findings: {ssl}[/bold green]'
        )


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 4 — API & ENDPOINT DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════

class Phase4API:
    """
    Phase 4: Crawling, API endpoint discovery, JS secret extraction,
    wayback machine, GraphQL probing.
    Tools: katana, gospider, hakrawler, subjs, getJS, gau/wayback
    """

    def __init__(
        self,
        runner: AsyncRunner,
        store:  ResultsStore,
        proxy:  Optional[str] = None,
        threads: int = 10,
    ):
        self.runner  = runner
        self.store   = store
        self.proxy   = proxy
        self.threads = threads
        self.domain  = store.domain
        self.target  = store.target
        self.outdir  = store.output_dir

    async def run(self):
        print_phase_header(
            4, 'API & ENDPOINT DISCOVERY',
            ['katana', 'gospider', 'hakrawler', 'subjs', 'getJS', 'gau']
        )

        await asyncio.gather(
            self._katana(),
            self._gospider(),
            self._hakrawler(),
            self._wayback(),
        )

        await asyncio.gather(
            self._js_analysis(),
            self._api_endpoint_probe(),
            self._graphql_probe(),
        )

        self._print_summary()

    # ── katana ────────────────────────────────────────────────────────────

    async def _katana(self):
        if not tool_exists('katana'):
            return
        print_tool('katana', f'Next-gen crawling: {self.target}')
        outfile = self.outdir / 'katana.txt'
        proxy_opt = f'-proxy {self.proxy}' if self.proxy else ''
        rc, out, _ = await self.runner.run(
            f'katana -u {self.target} -depth 3 -jc -ef png,jpg,gif,css,ttf,woff '
            f'-concurrency {self.threads} -silent {proxy_opt} -o {outfile} 2>/dev/null',
            timeout=300, tag='katana'
        )
        if outfile.exists():
            urls = [l.strip() for l in outfile.read_text().splitlines() if l.strip()]
            self.store.add('crawled_urls', urls)
            print_ok(f'katana: {len(urls)} URLs crawled')

    async def _gospider(self):
        if not tool_exists('gospider'):
            return
        print_tool('gospider', f'Fast spidering: {self.target}')
        proxy_opt = f'-p {self.proxy}' if self.proxy else ''
        rc, out, _ = await self.runner.run(
            f'gospider -s {self.target} -c {self.threads} -d 2 '
            f'--js -t {self.threads} --sitemap --robots {proxy_opt} '
            f'-q 2>/dev/null',
            timeout=300, tag='gospider'
        )
        urls = re.findall(r'https?://[^\s\]]+', out)
        if urls:
            self.store.add('crawled_urls', list(set(urls)))
            print_ok(f'gospider: {len(urls)} URLs found')

    async def _hakrawler(self):
        if not tool_exists('hakrawler'):
            return
        print_tool('hakrawler', f'Crawling: {self.target}')
        proxy_opt = f'-proxy {self.proxy}' if self.proxy else ''
        rc, out, _ = await self.runner.run(
            f'echo {self.target} | hakrawler -depth 2 -plain {proxy_opt} 2>/dev/null',
            timeout=180, tag='hakrawler'
        )
        urls = [l.strip() for l in out.splitlines() if l.strip().startswith('http')]
        if urls:
            self.store.add('crawled_urls', urls)
            print_ok(f'hakrawler: {len(urls)} URLs')

    # ── wayback machine ───────────────────────────────────────────────────

    async def _wayback(self):
        print_tool('gau/wayback', f'Historical URL collection: {self.domain}')

        if tool_exists('gau'):
            rc, out, _ = await self.runner.run(
                f'gau --threads {self.threads} --blacklist png,jpg,gif,css,woff,ttf '
                f'{self.domain} 2>/dev/null',
                timeout=180, tag='gau'
            )
            urls = [l.strip() for l in out.splitlines() if l.strip()]
        else:
            # Fallback: Wayback CDX API
            rc, out, _ = await self.runner.run(
                f'curl -sk "https://web.archive.org/cdx/search/cdx'
                f'?url=*.{self.domain}/*&output=text&fl=original&collapse=urlkey&limit=2000" '
                f'2>/dev/null',
                timeout=120, tag='wayback-api'
            )
            urls = [l.strip() for l in out.splitlines() if l.strip().startswith('http')]

        if urls:
            self.store.add('wayback_urls', list(set(urls)))
            # Look for interesting extensions/paths
            interesting = [u for u in urls if re.search(
                r'\.(sql|bak|backup|env|config|log|old|orig|php\.bak)$|'
                r'(admin|debug|test|dev|staging)', u, re.IGNORECASE
            )]
            for u in interesting[:20]:
                print_info(f'Interesting URL: {u[:100]}')
            print_ok(f'Historical URLs: {len(urls)} ({len(interesting)} interesting)')

    # ── JavaScript analysis ────────────────────────────────────────────────

    async def _js_analysis(self):
        print_tool('subjs/getJS', 'JavaScript endpoint & secret extraction')

        # Gather JS URLs from crawled data
        all_urls = (
            self.store.get('crawled_urls', []) +
            self.store.get('wayback_urls', [])
        )
        js_urls = [u for u in set(all_urls) if u.endswith('.js') or '.js?' in u]

        # Also discover JS from page
        if tool_exists('subjs'):
            rc, out, _ = await self.runner.run(
                f'echo {self.target} | subjs 2>/dev/null',
                timeout=120, tag='subjs'
            )
            js_urls += [l.strip() for l in out.splitlines() if l.strip()]

        if tool_exists('getJS'):
            rc, out, _ = await self.runner.run(
                f'getJS --url {self.target} --complete 2>/dev/null',
                timeout=120, tag='getJS'
            )
            js_urls += [l.strip() for l in out.splitlines() if l.strip()]

        js_urls = list(set(js_urls))[:100]
        all_secrets = []

        for js_url in js_urls:
            proxy_opt = f'-x {self.proxy}' if self.proxy else ''
            rc, content, _ = await self.runner.run(
                f'curl -sk --max-time 10 {proxy_opt} {js_url} 2>/dev/null',
                timeout=20, tag='js-fetch'
            )
            if content:
                secrets = scan_js_secrets(content, source=js_url)
                if secrets:
                    all_secrets.extend(secrets)
                    for s in secrets:
                        print_finding('high', f'Secret in JS: {s["type"]}',
                                      js_url, s['value'][:60])
                        self.store.add_vuln({
                            'name':        f'Exposed Secret: {s["type"]}',
                            'severity':    'high',
                            'url':         js_url,
                            'description': f'{s["type"]} found in JS file',
                            'tool':        'js-analysis',
                        })

        self.store.set('js_secrets', all_secrets)
        self.store.inc('secrets', len(all_secrets))
        print_ok(f'JS analysis: {len(js_urls)} files → {len(all_secrets)} secrets found')

    # ── API endpoint probing ──────────────────────────────────────────────

    async def _api_endpoint_probe(self):
        print_tool('api-probe', 'API endpoint discovery')
        found = []

        async def probe(endpoint: str):
            url = self.target.rstrip('/') + endpoint
            proxy_opt = f'-x {self.proxy}' if self.proxy else ''
            rc, out, _ = await self.runner.run(
                f'curl -sk --max-time 8 {proxy_opt} -o /dev/null '
                f'-w "%{{http_code}}|%{{content_type}}|%{{size_download}}" '
                f'-A "Mozilla/5.0" {url} 2>/dev/null',
                timeout=15, tag='api-probe'
            )
            if out:
                parts = out.split('|')
                code = int(parts[0]) if parts[0].isdigit() else 0
                ctype = parts[1] if len(parts) > 1 else ''
                if code not in (404, 410, 0) and code < 500:
                    found.append({
                        'url':          url,
                        'status':       code,
                        'content_type': ctype,
                        'endpoint':     endpoint,
                    })
                    if code < 400:
                        print_info(f'API endpoint [{code}]: {endpoint}')

        tasks = [probe(ep) for ep in API_ENDPOINTS]
        await asyncio.gather(*tasks)

        self.store.set('api_endpoints', found)
        print_ok(f'API endpoints: {len(found)} live')

    # ── GraphQL probing ───────────────────────────────────────────────────

    async def _graphql_probe(self):
        print_tool('graphql', 'GraphQL introspection probe')
        graphql_paths = [
            '/graphql', '/api/graphql', '/gql', '/graphiql',
            '/playground', '/altair', '/v1/graphql', '/query',
        ]
        graphql_findings = []

        introspection_query = '{"query":"query{__schema{queryType{name}}}"}' 

        for path in graphql_paths:
            url = self.target.rstrip('/') + path
            proxy_opt = f'-x {self.proxy}' if self.proxy else ''
            rc, out, _ = await self.runner.run(
                f'curl -sk --max-time 10 {proxy_opt} '
                f'-H "Content-Type: application/json" '
                f'-d \'{introspection_query}\' {url} 2>/dev/null',
                timeout=15, tag='graphql'
            )
            if out and '__schema' in out.lower():
                graphql_findings.append({
                    'url':   url,
                    'type':  'GraphQL introspection enabled',
                })
                self.store.add_vuln({
                    'name':        'GraphQL Introspection Enabled',
                    'severity':    'medium',
                    'url':         url,
                    'description': 'GraphQL introspection allows full schema enumeration',
                    'tool':        'graphql-probe',
                })
                print_finding('medium', 'GraphQL Introspection Enabled!', url)
            elif out and ('graphql' in out.lower() or 'playground' in out.lower()):
                graphql_findings.append({'url': url, 'type': 'GraphQL endpoint detected'})
                print_info(f'GraphQL endpoint: {url}')

        self.store.set('graphql_findings', graphql_findings)

    def _print_summary(self):
        crawled = len(set(self.store.get('crawled_urls', [])))
        wayback = len(self.store.get('wayback_urls', []))
        api     = len(self.store.get('api_endpoints', []))
        secrets = len(self.store.get('js_secrets', []))
        graphql = len(self.store.get('graphql_findings', []))
        console.print(
            f'\n  [bold green]Crawled: {crawled}  Wayback: {wayback}  '
            f'API Endpoints: {api}  JS Secrets: {secrets}  GraphQL: {graphql}[/bold green]'
        )


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 5 — CONTENT DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════

class Phase5Content:
    """
    Phase 5: Directory and file fuzzing, git exposure, backup files,
    configuration files, sensitive paths.
    Tools: ffuf, feroxbuster, dirsearch, gobuster
    """

    def __init__(
        self,
        runner:  AsyncRunner,
        store:   ResultsStore,
        proxy:   Optional[str] = None,
        threads: int = 30,
    ):
        self.runner  = runner
        self.store   = store
        self.proxy   = proxy
        self.threads = threads
        self.domain  = store.domain
        self.target  = store.target
        self.outdir  = store.output_dir

    async def run(self):
        print_phase_header(
            5, 'CONTENT DISCOVERY & FILE EXPOSURE',
            ['ffuf', 'feroxbuster', 'dirsearch', 'gobuster']
        )

        live_hosts = self.store.get('live_hosts', [])
        targets = [
            h.get('url', h) if isinstance(h, dict) else h
            for h in live_hosts[:5]
        ] or [self.target]

        for url in targets[:3]:
            await asyncio.gather(
                self._fuzz(url),
                self._git_exposure(url),
                self._juicy_paths(url),
                self._backup_files(url),
            )

        self._print_summary()

    # ── fuzzing ───────────────────────────────────────────────────────────

    async def _fuzz(self, url: str):
        """Main content fuzzing with best available tool."""
        wordlist = self._find_wordlist()
        if not wordlist:
            print_warn('No wordlist found – skipping directory fuzzing')
            return

        if tool_exists('ffuf'):
            await self._ffuf(url, wordlist)
        elif tool_exists('feroxbuster'):
            await self._feroxbuster(url, wordlist)
        elif tool_exists('dirsearch'):
            await self._dirsearch(url)
        elif tool_exists('gobuster'):
            await self._gobuster(url, wordlist)

    def _find_wordlist(self) -> Optional[str]:
        """Find best available wordlist."""
        candidates = [
            '/usr/share/seclists/Discovery/Web-Content/common.txt',
            '/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt',
            '/usr/share/wordlists/dirb/common.txt',
            '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
            '/opt/SecLists/Discovery/Web-Content/common.txt',
            os.path.expanduser('~/SecLists/Discovery/Web-Content/common.txt'),
        ]
        for path in candidates:
            if os.path.exists(path):
                return path
        return None

    async def _ffuf(self, url: str, wordlist: str):
        print_tool('ffuf', f'Directory fuzzing: {url}')
        outfile = self.outdir / 'ffuf.json'
        waf = self.store.get('waf_info', {})
        has_waf = any(v for v in waf.values())
        rate = '150' if has_waf else '500'
        proxy_opt = f'-x {self.proxy}' if self.proxy else ''
        rc, out, _ = await self.runner.run(
            f'ffuf -u {url}/FUZZ -w {wordlist} -t {self.threads} '
            f'-mc 200,201,202,204,301,302,307,401,403,405,500 '
            f'-o {outfile} -of json -rate {rate} '
            f'-fs 0 -ac {proxy_opt} 2>/dev/null',
            timeout=600, tag='ffuf'
        )
        if outfile.exists():
            self._parse_ffuf(str(outfile), url)

    def _parse_ffuf(self, path: str, base_url: str):
        try:
            data = json.loads(Path(path).read_text())
            results = data.get('results', [])
            dirs = []
            for r in results:
                entry = {
                    'url':    r.get('url', ''),
                    'status': r.get('status', 0),
                    'length': r.get('length', 0),
                    'words':  r.get('words', 0),
                }
                dirs.append(entry)
                code = r.get('status', 0)
                if code in (200, 201, 202):
                    print_ok(f'[{code}] {r.get("url", "")[:80]}')
                elif code in (301, 302, 307):
                    print_info(f'[{code}] {r.get("url", "")[:80]} → redirect')
                elif code == 403:
                    print_info(f'[403] {r.get("url", "")[:80]} (forbidden)')
                elif code == 401:
                    self.store.add_vuln({
                        'name':        'Exposed Protected Resource',
                        'severity':    'medium',
                        'url':         r.get('url', ''),
                        'description': 'Resource requires authentication – may be brute-forced',
                        'tool':        'ffuf',
                    })
            self.store.add('directories', dirs)
            print_ok(f'ffuf: {len(dirs)} paths discovered')
        except Exception as exc:
            print_warn(f'ffuf parse: {exc}')

    async def _feroxbuster(self, url: str, wordlist: str):
        print_tool('feroxbuster', f'Recursive content discovery: {url}')
        outfile = self.outdir / 'feroxbuster.txt'
        proxy_opt = f'--proxy {self.proxy}' if self.proxy else ''
        rc, out, _ = await self.runner.run(
            f'feroxbuster -u {url} -w {wordlist} -t {self.threads} '
            f'-d 3 --auto-tune --smart '
            f'-s 200,201,204,301,302,307,401,403,405 '
            f'-o {outfile} {proxy_opt} --quiet 2>/dev/null',
            timeout=600, tag='feroxbuster'
        )
        if outfile.exists():
            lines = outfile.read_text().splitlines()
            dirs = []
            for line in lines:
                parts = line.split()
                if len(parts) >= 2:
                    code = parts[0] if parts[0].isdigit() else ''
                    found_url = next((p for p in parts if p.startswith('http')), '')
                    if code and found_url:
                        dirs.append({'url': found_url, 'status': int(code)})
                        if code in ('200', '201'):
                            print_ok(f'[{code}] {found_url[:80]}')
            self.store.add('directories', dirs)
            print_ok(f'feroxbuster: {len(dirs)} paths')

    async def _dirsearch(self, url: str):
        print_tool('dirsearch', f'Directory search: {url}')
        outfile = self.outdir / 'dirsearch.json'
        proxy_opt = f'--proxy={self.proxy}' if self.proxy else ''
        rc, out, _ = await self.runner.run(
            f'dirsearch -u {url} -t {self.threads} --format=json '
            f'--output={outfile} -x 404,500 {proxy_opt} -q 2>/dev/null',
            timeout=600, tag='dirsearch'
        )
        if outfile.exists():
            try:
                data = json.loads(outfile.read_text())
                dirs = []
                for item in data.get('results', []):
                    entry = {
                        'url':    item.get('url', ''),
                        'status': item.get('status', 0),
                    }
                    dirs.append(entry)
                    if item.get('status') in (200, 201):
                        print_ok(f'[{item["status"]}] {item.get("url","")[:80]}')
                self.store.add('directories', dirs)
                print_ok(f'dirsearch: {len(dirs)} paths found')
            except Exception:
                pass

    async def _gobuster(self, url: str, wordlist: str):
        print_tool('gobuster', f'Directory brute-force: {url}')
        proxy_opt = f'--proxy {self.proxy}' if self.proxy else ''
        rc, out, _ = await self.runner.run(
            f'gobuster dir -u {url} -w {wordlist} -t {self.threads} '
            f'-s 200,201,204,301,302,307,401,403 '
            f'--no-error -q {proxy_opt} 2>/dev/null',
            timeout=600, tag='gobuster'
        )
        dirs = []
        for line in out.splitlines():
            m = re.match(r'(/.+)\s+\(Status:\s*(\d+)\)', line)
            if m:
                path = m.group(1)
                code = int(m.group(2))
                dirs.append({'url': url + path, 'status': code})
                if code in (200, 201):
                    print_ok(f'[{code}] {url + path}')
        self.store.add('directories', dirs)
        print_ok(f'gobuster: {len(dirs)} paths')

    # ── git exposure ──────────────────────────────────────────────────────

    async def _git_exposure(self, url: str):
        print_tool('git-check', 'Exposed .git repository detection')
        git_paths = [
            '/.git/config',
            '/.git/HEAD',
            '/.git/COMMIT_EDITMSG',
            '/.git/index',
            '/.svn/entries',
            '/.hg/hgrc',
            '/.bzr/README',
        ]
        proxy_opt = f'-x {self.proxy}' if self.proxy else ''
        for path in git_paths:
            check_url = url.rstrip('/') + path
            rc, out, _ = await self.runner.run(
                f'curl -sk --max-time 8 {proxy_opt} -o /dev/null '
                f'-w "%{{http_code}}" {check_url} 2>/dev/null',
                timeout=15, tag='git-check'
            )
            code = out.strip()
            if code == '200':
                self.store.add('git_exposure', check_url)
                self.store.add_vuln({
                    'name':        f'Exposed VCS Directory: {path}',
                    'severity':    'high',
                    'url':         check_url,
                    'description': f'Version control file accessible at {path} – source code disclosure risk',
                    'tool':        'git-check',
                    'owasp':       'A05:2021',
                })
                print_finding('high', f'Exposed: {path}', check_url)

        # Run gitdumper if git found
        git_exposures = self.store.get('git_exposure', [])
        if git_exposures and tool_exists('git-dumper'):
            dump_dir = self.outdir / 'git_dump'
            dump_dir.mkdir(exist_ok=True)
            rc, out, _ = await self.runner.run(
                f'git-dumper {url} {dump_dir} 2>/dev/null',
                timeout=300, tag='git-dumper'
            )
            if list(dump_dir.glob('*')):
                print_finding('critical', 'Git repository dumped!', url,
                              f'Source code extracted to {dump_dir}')
                self.store.add_vuln({
                    'name':        'Git Repository Source Code Disclosure',
                    'severity':    'critical',
                    'url':         url,
                    'description': 'Full source code extracted via .git exposure',
                    'tool':        'git-dumper',
                })

    # ── juicy / sensitive paths ────────────────────────────────────────────

    async def _juicy_paths(self, url: str):
        print_tool('juicy-scan', 'Sensitive file & path detection')
        found = []
        proxy_opt = f'-x {self.proxy}' if self.proxy else ''

        async def check_path(path: str):
            check_url = url.rstrip('/') + path
            rc, out, _ = await self.runner.run(
                f'curl -sk --max-time 8 {proxy_opt} -o /dev/null '
                f'-w "%{{http_code}}|%{{size_download}}" {check_url} 2>/dev/null',
                timeout=15, tag='juicy'
            )
            if '|' in out:
                code_str, size_str = out.split('|', 1)
                code = int(code_str) if code_str.isdigit() else 0
                size = int(size_str) if size_str.isdigit() else 0
                if code == 200 and size > 0:
                    found.append({'url': check_url, 'status': code, 'size': size})
                    sev = 'high' if any(x in path for x in ['.env', 'config', 'backup', 'sql']) else 'medium'
                    self.store.add_vuln({
                        'name':        f'Sensitive File Exposed: {path}',
                        'severity':    sev,
                        'url':         check_url,
                        'description': f'Sensitive path accessible: {path} ({size} bytes)',
                        'tool':        'juicy-scan',
                    })
                    print_finding(sev, f'Exposed file: {path}', check_url,
                                  f'Size: {size} bytes')

        tasks = [check_path(p) for p in JUICY_PATHS]
        await asyncio.gather(*tasks)

        self.store.add('exposed_files', found)
        print_ok(f'Sensitive paths: {len(found)} found')

    # ── backup files ──────────────────────────────────────────────────────

    async def _backup_files(self, url: str):
        print_tool('backup-scan', 'Backup file detection')
        parsed = urlparse(url)
        domain_name = parsed.hostname or self.domain

        backup_patterns = [
            f'/{domain_name}.zip', f'/{domain_name}.tar.gz', f'/{domain_name}.bak',
            f'/{domain_name}.sql', f'/{domain_name}_backup.zip',
            '/backup.zip', '/backup.tar.gz', '/backup.sql',
            '/db_backup.sql', '/database.sql', '/dump.sql',
            '/www.zip', '/htdocs.zip', '/public_html.zip',
            '/site.tar.gz', '/web.zip', '/html.zip',
            '/old.zip', '/new.zip', '/temp.zip',
            '/wp-backup.zip', '/backup/backup.sql',
        ]
        proxy_opt = f'-x {self.proxy}' if self.proxy else ''
        found = []

        async def check_backup(path: str):
            check_url = url.rstrip('/') + path
            rc, out, _ = await self.runner.run(
                f'curl -sk --max-time 10 {proxy_opt} -o /dev/null '
                f'-w "%{{http_code}}|%{{size_download}}" {check_url} 2>/dev/null',
                timeout=15, tag='backup'
            )
            if '|' in out:
                code_str, size_str = out.split('|', 1)
                code = int(code_str) if code_str.isdigit() else 0
                size = int(size_str) if size_str.isdigit() else 0
                if code == 200 and size > 1024:
                    found.append({'url': check_url, 'size': size})
                    self.store.add_vuln({
                        'name':        f'Backup File Exposed: {path}',
                        'severity':    'critical',
                        'url':         check_url,
                        'description': f'Backup archive accessible ({size:,} bytes) – full source code/data at risk',
                        'tool':        'backup-scan',
                    })
                    print_finding('critical', f'BACKUP FILE EXPOSED!', check_url,
                                  f'Size: {size:,} bytes')

        tasks = [check_backup(p) for p in backup_patterns]
        await asyncio.gather(*tasks)

        self.store.set('backup_files', found)

    def _print_summary(self):
        dirs    = len(self.store.get('directories', []))
        git     = len(self.store.get('git_exposure', []))
        exposed = len(self.store.get('exposed_files', []))
        backups = len(self.store.get('backup_files', []))
        console.print(
            f'\n  [bold green]Directories: {dirs}  '
            f'Git Exposure: {git}  '
            f'Sensitive Files: {exposed}  '
            f'Backups: {backups}[/bold green]'
        )
        if git or exposed or backups:
            console.print(
                f'  [bold red]⚠  {git + exposed + backups} HIGH-RISK exposures![/bold red]'
            )


# ═══════════════════════════════════════════════════════════════════════════
# PUBLIC INTERFACE — imported by lx-bot.py
# ═══════════════════════════════════════════════════════════════════════════

__all__ = [
    # Banner / constants
    'BANNER', 'VERSION', 'AUTHOR', 'YEAR',
    'SEV_COLOR', 'OWASP_MAP', 'DEFAULT_CREDS', 'API_ENDPOINTS',
    'JUICY_PATHS', 'SECRET_PATTERNS',
    # Core engine
    'AsyncRunner', 'ResultsStore',
    # Helpers
    'console',
    'print_phase_header', 'print_finding', 'print_ok', 'print_warn',
    'print_err', 'print_info', 'print_tool', 'severity_bar',
    'extract_domain', 'normalise_url', 'is_valid_ip', 'tool_exists',
    'parse_nmap_xml', 'parse_nuclei_output', 'scan_js_secrets',
    # Phases 1-5
    'Phase1Recon', 'Phase2Ports', 'Phase3Web', 'Phase4API', 'Phase5Content',
]
