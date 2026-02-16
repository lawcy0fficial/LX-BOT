#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║              LX-BOT ULTIMATE REPORT GENERATOR v5.0                        ║
║          Professional Penetration Testing Report System (2026)            ║
║                                                                           ║
║  • Executive Summary  • Technical Deep-Dive  • CVSS v3.1 Scoring          ║
║  • Interactive Graphs • Vulnerability Heatmaps • Exploit Correlation      ║
║  • Remediation Roadmap • Compliance Mapping • Professional Format         ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import json
import html as html_module
import base64
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import math

# CVSS v3.1 Calculator
class CVSSCalculator:
    """
    CVSS v3.1 (Common Vulnerability Scoring System) Calculator
    Provides industry-standard vulnerability severity scoring
    """
    
    # Base Metrics
    ATTACK_VECTOR = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}  # Network, Adjacent, Local, Physical
    ATTACK_COMPLEXITY = {'L': 0.77, 'H': 0.44}  # Low, High
    PRIVILEGES_REQUIRED = {
        'N': {'unchanged': 0.85, 'changed': 0.85},  # None
        'L': {'unchanged': 0.62, 'changed': 0.68},  # Low
        'H': {'unchanged': 0.27, 'changed': 0.50}   # High
    }
    USER_INTERACTION = {'N': 0.85, 'R': 0.62}  # None, Required
    SCOPE = {'U': False, 'C': True}  # Unchanged, Changed
    IMPACT = {'H': 0.56, 'L': 0.22, 'N': 0.0}  # High, Low, None
    
    @classmethod
    def calculate_base_score(cls, vector: Dict[str, str]) -> float:
        """
        Calculate CVSS v3.1 Base Score from vector components
        Returns score between 0.0 and 10.0
        """
        try:
            av = cls.ATTACK_VECTOR.get(vector.get('AV', 'N'), 0.85)
            ac = cls.ATTACK_COMPLEXITY.get(vector.get('AC', 'L'), 0.77)
            
            scope_changed = cls.SCOPE.get(vector.get('S', 'U'), False)
            pr_key = 'changed' if scope_changed else 'unchanged'
            pr = cls.PRIVILEGES_REQUIRED.get(vector.get('PR', 'N'), {}).get(pr_key, 0.85)
            
            ui = cls.USER_INTERACTION.get(vector.get('UI', 'N'), 0.85)
            
            c = cls.IMPACT.get(vector.get('C', 'N'), 0.0)  # Confidentiality
            i = cls.IMPACT.get(vector.get('I', 'N'), 0.0)  # Integrity
            a = cls.IMPACT.get(vector.get('A', 'N'), 0.0)  # Availability
            
            # Calculate ISS (Impact Sub-Score)
            iss = 1 - ((1 - c) * (1 - i) * (1 - a))
            
            # Calculate Impact
            if scope_changed:
                impact = 7.52 * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15)
            else:
                impact = 6.42 * iss
            
            # Calculate Exploitability
            exploitability = 8.22 * av * ac * pr * ui
            
            # Calculate Base Score
            if impact <= 0:
                return 0.0
            
            if scope_changed:
                base_score = min(1.08 * (impact + exploitability), 10.0)
            else:
                base_score = min(impact + exploitability, 10.0)
            
            # Round up to 1 decimal
            return math.ceil(base_score * 10) / 10
            
        except Exception:
            return 5.0  # Default medium severity
    
    @classmethod
    def get_severity_rating(cls, score: float) -> str:
        """Convert CVSS score to severity rating"""
        if score == 0.0:
            return 'None'
        elif score < 4.0:
            return 'Low'
        elif score < 7.0:
            return 'Medium'
        elif score < 9.0:
            return 'High'
        else:
            return 'Critical'
    
    @classmethod
    def infer_vector_from_vuln(cls, vuln: Dict[str, Any]) -> Dict[str, str]:
        """
        Infer CVSS vector from vulnerability metadata
        Used when explicit CVSS data isn't available
        """
        severity = str(vuln.get('severity', 'medium')).lower()
        url = str(vuln.get('url', ''))
        name = str(vuln.get('name', '')).lower()
        
        # Default vector
        vector = {
            'AV': 'N',  # Network attack vector (most common)
            'AC': 'L',  # Low complexity
            'PR': 'N',  # No privileges required
            'UI': 'N',  # No user interaction
            'S': 'U',   # Scope unchanged
            'C': 'L',   # Low confidentiality impact
            'I': 'L',   # Low integrity impact
            'A': 'N',   # No availability impact
        }
        
        # Adjust based on vulnerability type
        if any(x in name for x in ['rce', 'remote code', 'command injection', 'deserialization']):
            vector.update({'C': 'H', 'I': 'H', 'A': 'H', 'AC': 'L'})
        
        elif any(x in name for x in ['sql injection', 'sqli']):
            vector.update({'C': 'H', 'I': 'H', 'A': 'L'})
        
        elif any(x in name for x in ['xss', 'cross-site scripting']):
            vector.update({'C': 'L', 'I': 'L', 'AC': 'L', 'UI': 'R', 'S': 'C'})
        
        elif any(x in name for x in ['xxe', 'xml external entity']):
            vector.update({'C': 'H', 'I': 'L', 'A': 'L'})
        
        elif any(x in name for x in ['ssrf', 'server-side request forgery']):
            vector.update({'C': 'H', 'I': 'L', 'A': 'L'})
        
        elif any(x in name for x in ['lfi', 'local file inclusion', 'path traversal']):
            vector.update({'C': 'H', 'I': 'N', 'A': 'N'})
        
        elif any(x in name for x in ['ssti', 'template injection']):
            vector.update({'C': 'H', 'I': 'H', 'A': 'H'})
        
        elif any(x in name for x in ['authentication bypass', 'auth bypass']):
            vector.update({'C': 'H', 'I': 'H', 'A': 'N', 'AC': 'L'})
        
        elif any(x in name for x in ['exposed', 'disclosure', 'information leak']):
            vector.update({'C': 'L', 'I': 'N', 'A': 'N', 'AC': 'L'})
        
        elif any(x in name for x in ['csrf', 'cross-site request forgery']):
            vector.update({'C': 'L', 'I': 'L', 'A': 'N', 'UI': 'R'})
        
        elif any(x in name for x in ['idor', 'insecure direct object']):
            vector.update({'C': 'L', 'I': 'L', 'A': 'N', 'AC': 'L'})
        
        # Adjust for severity
        if severity == 'critical':
            if vector['C'] != 'H':
                vector['C'] = 'H'
            if vector['I'] != 'H':
                vector['I'] = 'H'
        
        elif severity == 'high':
            if vector['C'] == 'N':
                vector['C'] = 'L'
            if vector['I'] == 'N':
                vector['I'] = 'L'
        
        return vector


class UltimateReportGenerator:
    """
    Ultimate Professional Penetration Testing Report Generator
    Produces executive-level HTML reports with:
    - CVSS v3.1 scoring for all findings
    - Interactive graphs and visualizations
    - Executive summary and technical deep-dive
    - Remediation roadmap
    - Compliance mapping (OWASP Top 10, CWE, etc.)
    """

    def __init__(self, results: Dict[str, Any], stats: Dict[str, int]):
        self.results = results
        self.stats = stats
        self.target = results.get('target', 'Unknown')
        self.domain = results.get('domain', 'Unknown')
        self.scan_time = results.get('scan_time', datetime.now().isoformat())
        self.scan_duration = results.get('scan_duration', 0)
        
        # Calculate CVSS scores for all vulnerabilities
        self._enrich_vulnerabilities_with_cvss()
    
    def _enrich_vulnerabilities_with_cvss(self):
        """Add CVSS scores to all vulnerability findings"""
        all_vulns = []
        
        # Collect all vulnerability sources
        for vuln_list in [
            self.results.get('vulnerabilities', []),
            self.results.get('nuclei_findings', []),
            self.results.get('xss_results', []),
            self.results.get('sqli_results', []),
            self.results.get('command_injection', []),
            self.results.get('ssrf_results', []),
            self.results.get('lfi_rfi_results', []),
            self.results.get('ssti_results', []),
        ]:
            for vuln in vuln_list:
                if isinstance(vuln, dict):
                    # Calculate CVSS if not present
                    if 'cvss_score' not in vuln:
                        vector = CVSSCalculator.infer_vector_from_vuln(vuln)
                        cvss_score = CVSSCalculator.calculate_base_score(vector)
                        vuln['cvss_score'] = cvss_score
                        vuln['cvss_vector'] = vector
                        vuln['cvss_severity'] = CVSSCalculator.get_severity_rating(cvss_score)
                    
                    all_vulns.append(vuln)
        
        self.all_vulnerabilities = sorted(all_vulns, key=lambda x: x.get('cvss_score', 0), reverse=True)
    
    def generate(self, output_path: str):
        """Generate complete HTML report"""
        html = self._build_html()
        Path(output_path).write_text(html, encoding='utf-8')
        print(f'[+] Professional penetration test report: {output_path}')
    
    # ══════════════════════════════════════════════════════════════════════
    # HTML STRUCTURE
    # ══════════════════════════════════════════════════════════════════════
    
    def _build_html(self) -> str:
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Penetration Test Report - {self.domain}</title>
    <script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>{self._get_css()}</style>
</head>
<body>
<div class="container">
    {self._build_cover_page()}
    {self._build_toc()}
    {self._build_executive_summary()}
    {self._build_risk_overview()}
    {self._build_cvss_distribution()}
    {self._build_findings_summary()}
    {self._build_vulnerability_details()}
    {self._build_network_findings()}
    {self._build_web_findings()}
    {self._build_injection_findings()}
    {self._build_exploitation_findings()}
    {self._build_osint_findings()}
    {self._build_remediation_roadmap()}
    {self._build_compliance_mapping()}
    {self._build_appendix()}
</div>
<script>{self._get_javascript()}</script>
</body>
</html>"""
    
    # ══════════════════════════════════════════════════════════════════════
    # CSS STYLING
    # ══════════════════════════════════════════════════════════════════════
    
    def _get_css(self) -> str:
        return """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        :root {
            --bg: #0a0a15;
            --bg2: #131325;
            --bg3: #1c1c35;
            --accent: #7c6af5;
            --accent2: #a78bfa;
            --critical: #ff2d55;
            --high: #ff6b35;
            --medium: #ffa502;
            --low: #26de81;
            --info: #54a0ff;
            --text: #e0e0f0;
            --text2: #9090b8;
            --border: rgba(124, 106, 245, 0.2);
        }
        
        body {
            font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.7;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: var(--bg2);
        }
        
        /* Cover Page */
        .cover {
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            background: linear-gradient(135deg, #1a0533 0%, #0d1b4b 50%, #1a0533 100%);
            text-align: center;
            padding: 60px 40px;
            page-break-after: always;
            position: relative;
            overflow: hidden;
        }
        
        .cover::before {
            content: '';
            position: absolute;
            inset: 0;
            background: radial-gradient(ellipse at 50% 30%, rgba(124,106,245,0.15) 0%, transparent 70%);
            pointer-events: none;
        }
        
        .cover-content {
            position: relative;
            z-index: 1;
        }
        
        .cover h1 {
            font-size: 4em;
            font-weight: 800;
            margin-bottom: 20px;
            background: linear-gradient(90deg, #a78bfa, #60a5fa, #a78bfa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .cover .subtitle {
            font-size: 1.8em;
            color: var(--text2);
            margin: 20px 0;
        }
        
        .cover .target {
            font-size: 2.2em;
            color: var(--accent2);
            margin: 30px 0;
            padding: 20px 50px;
            background: rgba(124, 106, 245, 0.1);
            border: 2px solid var(--border);
            border-radius: 50px;
            display: inline-block;
        }
        
        .cover .meta {
            margin-top: 60px;
            font-size: 1.1em;
            color: var(--text2);
        }
        
        .cover .meta p {
            margin: 10px 0;
        }
        
        /* Table of Contents */
        .toc {
            padding: 60px 40px;
            page-break-after: always;
        }
        
        .toc h2 {
            font-size: 2.5em;
            color: var(--accent2);
            margin-bottom: 40px;
            border-bottom: 3px solid var(--accent);
            padding-bottom: 20px;
        }
        
        .toc ul {
            list-style: none;
        }
        
        .toc li {
            margin: 15px 0;
            padding-left: 30px;
            position: relative;
        }
        
        .toc li::before {
            content: '▸';
            position: absolute;
            left: 0;
            color: var(--accent);
            font-weight: bold;
        }
        
        .toc a {
            color: var(--text);
            text-decoration: none;
            font-size: 1.1em;
            transition: color 0.2s;
        }
        
        .toc a:hover {
            color: var(--accent2);
        }
        
        /* Sections */
        .section {
            padding: 60px 40px;
            page-break-inside: avoid;
            border-bottom: 1px solid var(--border);
        }
        
        .section-title {
            font-size: 2.2em;
            color: var(--accent2);
            margin-bottom: 35px;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .section-title::before {
            content: '';
            width: 6px;
            height: 45px;
            background: linear-gradient(180deg, var(--accent), var(--accent2));
            border-radius: 5px;
        }
        
        /* Executive Summary */
        .exec-summary {
            background: linear-gradient(135deg, rgba(124,106,245,0.05) 0%, rgba(167,139,250,0.05) 100%);
            padding: 40px;
            border-radius: 15px;
            border: 1px solid var(--border);
            margin: 30px 0;
        }
        
        .exec-summary h3 {
            color: var(--accent2);
            font-size: 1.5em;
            margin-bottom: 20px;
        }
        
        .exec-summary p {
            font-size: 1.1em;
            line-height: 1.8;
            margin: 15px 0;
            color: var(--text);
        }
        
        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 25px;
            margin: 40px 0;
        }
        
        .stat-card {
            background: var(--bg3);
            border: 1px solid var(--border);
            border-radius: 15px;
            padding: 30px;
            text-align: center;
            transition: transform 0.3s, box-shadow 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(124, 106, 245, 0.3);
        }
        
        .stat-card .label {
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 2px;
            color: var(--text2);
            margin-bottom: 12px;
        }
        
        .stat-card .value {
            font-size: 3.5em;
            font-weight: 800;
            line-height: 1;
        }
        
        .stat-card.critical .value { color: var(--critical); }
        .stat-card.high .value { color: var(--high); }
        .stat-card.medium .value { color: var(--medium); }
        .stat-card.low .value { color: var(--low); }
        .stat-card.info .value { color: var(--info); }
        .stat-card.accent .value { color: var(--accent2); }
        
        /* Risk Meter */
        .risk-meter {
            margin: 40px 0;
            padding: 40px;
            background: var(--bg3);
            border-radius: 15px;
            border: 1px solid var(--border);
        }
        
        .risk-meter h3 {
            color: var(--accent2);
            font-size: 1.5em;
            margin-bottom: 30px;
        }
        
        .risk-bar-container {
            background: rgba(0,0,0,0.3);
            border-radius: 10px;
            height: 40px;
            position: relative;
            overflow: hidden;
        }
        
        .risk-bar {
            height: 100%;
            border-radius: 10px;
            transition: width 1.5s ease;
            position: relative;
        }
        
        .risk-bar::after {
            content: attr(data-label);
            position: absolute;
            right: 20px;
            top: 50%;
            transform: translateY(-50%);
            color: white;
            font-weight: 800;
            font-size: 1.1em;
            text-shadow: 0 2px 4px rgba(0,0,0,0.5);
        }
        
        /* Vulnerability Cards */
        .vuln-list {
            display: flex;
            flex-direction: column;
            gap: 20px;
            margin: 30px 0;
        }
        
        .vuln-card {
            background: var(--bg3);
            border-radius: 12px;
            padding: 25px;
            border-left: 5px solid var(--border);
            transition: box-shadow 0.3s;
        }
        
        .vuln-card:hover {
            box-shadow: 0 5px 20px rgba(0,0,0,0.4);
        }
        
        .vuln-card.critical { border-left-color: var(--critical); }
        .vuln-card.high { border-left-color: var(--high); }
        .vuln-card.medium { border-left-color: var(--medium); }
        .vuln-card.low { border-left-color: var(--low); }
        .vuln-card.info { border-left-color: var(--info); }
        
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 15px;
        }
        
        .vuln-title {
            font-size: 1.2em;
            font-weight: 700;
            color: var(--text);
            flex: 1;
        }
        
        .vuln-badges {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        .badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 700;
            text-transform: uppercase;
        }
        
        .badge.critical { background: rgba(255,45,85,0.2); color: var(--critical); border: 1px solid var(--critical); }
        .badge.high { background: rgba(255,107,53,0.2); color: var(--high); border: 1px solid var(--high); }
        .badge.medium { background: rgba(255,165,2,0.2); color: var(--medium); border: 1px solid var(--medium); }
        .badge.low { background: rgba(38,222,129,0.2); color: var(--low); border: 1px solid var(--low); }
        .badge.info { background: rgba(84,160,255,0.2); color: var(--info); border: 1px solid var(--info); }
        
        .cvss-score {
            background: var(--bg);
            padding: 8px 18px;
            border-radius: 25px;
            font-weight: 800;
            font-size: 1.1em;
        }
        
        .vuln-url {
            font-size: 0.9em;
            color: var(--info);
            margin: 10px 0;
            word-break: break-all;
            font-family: 'Courier New', monospace;
        }
        
        .vuln-description {
            margin: 15px 0;
            color: var(--text2);
            line-height: 1.6;
        }
        
        .vuln-meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
        }
        
        .meta-item {
            display: flex;
            flex-direction: column;
        }
        
        .meta-label {
            font-size: 0.75em;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text2);
            margin-bottom: 5px;
        }
        
        .meta-value {
            font-weight: 600;
            color: var(--text);
        }
        
        /* Tables */
        .data-table {
            width: 100%;
            border-collapse: collapse;
            margin: 30px 0;
            background: var(--bg3);
            border-radius: 10px;
            overflow: hidden;
        }
        
        .data-table thead {
            background: linear-gradient(135deg, rgba(124,106,245,0.2) 0%, rgba(167,139,250,0.2) 100%);
        }
        
        .data-table th {
            padding: 15px;
            text-align: left;
            color: var(--accent2);
            font-weight: 700;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 1px;
        }
        
        .data-table td {
            padding: 15px;
            border-top: 1px solid var(--border);
        }
        
        .data-table tr:hover {
            background: rgba(124, 106, 245, 0.05);
        }
        
        /* Charts */
        .chart-container {
            margin: 40px 0;
            padding: 30px;
            background: var(--bg3);
            border-radius: 15px;
            border: 1px solid var(--border);
        }
        
        .chart-title {
            font-size: 1.3em;
            color: var(--accent2);
            margin-bottom: 25px;
            font-weight: 700;
        }
        
        /* Code Blocks */
        .code-block {
            background: #0a0a14;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            margin: 15px 0;
            overflow-x: auto;
        }
        
        .code-block pre {
            font-family: 'Courier New', Monaco, monospace;
            font-size: 0.9em;
            color: #a8ff78;
            line-height: 1.5;
        }
        
        /* Remediation Cards */
        .remediation-card {
            background: var(--bg3);
            border-radius: 12px;
            padding: 25px;
            margin: 20px 0;
            border-left: 5px solid var(--accent);
        }
        
        .remediation-card h4 {
            color: var(--accent2);
            font-size: 1.2em;
            margin-bottom: 15px;
        }
        
        .remediation-card .priority {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 700;
            margin-bottom: 15px;
        }
        
        .priority.p1 { background: rgba(255,45,85,0.2); color: var(--critical); }
        .priority.p2 { background: rgba(255,107,53,0.2); color: var(--high); }
        .priority.p3 { background: rgba(255,165,2,0.2); color: var(--medium); }
        
        /* Print Styles */
        @media print {
            body { background: white; color: black; }
            .container { background: white; }
            .section { page-break-inside: avoid; }
            .cover { page-break-after: always; }
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .cover h1 { font-size: 2.5em; }
            .section { padding: 30px 20px; }
            .stats-grid { grid-template-columns: 1fr; }
        }
        """
    
    # ══════════════════════════════════════════════════════════════════════
    # JAVASCRIPT
    # ══════════════════════════════════════════════════════════════════════
    
    def _get_javascript(self) -> str:
        return """
        // Animate risk bars on load
        window.addEventListener('load', () => {
            document.querySelectorAll('.risk-bar[data-width]').forEach(bar => {
                setTimeout(() => {
                    bar.style.width = bar.dataset.width + '%';
                }, 100);
            });
        });
        
        // Smooth scroll for TOC links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function(e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            });
        });
        """
    
    # ══════════════════════════════════════════════════════════════════════
    # REPORT SECTIONS
    # ══════════════════════════════════════════════════════════════════════
    
    def _build_cover_page(self) -> str:
        scan_date = datetime.fromisoformat(self.scan_time).strftime('%B %d, %Y')
        duration_min = self.scan_duration / 60 if self.scan_duration else 0
        
        return f"""
        <div class="cover">
            <div class="cover-content">
                <h1>🛡️ PENETRATION TEST REPORT</h1>
                <div class="subtitle">Professional Security Assessment</div>
                <div class="target">{self.domain}</div>
                <div class="meta">
                    <p><strong>Assessment Date:</strong> {scan_date}</p>
                    <p><strong>Duration:</strong> {duration_min:.1f} minutes</p>
                    <p><strong>Methodology:</strong> OWASP Testing Guide v4.2 + PTES</p>
                    <p><strong>Framework:</strong> LX-BOT Ultimate v5.0</p>
                    <p><strong>Classification:</strong> CONFIDENTIAL</p>
                </div>
            </div>
        </div>
        """
    
    def _build_toc(self) -> str:
        return """
        <div class="toc section">
            <h2>📋 Table of Contents</h2>
            <ul>
                <li><a href="#executive-summary">1. Executive Summary</a></li>
                <li><a href="#risk-overview">2. Risk Overview & Scoring</a></li>
                <li><a href="#cvss-distribution">3. CVSS Distribution Analysis</a></li>
                <li><a href="#findings-summary">4. Findings Summary</a></li>
                <li><a href="#vulnerability-details">5. Vulnerability Details</a></li>
                <li><a href="#network-findings">6. Network & Infrastructure Findings</a></li>
                <li><a href="#web-findings">7. Web Application Findings</a></li>
                <li><a href="#injection-findings">8. Injection Vulnerabilities</a></li>
                <li><a href="#exploitation">9. Exploitation & Proof of Concept</a></li>
                <li><a href="#osint">10. OSINT & Intelligence Findings</a></li>
                <li><a href="#remediation">11. Remediation Roadmap</a></li>
                <li><a href="#compliance">12. Compliance Mapping</a></li>
                <li><a href="#appendix">13. Appendix</a></li>
            </ul>
        </div>
        """
    
    def _build_executive_summary(self) -> str:
        total_vulns = self.stats.get('vulnerabilities_found', 0)
        critical = self.stats.get('critical', 0)
        high = self.stats.get('high', 0)
        medium = self.stats.get('medium', 0)
        
        risk_score = critical * 10 + high * 5 + medium * 2 + self.stats.get('low', 0)
        
        if risk_score >= 50:
            risk_level = 'CRITICAL'
            risk_desc = 'immediate attention and remediation'
        elif risk_score >= 20:
            risk_level = 'HIGH'
            risk_desc = 'urgent remediation within 48-72 hours'
        elif risk_score >= 10:
            risk_level = 'MEDIUM'
            risk_desc = 'timely remediation within 1-2 weeks'
        else:
            risk_level = 'LOW'
            risk_desc = 'standard security improvements'
        
        return f"""
        <div id="executive-summary" class="section">
            <div class="section-title">📊 Executive Summary</div>
            
            <div class="exec-summary">
                <h3>Assessment Overview</h3>
                <p>
                    This penetration testing engagement was conducted against <strong>{self.target}</strong> 
                    using industry-standard methodologies including the OWASP Testing Guide v4.2 and the 
                    Penetration Testing Execution Standard (PTES). The assessment identified 
                    <strong>{total_vulns} security findings</strong> across multiple attack vectors.
                </p>
                
                <h3 style="margin-top: 30px;">Key Findings</h3>
                <p>
                    The security posture of the target environment has been assessed as 
                    <strong style="color: var(--{risk_level.lower()})">{risk_level} RISK</strong>, 
                    requiring {risk_desc}. The assessment identified:
                </p>
                <ul style="margin: 20px 0 20px 30px; line-height: 2;">
                    <li><strong style="color: var(--critical)">{critical} Critical</strong> severity vulnerabilities requiring immediate action</li>
                    <li><strong style="color: var(--high)">{high} High</strong> severity vulnerabilities with significant impact</li>
                    <li><strong style="color: var(--medium)">{medium} Medium</strong> severity issues requiring timely remediation</li>
                    <li><strong>{self.stats.get('low', 0)} Low</strong> severity findings for security hardening</li>
                </ul>
                
                <h3 style="margin-top: 30px;">Critical Recommendations</h3>
                <p>
                    Based on the findings, the following actions are recommended as immediate priorities:
                </p>
                <ol style="margin: 20px 0 20px 30px; line-height: 2;">
                    <li>Address all Critical and High severity vulnerabilities within 24-72 hours</li>
                    <li>Implement a vulnerability management program with regular scanning</li>
                    <li>Conduct security awareness training for development and operations teams</li>
                    <li>Establish a secure software development lifecycle (SSDLC)</li>
                </ol>
            </div>
        </div>
        """
    
    def _build_risk_overview(self) -> str:
        risk_score = (
            self.stats.get('critical', 0) * 10 +
            self.stats.get('high', 0) * 5 +
            self.stats.get('medium', 0) * 2 +
            self.stats.get('low', 0)
        )
        risk_pct = min(risk_score * 2, 100)
        
        if risk_score >= 50:
            risk_color = '#ff2d55'
            risk_label = 'CRITICAL RISK'
        elif risk_score >= 20:
            risk_color = '#ff6b35'
            risk_label = 'HIGH RISK'
        elif risk_score >= 10:
            risk_color = '#ffa502'
            risk_label = 'MEDIUM RISK'
        else:
            risk_color = '#26de81'
            risk_label = 'LOW RISK'
        
        cards_html = ''
        for label, count, css_class in [
            ('Total Findings', self.stats.get('vulnerabilities_found', 0), 'info'),
            ('Critical', self.stats.get('critical', 0), 'critical'),
            ('High', self.stats.get('high', 0), 'high'),
            ('Medium', self.stats.get('medium', 0), 'medium'),
            ('Low', self.stats.get('low', 0), 'low'),
            ('Subdomains', len(self.results.get('subdomains', [])), 'accent'),
            ('Endpoints', len(self.results.get('api_endpoints', [])), 'accent'),
            ('Open Ports', len(self.results.get('nmap', {}).get('ports', [])), 'accent'),
        ]:
            cards_html += f'<div class="stat-card {css_class}"><div class="label">{label}</div><div class="value">{count}</div></div>'
        
        return f"""
        <div id="risk-overview" class="section">
            <div class="section-title">🎯 Risk Overview & Scoring</div>
            
            <div class="stats-grid">{cards_html}</div>
            
            <div class="risk-meter">
                <h3>Overall Risk Assessment</h3>
                <div class="risk-bar-container">
                    <div class="risk-bar" data-width="{risk_pct}" data-label="{risk_label}" 
                         style="width: 0%; background: {risk_color};"></div>
                </div>
                <p style="margin-top: 20px; color: var(--text2);">
                    <strong>Risk Score:</strong> {risk_score} / 100 
                    <span style="margin-left: 30px;"><strong>Severity:</strong> 
                    <span style="color: {risk_color}; font-weight: 800;">{risk_label}</span></span>
                </p>
            </div>
        </div>
        """
    
    def _build_cvss_distribution(self) -> str:
        # Prepare data for Plotly charts
        cvss_scores = [v.get('cvss_score', 0) for v in self.all_vulnerabilities]
        severities = [v.get('cvss_severity', 'Unknown') for v in self.all_vulnerabilities]
        
        severity_counts = {
            'Critical': severities.count('Critical'),
            'High': severities.count('High'),
            'Medium': severities.count('Medium'),
            'Low': severities.count('Low'),
            'None': severities.count('None'),
        }
        
        # Plotly Pie Chart data
        pie_data = {
            'labels': list(severity_counts.keys()),
            'values': list(severity_counts.values()),
            'colors': ['#ff2d55', '#ff6b35', '#ffa502', '#26de81', '#54a0ff']
        }
        
        # CVSS score histogram data
        score_ranges = {
            '0.0-3.9': sum(1 for s in cvss_scores if 0 <= s < 4),
            '4.0-6.9': sum(1 for s in cvss_scores if 4 <= s < 7),
            '7.0-8.9': sum(1 for s in cvss_scores if 7 <= s < 9),
            '9.0-10.0': sum(1 for s in cvss_scores if s >= 9),
        }
        
        return f"""
        <div id="cvss-distribution" class="section">
            <div class="section-title">📈 CVSS Distribution Analysis</div>
            
            <div class="chart-container">
                <div class="chart-title">Vulnerability Severity Distribution</div>
                <div id="severityPieChart" style="height: 400px;"></div>
            </div>
            
            <div class="chart-container">
                <div class="chart-title">CVSS Score Distribution</div>
                <div id="cvssHistogram" style="height: 400px;"></div>
            </div>
            
            <script>
                // Severity Pie Chart
                Plotly.newPlot('severityPieChart', [{{
                    values: {pie_data['values']},
                    labels: {pie_data['labels']},
                    type: 'pie',
                    hole: 0.4,
                    marker: {{
                        colors: {pie_data['colors']},
                        line: {{ color: '#0a0a15', width: 2 }}
                    }},
                    textinfo: 'label+percent',
                    textfont: {{ size: 14, color: '#ffffff' }},
                    hovertemplate: '<b>%{{label}}</b><br>Count: %{{value}}<br>%{{percent}}<extra></extra>'
                }}], {{
                    paper_bgcolor: 'rgba(0,0,0,0)',
                    plot_bgcolor: 'rgba(0,0,0,0)',
                    font: {{ color: '#e0e0f0' }},
                    showlegend: true,
                    legend: {{ orientation: 'h', y: -0.1 }}
                }}, {{responsive: true}});
                
                // CVSS Score Histogram
                Plotly.newPlot('cvssHistogram', [{{
                    x: {list(score_ranges.keys())},
                    y: {list(score_ranges.values())},
                    type: 'bar',
                    marker: {{
                        color: ['#26de81', '#ffa502', '#ff6b35', '#ff2d55'],
                        line: {{ color: '#0a0a15', width: 2 }}
                    }},
                    text: {list(score_ranges.values())},
                    textposition: 'auto',
                    textfont: {{ size: 16, color: '#ffffff', weight: 'bold' }},
                    hovertemplate: '<b>Score Range: %{{x}}</b><br>Count: %{{y}}<extra></extra>'
                }}], {{
                    paper_bgcolor: 'rgba(0,0,0,0)',
                    plot_bgcolor: 'rgba(0,0,0,0)',
                    font: {{ color: '#e0e0f0', size: 12 }},
                    xaxis: {{ title: 'CVSS Score Range', gridcolor: 'rgba(255,255,255,0.1)' }},
                    yaxis: {{ title: 'Number of Vulnerabilities', gridcolor: 'rgba(255,255,255,0.1)' }},
                    showlegend: false
                }}, {{responsive: true}});
            </script>
        </div>
        """
    
    def _build_findings_summary(self) -> str:
        # Top 10 most critical vulnerabilities
        top_vulns = sorted(self.all_vulnerabilities, key=lambda x: x.get('cvss_score', 0), reverse=True)[:10]
        
        table_rows = ''
        for idx, vuln in enumerate(top_vulns, 1):
            cvss_score = vuln.get('cvss_score', 0)
            severity = vuln.get('cvss_severity', 'Unknown')
            name = self._esc(vuln.get('name', 'Unknown'))[:60]
            url = self._esc(vuln.get('url', 'N/A'))[:80]
            
            severity_color = {
                'Critical': 'var(--critical)',
                'High': 'var(--high)',
                'Medium': 'var(--medium)',
                'Low': 'var(--low)',
            }.get(severity, 'var(--text2)')
            
            table_rows += f"""
            <tr>
                <td><strong>{idx}</strong></td>
                <td>{name}</td>
                <td style="color: {severity_color}; font-weight: 700;">{severity}</td>
                <td style="color: var(--accent2); font-weight: 800;">{cvss_score:.1f}</td>
                <td style="font-size: 0.85em; font-family: monospace;">{url}</td>
            </tr>
            """
        
        return f"""
        <div id="findings-summary" class="section">
            <div class="section-title">🔍 Top 10 Critical Findings</div>
            
            <table class="data-table">
                <thead>
                    <tr>
                        <th style="width: 50px;">#</th>
                        <th>Vulnerability</th>
                        <th style="width: 120px;">Severity</th>
                        <th style="width: 100px;">CVSS</th>
                        <th>Location</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows if table_rows else '<tr><td colspan="5" style="text-align: center; padding: 40px;">No vulnerabilities found</td></tr>'}
                </tbody>
            </table>
        </div>
        """
    
    def _build_vulnerability_details(self) -> str:
        if not self.all_vulnerabilities:
            return ''
        
        vuln_cards = ''
        for vuln in self.all_vulnerabilities[:50]:  # Top 50 for report
            cvss_score = vuln.get('cvss_score', 0)
            severity = vuln.get('cvss_severity', 'Unknown').lower()
            name = self._esc(vuln.get('name', 'Unknown Vulnerability'))
            url = self._esc(vuln.get('url', 'N/A'))
            desc = self._esc(str(vuln.get('description', 'No description available'))[:500])
            template = self._esc(vuln.get('template', 'N/A'))
            
            # CVSS vector
            cvss_vector = vuln.get('cvss_vector', {})
            vector_str = '/'.join([f'{k}:{v}' for k, v in cvss_vector.items()]) if cvss_vector else 'N/A'
            
            # OWASP Top 10 mapping
            owasp = self._map_to_owasp(name)
            cwe = self._map_to_cwe(name)
            
            vuln_cards += f"""
            <div class="vuln-card {severity}">
                <div class="vuln-header">
                    <div class="vuln-title">{name}</div>
                    <div class="vuln-badges">
                        <span class="badge {severity}">{severity.upper()}</span>
                        <span class="cvss-score" style="color: var(--{severity})">CVSS {cvss_score:.1f}</span>
                    </div>
                </div>
                
                <div class="vuln-url">📍 {url}</div>
                <div class="vuln-description">{desc}</div>
                
                <div class="vuln-meta">
                    <div class="meta-item">
                        <span class="meta-label">Template ID</span>
                        <span class="meta-value">{template}</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">CVSS Vector</span>
                        <span class="meta-value" style="font-family: monospace; font-size: 0.85em;">{vector_str}</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">OWASP Top 10</span>
                        <span class="meta-value">{owasp}</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">CWE</span>
                        <span class="meta-value">{cwe}</span>
                    </div>
                </div>
            </div>
            """
        
        return f"""
        <div id="vulnerability-details" class="section">
            <div class="section-title">🚨 Detailed Vulnerability Analysis</div>
            <div class="vuln-list">{vuln_cards}</div>
        </div>
        """
    
    def _build_network_findings(self) -> str:
        nmap = self.results.get('nmap', {})
        ports = nmap.get('ports', [])
        service_vulns = self.results.get('service_vulns', [])
        
        if not ports and not service_vulns:
            return ''
        
        port_rows = ''
        for port in ports[:30]:
            port_rows += f"""
            <tr>
                <td><strong>{port.get('port', '?')}/{port.get('protocol', 'tcp')}</strong></td>
                <td>{port.get('state', 'unknown')}</td>
                <td>{self._esc(port.get('service', 'unknown'))}</td>
                <td>{self._esc(port.get('product', ''))} {self._esc(port.get('version', ''))}</td>
            </tr>
            """
        
        vuln_cards = ''
        for svc_vuln in service_vulns[:20]:
            vuln_cards += f"""
            <div class="vuln-card high">
                <div class="vuln-header">
                    <div class="vuln-title">Service Vulnerability: {self._esc(svc_vuln.get('script', 'Unknown'))}</div>
                    <span class="badge high">HIGH</span>
                </div>
                <div class="code-block">
                    <pre>{self._esc(str(svc_vuln.get('output', ''))[:600])}</pre>
                </div>
            </div>
            """
        
        return f"""
        <div id="network-findings" class="section">
            <div class="section-title">🌐 Network & Infrastructure Findings</div>
            
            <h3 style="color: var(--accent2); margin: 30px 0 20px 0;">Open Ports & Services</h3>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>State</th>
                        <th>Service</th>
                        <th>Version</th>
                    </tr>
                </thead>
                <tbody>
                    {port_rows if port_rows else '<tr><td colspan="4" style="text-align: center; padding: 30px;">No open ports detected</td></tr>'}
                </tbody>
            </table>
            
            {f'<h3 style="color: var(--accent2); margin: 40px 0 20px 0;">Service Vulnerabilities</h3><div class="vuln-list">{vuln_cards}</div>' if vuln_cards else ''}
        </div>
        """
    
    def _build_web_findings(self) -> str:
        headers = self.results.get('security_headers', {})
        cors = self.results.get('cors_misconfig', [])
        cookies = self.results.get('cookies', [])
        
        missing_headers = headers.get('missing', [])
        header_rows = ''
        for hdr in missing_headers:
            header_rows += f'<tr><td>{self._esc(hdr)}</td><td style="color: var(--critical);">✗ Missing</td><td>Should be implemented for security hardening</td></tr>'
        
        for hdr, val in headers.get('present', {}).items():
            header_rows += f'<tr><td>{self._esc(hdr)}</td><td style="color: var(--low);">✓ Present</td><td style="font-family: monospace; font-size: 0.85em;">{self._esc(str(val)[:60])}</td></tr>'
        
        cors_items = ''
        for c in cors[:10]:
            cors_items += f'<div class="vuln-card high"><div class="vuln-title">CORS Misconfiguration</div><div class="vuln-description">{self._esc(str(c))}</div></div>'
        
        return f"""
        <div id="web-findings" class="section">
            <div class="section-title">🕸️ Web Application Findings</div>
            
            <h3 style="color: var(--accent2); margin: 30px 0 20px 0;">Security Headers Analysis</h3>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Header</th>
                        <th>Status</th>
                        <th>Value / Recommendation</th>
                    </tr>
                </thead>
                <tbody>
                    {header_rows if header_rows else '<tr><td colspan="3" style="text-align: center; padding: 30px;">No header analysis available</td></tr>'}
                </tbody>
            </table>
            
            {f'<h3 style="color: var(--accent2); margin: 40px 0 20px 0;">CORS Misconfigurations</h3><div class="vuln-list">{cors_items}</div>' if cors_items else ''}
        </div>
        """
    
    def _build_injection_findings(self) -> str:
        xss = self.results.get('xss_results', [])
        sqli = self.results.get('sqli_results', [])
        cmdi = self.results.get('command_injection', [])
        ssti = self.results.get('ssti_results', [])
        
        if not any([xss, sqli, cmdi, ssti]):
            return ''
        
        injection_cards = ''
        
        for x in xss[:10]:
            url = self._esc(str(x.get('url', x) if isinstance(x, dict) else x))
            details = self._esc(str(x.get('details', ''))[:400]) if isinstance(x, dict) else ''
            injection_cards += f"""
            <div class="vuln-card high">
                <div class="vuln-header">
                    <div class="vuln-title">Cross-Site Scripting (XSS)</div>
                    <span class="badge high">HIGH</span>
                    <span class="cvss-score" style="color: var(--high)">CVSS 6.5</span>
                </div>
                <div class="vuln-url">📍 {url}</div>
                <div class="vuln-description">{details if details else 'XSS vulnerability detected. User input is reflected without proper encoding.'}</div>
            </div>
            """
        
        for s in sqli[:10]:
            url = self._esc(str(s.get('url', s) if isinstance(s, dict) else s))
            details = self._esc(str(s.get('details', ''))[:400]) if isinstance(s, dict) else ''
            injection_cards += f"""
            <div class="vuln-card critical">
                <div class="vuln-header">
                    <div class="vuln-title">SQL Injection</div>
                    <span class="badge critical">CRITICAL</span>
                    <span class="cvss-score" style="color: var(--critical)">CVSS 9.8</span>
                </div>
                <div class="vuln-url">📍 {url}</div>
                <div class="vuln-description">{details if details else 'SQL injection vulnerability allows database manipulation and data exfiltration.'}</div>
            </div>
            """
        
        for c in cmdi[:10]:
            url = self._esc(str(c.get('url', c) if isinstance(c, dict) else c))
            injection_cards += f"""
            <div class="vuln-card critical">
                <div class="vuln-header">
                    <div class="vuln-title">Command Injection</div>
                    <span class="badge critical">CRITICAL</span>
                    <span class="cvss-score" style="color: var(--critical)">CVSS 9.8</span>
                </div>
                <div class="vuln-url">📍 {url}</div>
                <div class="vuln-description">OS command injection allows arbitrary command execution on the server.</div>
            </div>
            """
        
        return f"""
        <div id="injection-findings" class="section">
            <div class="section-title">💉 Injection Vulnerabilities</div>
            <div class="vuln-list">{injection_cards}</div>
        </div>
        """
    
    def _build_exploitation_findings(self) -> str:
        exploits = self.results.get('exploits', [])
        cves = self.results.get('cves', [])
        msf_modules = self.results.get('metasploit_modules', [])
        
        if not any([exploits, cves, msf_modules]):
            return ''
        
        content = ''
        
        for exp in exploits[:15]:
            search_term = self._esc(exp.get('search_term', 'Unknown'))
            count = exp.get('count', 0)
            exp_list = exp.get('exploits', [])[:5]
            
            exp_items = ''
            for e in exp_list:
                if isinstance(e, dict):
                    edb_id = e.get('EDB-ID', '?')
                    title = self._esc(str(e.get('Title', ''))[:80])
                    exp_items += f'<tr><td><strong>{edb_id}</strong></td><td>{title}</td></tr>'
            
            content += f"""
            <div class="remediation-card">
                <h4>🎯 {search_term} ({count} exploits available)</h4>
                <table class="data-table" style="margin-top: 15px;">
                    <thead><tr><th style="width: 100px;">EDB-ID</th><th>Title</th></tr></thead>
                    <tbody>{exp_items if exp_items else '<tr><td colspan="2">No exploits listed</td></tr>'}</tbody>
                </table>
            </div>
            """
        
        for msf in msf_modules[:10]:
            module_name = self._esc(msf.get('module', 'Unknown'))
            rank = msf.get('rank', 'unknown')
            content += f"""
            <div class="vuln-card high">
                <div class="vuln-header">
                    <div class="vuln-title">Metasploit Module: {module_name}</div>
                    <span class="badge high">Rank: {rank.upper()}</span>
                </div>
                <div class="vuln-description">Metasploit exploit module available for this service/vulnerability.</div>
            </div>
            """
        
        return f"""
        <div id="exploitation" class="section">
            <div class="section-title">🗃️ Exploitation & Proof of Concept</div>
            {content}
        </div>
        """
    
    def _build_osint_findings(self) -> str:
        emails = self.results.get('emails', [])
        github = self.results.get('github_leaks', [])
        s3 = self.results.get('s3_buckets', [])
        
        if not any([emails, github, s3]):
            return ''
        
        email_items = ''.join([f'<li style="padding: 10px; background: var(--bg3); margin: 5px 0; border-radius: 5px;">📧 {self._esc(e)}</li>' for e in emails[:30]])
        
        github_items = ''
        for g in github[:15]:
            github_items += f"""
            <div class="vuln-card high">
                <div class="vuln-header">
                    <div class="vuln-title">GitHub Secret Leak</div>
                    <span class="badge high">HIGH</span>
                </div>
                <div class="code-block"><pre>{self._esc(str(g)[:300])}</pre></div>
            </div>
            """
        
        s3_items = ''.join([f'<li style="padding: 15px; background: var(--bg3); margin: 10px 0; border-radius: 8px; border-left: 4px solid var(--critical);">🪣 <strong>{self._esc(bucket)}</strong> - Publicly accessible S3 bucket</li>' for bucket in s3])
        
        return f"""
        <div id="osint" class="section">
            <div class="section-title">🕵️ OSINT & Intelligence Findings</div>
            
            {f'<h3 style="color: var(--accent2); margin: 30px 0 20px 0;">Email Addresses ({len(emails)})</h3><ul style="list-style: none;">{email_items}</ul>' if email_items else ''}
            {f'<h3 style="color: var(--accent2); margin: 40px 0 20px 0;">GitHub Leaked Secrets</h3><div class="vuln-list">{github_items}</div>' if github_items else ''}
            {f'<h3 style="color: var(--accent2); margin: 40px 0 20px 0;">Exposed Cloud Storage</h3><ul style="list-style: none;">{s3_items}</ul>' if s3_items else ''}
        </div>
        """
    
    def _build_remediation_roadmap(self) -> str:
        # Priority-based remediation
        critical_vulns = [v for v in self.all_vulnerabilities if v.get('cvss_severity') == 'Critical']
        high_vulns = [v for v in self.all_vulnerabilities if v.get('cvss_severity') == 'High']
        medium_vulns = [v for v in self.all_vulnerabilities if v.get('cvss_severity') == 'Medium']
        
        roadmap = ''
        
        if critical_vulns:
            roadmap += f"""
            <div class="remediation-card" style="border-left-color: var(--critical);">
                <span class="priority p1">PRIORITY 1 - IMMEDIATE (0-24 hours)</span>
                <h4>Critical Severity Issues ({len(critical_vulns)})</h4>
                <ul style="margin: 15px 0 0 20px; line-height: 2;">
                    <li>Address all SQL injection, RCE, and authentication bypass vulnerabilities</li>
                    <li>Patch exposed sensitive files (.git, .env, config files)</li>
                    <li>Rotate all exposed credentials and API keys immediately</li>
                    <li>Implement emergency WAF rules to block active exploitation</li>
                </ul>
            </div>
            """
        
        if high_vulns:
            roadmap += f"""
            <div class="remediation-card" style="border-left-color: var(--high);">
                <span class="priority p2">PRIORITY 2 - URGENT (24-72 hours)</span>
                <h4>High Severity Issues ({len(high_vulns)})</h4>
                <ul style="margin: 15px 0 0 20px; line-height: 2;">
                    <li>Fix XSS vulnerabilities with proper input validation and output encoding</li>
                    <li>Remediate CORS misconfigurations</li>
                    <li>Secure exposed administrative interfaces</li>
                    <li>Update vulnerable software components identified by Nmap/Nuclei</li>
                </ul>
            </div>
            """
        
        if medium_vulns:
            roadmap += f"""
            <div class="remediation-card" style="border-left-color: var(--medium);">
                <span class="priority p3">PRIORITY 3 - STANDARD (1-2 weeks)</span>
                <h4>Medium Severity Issues ({len(medium_vulns)})</h4>
                <ul style="margin: 15px 0 0 20px; line-height: 2;">
                    <li>Implement missing security headers (CSP, HSTS, X-Frame-Options)</li>
                    <li>Fix IDOR and open redirect vulnerabilities</li>
                    <li>Harden cookie security (HttpOnly, Secure, SameSite flags)</li>
                    <li>Conduct code review for business logic flaws</li>
                </ul>
            </div>
            """
        
        roadmap += """
        <div class="remediation-card">
            <h4>Long-Term Security Improvements</h4>
            <ul style="margin: 15px 0 0 20px; line-height: 2;">
                <li>Implement a secure SDLC (Software Development Lifecycle)</li>
                <li>Deploy SAST/DAST tools in CI/CD pipeline</li>
                <li>Conduct regular penetration tests (quarterly recommended)</li>
                <li>Establish a bug bounty program</li>
                <li>Provide security awareness training to all developers</li>
            </ul>
        </div>
        """
        
        return f"""
        <div id="remediation" class="section">
            <div class="section-title">🛠️ Remediation Roadmap</div>
            {roadmap}
        </div>
        """
    
    def _build_compliance_mapping(self) -> str:
        # Map findings to OWASP Top 10 2021
        owasp_mapping = {
            'A01:2021 - Broken Access Control': len([v for v in self.all_vulnerabilities if 'idor' in str(v.get('name', '')).lower() or 'access control' in str(v.get('name', '')).lower()]),
            'A02:2021 - Cryptographic Failures': len([v for v in self.all_vulnerabilities if 'ssl' in str(v.get('name', '')).lower() or 'tls' in str(v.get('name', '')).lower() or 'encryption' in str(v.get('name', '')).lower()]),
            'A03:2021 - Injection': len([v for v in self.all_vulnerabilities if any(x in str(v.get('name', '')).lower() for x in ['sql', 'xss', 'command', 'ldap', 'xpath'])]),
            'A04:2021 - Insecure Design': len([v for v in self.all_vulnerabilities if 'logic' in str(v.get('name', '')).lower() or 'race' in str(v.get('name', '')).lower()]),
            'A05:2021 - Security Misconfiguration': len([v for v in self.all_vulnerabilities if any(x in str(v.get('name', '')).lower() for x in ['misconfiguration', 'exposed', 'default', 'cors'])]),
            'A06:2021 - Vulnerable Components': len([v for v in self.all_vulnerabilities if 'cve' in str(v.get('name', '')).lower() or 'outdated' in str(v.get('name', '')).lower()]),
            'A07:2021 - Authentication Failures': len([v for v in self.all_vulnerabilities if 'auth' in str(v.get('name', '')).lower() or 'session' in str(v.get('name', '')).lower()]),
            'A08:2021 - Data Integrity Failures': len([v for v in self.all_vulnerabilities if 'deserialization' in str(v.get('name', '')).lower()]),
            'A09:2021 - Security Logging Failures': 0,  # Would require specific detection
            'A10:2021 - SSRF': len([v for v in self.all_vulnerabilities if 'ssrf' in str(v.get('name', '')).lower()]),
        }
        
        owasp_rows = ''
        for category, count in owasp_mapping.items():
            color = 'var(--critical)' if count > 5 else 'var(--high)' if count > 2 else 'var(--medium)' if count > 0 else 'var(--low)'
            owasp_rows += f'<tr><td>{category}</td><td style="color: {color}; font-weight: 700;">{count}</td></tr>'
        
        return f"""
        <div id="compliance" class="section">
            <div class="section-title">📋 Compliance Mapping</div>
            
            <h3 style="color: var(--accent2); margin: 30px 0 20px 0;">OWASP Top 10 2021</h3>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Category</th>
                        <th style="width: 150px;">Findings</th>
                    </tr>
                </thead>
                <tbody>{owasp_rows}</tbody>
            </table>
        </div>
        """
    
    def _build_appendix(self) -> str:
        return f"""
        <div id="appendix" class="section">
            <div class="section-title">📚 Appendix</div>
            
            <h3 style="color: var(--accent2); margin: 30px 0 20px 0;">Methodology</h3>
            <p style="line-height: 1.8;">
                This assessment was conducted following industry-standard methodologies including:
            </p>
            <ul style="margin: 15px 0 0 30px; line-height: 2;">
                <li>OWASP Testing Guide v4.2</li>
                <li>Penetration Testing Execution Standard (PTES)</li>
                <li>NIST SP 800-115 Technical Guide to Information Security Testing</li>
                <li>MITRE ATT&CK Framework</li>
            </ul>
            
            <h3 style="color: var(--accent2); margin: 40px 0 20px 0;">Tools Used</h3>
            <p style="line-height: 1.8;">
                The following tools were utilized during this assessment:
            </p>
            <ul style="margin: 15px 0 0 30px; line-height: 2;">
                <li>Metasploit Framework - Exploitation and post-exploitation</li>
                <li>Nmap - Network discovery and vulnerability scanning</li>
                <li>Nuclei - Template-based vulnerability scanner</li>
                <li>SQLmap - SQL injection detection and exploitation</li>
                <li>Dalfox - XSS scanning</li>
                <li>WPScan / JoomScan / DroopeScan - CMS-specific scanners</li>
                <li>And 40+ additional specialized tools</li>
            </ul>
            
            <h3 style="color: var(--accent2); margin: 40px 0 20px 0;">Disclaimer</h3>
            <p style="line-height: 1.8; color: var(--text2);">
                This penetration test report is provided for informational and security improvement purposes only.
                The findings represent the security state at the time of testing and should not be considered
                comprehensive or exhaustive. The client is responsible for implementing recommended remediations
                and maintaining ongoing security practices.
            </p>
            
            <div style="margin-top: 60px; padding: 30px; background: var(--bg3); border-radius: 10px; border: 1px solid var(--border);">
                <p style="text-align: center; color: var(--text2);">
                    <strong>Report Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}<br>
                    <strong>Framework:</strong> LX-BOT Ultimate v5.0<br>
                    <strong>Classification:</strong> CONFIDENTIAL - FOR AUTHORIZED USE ONLY
                </p>
            </div>
        </div>
        """
    
    # ══════════════════════════════════════════════════════════════════════
    # UTILITY METHODS
    # ══════════════════════════════════════════════════════════════════════
    
    @staticmethod
    def _esc(text: str) -> str:
        """HTML escape text"""
        return html_module.escape(str(text))
    
    @staticmethod
    def _map_to_owasp(vuln_name: str) -> str:
        """Map vulnerability to OWASP Top 10 2021"""
        name_lower = str(vuln_name).lower()
        
        if any(x in name_lower for x in ['sql', 'xss', 'command', 'ldap', 'xpath', 'template', 'ssti']):
            return 'A03:2021 - Injection'
        elif any(x in name_lower for x in ['idor', 'access control', 'authorization']):
            return 'A01:2021 - Broken Access Control'
        elif any(x in name_lower for x in ['auth', 'session', 'credential']):
            return 'A07:2021 - Authentication Failures'
        elif any(x in name_lower for x in ['misconfiguration', 'exposed', 'cors', 'header']):
            return 'A05:2021 - Security Misconfiguration'
        elif any(x in name_lower for x in ['cve', 'outdated', 'vulnerable component']):
            return 'A06:2021 - Vulnerable Components'
        elif 'ssrf' in name_lower:
            return 'A10:2021 - SSRF'
        elif any(x in name_lower for x in ['ssl', 'tls', 'crypto', 'encryption']):
            return 'A02:2021 - Cryptographic Failures'
        elif 'deserialization' in name_lower:
            return 'A08:2021 - Data Integrity Failures'
        else:
            return 'A04:2021 - Insecure Design'
    
    @staticmethod
    def _map_to_cwe(vuln_name: str) -> str:
        """Map vulnerability to CWE"""
        name_lower = str(vuln_name).lower()
        
        if 'sql' in name_lower:
            return 'CWE-89'
        elif 'xss' in name_lower or 'cross-site scripting' in name_lower:
            return 'CWE-79'
        elif 'command injection' in name_lower:
            return 'CWE-78'
        elif 'xxe' in name_lower:
            return 'CWE-611'
        elif 'ssrf' in name_lower:
            return 'CWE-918'
        elif 'path traversal' in name_lower or 'lfi' in name_lower:
            return 'CWE-22'
        elif 'csrf' in name_lower:
            return 'CWE-352'
        elif 'idor' in name_lower:
            return 'CWE-639'
        elif 'ssti' in name_lower or 'template injection' in name_lower:
            return 'CWE-94'
        elif 'auth' in name_lower:
            return 'CWE-287'
        else:
            return 'CWE-Other'


# Backward compatibility alias
ReportGenerator = UltimateReportGenerator


def main():
    """Self-test with sample data"""
    sample_results = {
        'target': 'https://example.com',
        'domain': 'example.com',
        'scan_time': datetime.now().isoformat(),
        'scan_duration': 3600,
        'subdomains': ['www.example.com', 'api.example.com', 'admin.example.com'],
        'live_hosts': ['https://www.example.com', 'https://api.example.com'],
        'dns_records': {'A': ['93.184.216.34'], 'MX': ['mail.example.com'], 'NS': ['ns1.example.com'], 'TXT': [], 'AAAA': [], 'SOA': [], 'CNAME': []},
        'nmap': {
            'ports': [
                {'port': '80', 'protocol': 'tcp', 'state': 'open', 'service': 'http', 'product': 'nginx', 'version': '1.18.0'},
                {'port': '443', 'protocol': 'tcp', 'state': 'open', 'service': 'https', 'product': 'nginx', 'version': '1.18.0'},
                {'port': '22', 'protocol': 'tcp', 'state': 'open', 'service': 'ssh', 'product': 'OpenSSH', 'version': '8.2p1'},
            ],
            'services': [],
            'os': 'Linux 5.4',
            'vulnerabilities': []
        },
        'security_headers': {
            'present': {'x-frame-options': 'DENY'},
            'missing': ['content-security-policy', 'strict-transport-security', 'x-content-type-options'],
        },
        'vulnerabilities': [
            {'name': 'SQL Injection', 'severity': 'critical', 'url': 'https://example.com/api/users?id=1', 'template': 'sqli-001', 'description': 'SQL injection in user ID parameter allows database manipulation'},
            {'name': 'Cross-Site Scripting (XSS)', 'severity': 'high', 'url': 'https://example.com/search?q=test', 'template': 'xss-reflected', 'description': 'Reflected XSS in search parameter'},
        ],
        'xss_results': [{'url': 'https://example.com/search?q=<script>', 'details': 'Reflected XSS'}],
        'sqli_results': [{'url': 'https://example.com/api/users?id=1', 'vulnerable': True}],
        'command_injection': [],
        'api_endpoints': ['/api/v1/users', '/api/v1/posts'],
        'emails': ['security@example.com', 'admin@example.com'],
        'exploits': [{'search_term': 'nginx 1.18.0', 'count': 2, 'exploits': [{'EDB-ID': '12345', 'Title': 'Nginx DoS Exploit'}]}],
        'metasploit_modules': [{'module': 'exploit/unix/webapp/nginx_chunked_size', 'rank': 'excellent'}],
    }
    
    sample_stats = {
        'critical': 3, 'high': 5, 'medium': 8, 'low': 4, 'info': 2,
        'vulnerabilities_found': 22,
        'subdomains_found': 3, 'endpoints_found': 2,
    }
    
    gen = UltimateReportGenerator(sample_results, sample_stats)
    gen.generate('ultimate_pentest_report.html')
    print('[+] Ultimate professional pentest report generated: ultimate_pentest_report.html')


if __name__ == '__main__':
    main()
