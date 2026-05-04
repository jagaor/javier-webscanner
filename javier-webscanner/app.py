#!/usr/bin/env python3
"""
Javier WebScanner - Flask backend.

Orquestador de motores de auditoría web.
- Validación estricta de URL
- subprocess.run con lista de args (sin shell=True)
- PDF auto-generado al terminar
- Bind 127.0.0.1
"""
import os
import re
import ssl
import socket
import subprocess
import threading
import uuid
import datetime
from urllib.parse import urlparse, urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

from flask import Flask, render_template, request, jsonify, send_file, abort

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, KeepTogether
)
from reportlab.lib.enums import TA_JUSTIFY

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
os.makedirs(REPORTS_DIR, exist_ok=True)

scans = {}
scans_lock = threading.Lock()

ALLOWED_TOOLS = {
    'http_headers', 'ssl_check', 'whatweb', 'wafw00f', 'dns', 'robots',
    'sensitive_files', 'nikto', 'nmap', 'sqlmap', 'dirb', 'gobuster'
}
URL_RE = re.compile(r'^https?://[A-Za-z0-9._\-:/%?=&#~+,;@!$\'()*\[\]]+$')

WORDLIST_CANDIDATES = [
    '/usr/share/wordlists/dirb/common.txt',
    '/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt',
    '/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt',
    '/usr/share/seclists/Discovery/Web-Content/common.txt',
]

SECURITY_HEADERS = {
    'Strict-Transport-Security': ('high',   'HSTS no configurado: tráfico vulnerable a downgrade attacks'),
    'Content-Security-Policy':   ('high',   'CSP ausente: protección contra XSS reducida'),
    'X-Frame-Options':           ('medium', 'X-Frame-Options ausente: vulnerable a clickjacking'),
    'X-Content-Type-Options':    ('low',    'X-Content-Type-Options ausente: posible MIME sniffing'),
    'Referrer-Policy':           ('low',    'Referrer-Policy no configurado'),
    'Permissions-Policy':        ('low',    'Permissions-Policy no configurado'),
    'X-XSS-Protection':          ('info',   'X-XSS-Protection legacy ausente (deprecado)'),
}

SENSITIVE_PATHS = [
    '.env', '.git/config', '.git/HEAD', '.svn/entries', '.htaccess', '.htpasswd',
    'backup.zip', 'backup.tar.gz', 'database.sql', 'dump.sql', 'config.php.bak',
    'wp-config.php.bak', '.DS_Store', 'phpinfo.php', 'admin/', 'phpmyadmin/',
    'server-status', 'server-info', 'README.md', 'CHANGELOG.md',
    '.well-known/security.txt', 'crossdomain.xml', 'clientaccesspolicy.xml',
    'web.config', '.bash_history',
]


def find_wordlist():
    for w in WORDLIST_CANDIDATES:
        if os.path.isfile(w):
            return w
    return None


def is_safe_url(url):
    if not URL_RE.match(url):
        return False
    p = urlparse(url)
    return p.scheme in ('http', 'https') and bool(p.netloc)


def extract_host(url):
    return urlparse(url).hostname or ''


def extract_port(url):
    p = urlparse(url)
    if p.port:
        return p.port
    return 443 if p.scheme == 'https' else 80


def make_session(user_agent):
    s = requests.Session()
    s.headers.update({'User-Agent': user_agent})
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[502, 503, 504])
    s.mount('http://', HTTPAdapter(max_retries=retry))
    s.mount('https://', HTTPAdapter(max_retries=retry))
    return s


class ScannerThread(threading.Thread):
    def __init__(self, scan_id, url, tools, options):
        super().__init__(daemon=True)
        self.scan_id = scan_id
        self.url = url
        self.tools = tools
        self.options = options
        self.results = {}
        self.findings = []
        self.progress = 0
        self.status_message = "Iniciando..."
        self.completed = False
        self.started_at = datetime.datetime.now()
        self.finished_at = None
        self.pdf_path = None

    def add_finding(self, severity, title, description, tool):
        self.findings.append({
            'severity': severity, 'title': title,
            'description': description, 'tool': tool
        })

    def run(self):
        runners = {
            'http_headers': self.run_http_headers,
            'ssl_check': self.run_ssl_check,
            'whatweb': self.run_whatweb,
            'wafw00f': self.run_wafw00f,
            'dns': self.run_dns,
            'robots': self.run_robots,
            'sensitive_files': self.run_sensitive_files,
            'nikto': self.run_nikto,
            'nmap': self.run_nmap,
            'sqlmap': self.run_sqlmap,
            'dirb': self.run_dirb,
            'gobuster': self.run_gobuster,
        }
        total = len(self.tools)
        done = 0
        for tool in self.tools:
            self.status_message = f"Ejecutando {tool}..."
            try:
                self.results[tool] = runners[tool]()
            except Exception as e:
                self.results[tool] = {'error': f"{tool}: {e}"}
            done += 1
            self.progress = int((done / total) * 95)

        self.status_message = "Generando informe PDF..."
        self.finished_at = datetime.datetime.now()
        try:
            self.pdf_path = build_pdf_report(self)
        except Exception as e:
            self.results['__pdf_error__'] = {'error': f'PDF generation failed: {e}'}
        self.progress = 100
        self.status_message = "Escaneo completado"
        self.completed = True

    # ------------------------------------------------------------- ENGINES
    def run_http_headers(self):
        ua = self.options.get('user_agent', 'Mozilla/5.0')
        try:
            s = make_session(ua)
            r = s.get(self.url, timeout=15, verify=False, allow_redirects=True)
            headers = dict(r.headers)
            output_lines = [f"Status: {r.status_code}", f"Final URL: {r.url}", "", "Headers:"]
            for k, v in headers.items():
                output_lines.append(f"  {k}: {v}")
            for h, (sev, desc) in SECURITY_HEADERS.items():
                if h not in headers:
                    self.add_finding(sev, f'Header faltante: {h}', desc, 'http_headers')
            if 'Server' in headers:
                self.add_finding('info', 'Servidor revelado',
                                 f"Header Server expone: {headers['Server']}", 'http_headers')
            if 'X-Powered-By' in headers:
                self.add_finding('low', 'X-Powered-By revelado',
                                 f"Tecnología expuesta: {headers['X-Powered-By']}", 'http_headers')
            for c in r.cookies:
                flags = []
                if not c.secure:
                    flags.append('Secure')
                if 'httponly' not in str(c._rest).lower():
                    flags.append('HttpOnly')
                if flags:
                    self.add_finding('medium', f'Cookie sin flags: {c.name}',
                                     f"Falta(n): {', '.join(flags)}", 'http_headers')
            return {'output': '\n'.join(output_lines)}
        except Exception as e:
            return {'error': str(e)}

    def run_ssl_check(self):
        host = extract_host(self.url)
        port = extract_port(self.url)
        if not host or urlparse(self.url).scheme != 'https':
            return {'output': 'No HTTPS, omitiendo TLS'}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    proto = ssock.version()
            lines = [f"Host: {host}:{port}", f"Protocol: {proto}",
                     f"Cipher: {cipher[0]} ({cipher[1]} bits)"]
            if proto in ('SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'):
                self.add_finding('high', f'Protocolo TLS obsoleto: {proto}',
                                 'Protocolo deprecado, vulnerable a ataques conocidos', 'ssl_check')
            if cipher[2] < 128:
                self.add_finding('high', f'Cifrado débil: {cipher[0]}',
                                 f'Solo {cipher[2]} bits', 'ssl_check')
            try:
                proc = subprocess.run(
                    ['openssl', 's_client', '-servername', host, '-connect', f'{host}:{port}'],
                    input=b'', capture_output=True, timeout=15
                )
                cert_text = proc.stdout.decode(errors='ignore') + proc.stderr.decode(errors='ignore')
                lines.append('\n--- openssl s_client output ---')
                lines.append(cert_text[:8000])
            except Exception:
                pass
            if cert:
                not_after = cert.get('notAfter')
                if not_after:
                    try:
                        exp = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days = (exp - datetime.datetime.utcnow()).days
                        lines.append(f"Cert expira: {not_after} ({days} días)")
                        if days < 0:
                            self.add_finding('high', 'Certificado SSL caducado',
                                             f'Caducó hace {-days} días', 'ssl_check')
                        elif days < 30:
                            self.add_finding('medium', 'Certificado SSL próximo a caducar',
                                             f'Quedan {days} días', 'ssl_check')
                    except Exception:
                        pass
            return {'output': '\n'.join(lines)}
        except Exception as e:
            return {'error': str(e)}

    def run_whatweb(self):
        out = self.run_command(['whatweb', '-a', '3', '--color=never', self.url])
        if 'output' in out:
            for tech in re.findall(r'\[(.*?)\]', out['output']):
                if any(k in tech.lower() for k in ['version', 'wordpress', 'drupal', 'joomla', 'php']):
                    self.add_finding('info', 'Tecnología detectada', tech, 'whatweb')
        return out

    def run_wafw00f(self):
        out = self.run_command(['wafw00f', self.url])
        if 'output' in out:
            o = out['output'].lower()
            if 'is behind' in o or 'identified' in o:
                m = re.search(r'is behind\s+(.+?)(?:\n|\.)', out['output'], re.I)
                if m:
                    self.add_finding('info', 'WAF detectado', m.group(1).strip(), 'wafw00f')
            elif 'no waf detected' in o:
                self.add_finding('low', 'Sin WAF detectado',
                                 'No se identificó WAF en el target', 'wafw00f')
        return out

    def run_dns(self):
        host = extract_host(self.url)
        lines = []
        for rec in ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']:
            r = self.run_command(['dig', '+short', rec, host])
            if r.get('output'):
                lines.append(f"--- {rec} ---\n{r['output']}")
        whois = self.run_command(['whois', host])
        if whois.get('output'):
            lines.append('\n--- WHOIS ---\n' + whois['output'][:4000])
        return {'output': '\n\n'.join(lines) or '(sin datos)'}

    def run_robots(self):
        ua = self.options.get('user_agent', 'Mozilla/5.0')
        s = make_session(ua)
        out = []
        for path in ('robots.txt', 'sitemap.xml', '.well-known/security.txt', 'humans.txt'):
            try:
                u = urljoin(self.url.rstrip('/') + '/', path)
                r = s.get(u, timeout=10, verify=False)
                if r.status_code == 200 and len(r.text) > 0:
                    out.append(f"=== {path} (200) ===\n{r.text[:3000]}")
                    if path == 'robots.txt':
                        disallows = re.findall(r'Disallow:\s*(\S+)', r.text)
                        if disallows:
                            self.add_finding('info', 'Rutas en robots.txt',
                                             f'{len(disallows)} disallow detectados', 'robots')
                else:
                    out.append(f"=== {path} ({r.status_code}) ===")
            except Exception as e:
                out.append(f"=== {path} ERROR: {e} ===")
        return {'output': '\n\n'.join(out)}

    def run_sensitive_files(self):
        ua = self.options.get('user_agent', 'Mozilla/5.0')
        s = make_session(ua)
        found = []
        checked = 0
        for path in SENSITIVE_PATHS:
            try:
                u = urljoin(self.url.rstrip('/') + '/', path)
                r = s.get(u, timeout=8, verify=False, allow_redirects=False)
                checked += 1
                if r.status_code == 200 and len(r.content) > 0:
                    found.append(f"[200] {u}  ({len(r.content)} bytes)")
                    sev = 'high' if path in ('.env', '.git/config', 'database.sql',
                                             'dump.sql', 'wp-config.php.bak') else 'medium'
                    self.add_finding(sev, f'Archivo sensible expuesto: {path}',
                                     f'Accesible públicamente en {u}', 'sensitive_files')
                elif r.status_code in (401, 403):
                    found.append(f"[{r.status_code}] {u}  (existe pero protegido)")
            except Exception:
                pass
        return {'output': f"Comprobados: {checked}\nEncontrados:\n" +
                ('\n'.join(found) if found else '  (ninguno)')}

    def run_nikto(self):
        ua = self.options.get('user_agent', 'Mozilla/5.0')
        out = self.run_command(['nikto', '-h', self.url, '-useragent', ua,
                                '-Tuning', '1234567', '-nointeractive', '-ask', 'no'])
        if 'output' in out:
            for line in out['output'].splitlines():
                if line.strip().startswith('+ ') and 'OSVDB' not in line and len(line) > 10:
                    sev = 'medium'
                    low = line.lower()
                    if any(k in low for k in ['xss', 'sql', 'rce', 'injection', 'disclosure', 'traversal']):
                        sev = 'high'
                    elif any(k in low for k in ['cookie', 'header', 'version']):
                        sev = 'low'
                    self.add_finding(sev, 'Hallazgo Nikto', line.strip()[:300], 'nikto')
        return out

    def run_nmap(self):
        host = extract_host(self.url)
        if not host:
            return {'error': 'host inválido'}
        out = self.run_command(['nmap', '-sV', '-sC', '-Pn', '-T4',
                                '--top-ports', '1000', host])
        if 'output' in out:
            for line in out['output'].splitlines():
                m = re.match(r'(\d+)/tcp\s+open\s+(\S+)\s+(.*)', line)
                if m:
                    port, svc, ver = m.groups()
                    sev = 'medium' if svc in ('telnet', 'ftp', 'rsh', 'smb', 'rpcbind') else 'info'
                    self.add_finding(sev, f'Puerto abierto {port}/tcp',
                                     f'{svc} {ver}'.strip(), 'nmap')
        return out

    def run_sqlmap(self):
        return self.run_command([
            'sqlmap', '-u', self.url, '--batch', '--random-agent',
            '--level=1', '--risk=1', '--disable-coloring', '--smart'
        ])

    def run_dirb(self):
        wl = find_wordlist()
        cmd = ['dirb', self.url]
        if wl:
            cmd.append(wl)
        cmd += ['-S', '-r']
        return self.run_command(cmd)

    def run_gobuster(self):
        wl = find_wordlist()
        if not wl:
            return {'error': 'wordlist no encontrada'}
        threads = str(self.options.get('threads', 20))
        return self.run_command(['gobuster', 'dir', '-u', self.url, '-w', wl,
                                 '-t', threads, '-q', '--no-error', '-k'])

    def run_command(self, cmd):
        try:
            timeout = int(self.options.get('timeout', 300))
        except (TypeError, ValueError):
            timeout = 300
        timeout = max(30, min(timeout, 3600))
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout, check=False)
            output = (proc.stdout or '') + (proc.stderr or '')
            return {'output': output.strip() or '(sin salida)'}
        except FileNotFoundError:
            return {'error': f"Binario no encontrado: {cmd[0]}"}
        except subprocess.TimeoutExpired as e:
            partial = ''
            if e.stdout:
                partial += e.stdout if isinstance(e.stdout, str) else e.stdout.decode(errors='ignore')
            if e.stderr:
                partial += e.stderr if isinstance(e.stderr, str) else e.stderr.decode(errors='ignore')
            return {'output': f"[Timeout {timeout}s]\n{partial}"}
        except Exception as e:
            return {'error': str(e)}


# --------------------------------------------------------------------- ROUTES
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def start_scan():
    url = (request.form.get('url') or '').strip()
    tools = [t for t in request.form.getlist('tools') if t in ALLOWED_TOOLS]
    if not url or not is_safe_url(url):
        return jsonify({'error': 'URL inválida (http:// o https://)'}), 400
    if not tools:
        return jsonify({'error': 'Selecciona al menos una herramienta'}), 400
    options = {
        'timeout': request.form.get('timeout', 300),
        'threads': request.form.get('threads', 20),
        'user_agent': request.form.get('user_agent', 'Mozilla/5.0 WebVulnScanner'),
    }
    scan_id = str(uuid.uuid4())
    t = ScannerThread(scan_id, url, tools, options)
    with scans_lock:
        scans[scan_id] = t
    t.start()
    return jsonify({'status': 'started', 'scan_id': scan_id})


@app.route('/status/<scan_id>')
def scan_status(scan_id):
    with scans_lock:
        scan = scans.get(scan_id)
    if scan is None:
        return jsonify({'error': 'no encontrado'}), 404
    summary = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for f in scan.findings:
        s = f.get('severity', 'info')
        if s in summary:
            summary[s] += 1
    tool_counts = {}
    for f in scan.findings:
        tool_counts[f.get('tool', '?')] = tool_counts.get(f.get('tool', '?'), 0) + 1
    return jsonify({
        'scan_id': scan_id,
        'progress': scan.progress,
        'status_message': scan.status_message,
        'completed': scan.completed,
        'results': scan.results if scan.completed else {},
        'findings': scan.findings if scan.completed else [],
        'summary': summary,
        'tool_counts': tool_counts,
    })


# ------------------------------------------------------------------------ PDF
def generate_charts(summary, tool_counts, out_dir):
    chart_paths = {}
    fig, ax = plt.subplots(figsize=(5, 4), facecolor='white')
    labels, vals, colrs = [], [], []
    palette = {'high': '#ef4444', 'medium': '#f59e0b', 'low': '#3b82f6', 'info': '#06b6d4'}
    names = {'high': 'Críticas', 'medium': 'Medias', 'low': 'Bajas', 'info': 'Informativas'}
    for k in ('high', 'medium', 'low', 'info'):
        if summary.get(k, 0) > 0:
            labels.append(f"{names[k]} ({summary[k]})")
            vals.append(summary[k])
            colrs.append(palette[k])
    if vals:
        ax.pie(vals, labels=labels, colors=colrs, autopct='%1.0f%%', startangle=90,
               textprops={'fontsize': 9}, wedgeprops={'edgecolor': 'white', 'linewidth': 2})
    else:
        ax.text(0.5, 0.5, 'Sin hallazgos', ha='center', va='center', fontsize=12)
        ax.axis('off')
    ax.set_title('Distribución por severidad', fontsize=11, fontweight='bold')
    p1 = os.path.join(out_dir, 'chart_sev.png')
    fig.tight_layout()
    fig.savefig(p1, dpi=130, bbox_inches='tight')
    plt.close(fig)
    chart_paths['sev'] = p1

    fig, ax = plt.subplots(figsize=(6, 3.5), facecolor='white')
    if tool_counts:
        items = sorted(tool_counts.items(), key=lambda x: -x[1])
        keys = [k for k, _ in items]
        values = [v for _, v in items]
        bars = ax.bar(keys, values, color='#8b5cf6', edgecolor='#6d28d9')
        ax.set_ylabel('Hallazgos')
        ax.set_title('Hallazgos por motor', fontsize=11, fontweight='bold')
        plt.setp(ax.get_xticklabels(), rotation=30, ha='right', fontsize=8)
        for b in bars:
            ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.05,
                    int(b.get_height()), ha='center', fontsize=8)
    else:
        ax.text(0.5, 0.5, 'Sin datos', ha='center', va='center')
        ax.axis('off')
    p2 = os.path.join(out_dir, 'chart_tools.png')
    fig.tight_layout()
    fig.savefig(p2, dpi=130, bbox_inches='tight')
    plt.close(fig)
    chart_paths['tools'] = p2
    return chart_paths


def build_pdf_report(scan):
    summary = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for f in scan.findings:
        s = f.get('severity', 'info')
        if s in summary:
            summary[s] += 1
    tool_counts = {}
    for f in scan.findings:
        tool_counts[f.get('tool', '?')] = tool_counts.get(f.get('tool', '?'), 0) + 1

    tmp = os.path.join(REPORTS_DIR, scan.scan_id)
    os.makedirs(tmp, exist_ok=True)
    charts = generate_charts(summary, tool_counts, tmp)

    host = extract_host(scan.url) or 'target'
    safe_host = re.sub(r'[^A-Za-z0-9._-]', '_', host)
    ts = scan.started_at.strftime('%Y%m%d_%H%M%S')
    pdf_path = os.path.join(REPORTS_DIR,
                            f"informe_{safe_host}_{ts}_{scan.scan_id[:8]}.pdf")

    doc = SimpleDocTemplate(pdf_path, pagesize=A4,
                            leftMargin=2 * cm, rightMargin=2 * cm,
                            topMargin=2 * cm, bottomMargin=2 * cm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('Title', parent=styles['Title'], fontSize=22,
                                 textColor=colors.HexColor('#1f2937'), spaceAfter=12)
    h2 = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=14,
                        textColor=colors.HexColor('#06b6d4'), spaceBefore=14, spaceAfter=8)
    h3 = ParagraphStyle('H3', parent=styles['Heading3'], fontSize=11,
                        textColor=colors.HexColor('#374151'), spaceBefore=8, spaceAfter=4)
    body = ParagraphStyle('Body', parent=styles['BodyText'], fontSize=9.5,
                          leading=13, alignment=TA_JUSTIFY)
    code = ParagraphStyle('Code', parent=styles['Code'], fontSize=7.5, leading=9,
                          textColor=colors.HexColor('#1f2937'),
                          backColor=colors.HexColor('#f3f4f6'))

    story = []
    story.append(Paragraph("Javier WebScanner - Informe de Auditoría", title_style))
    story.append(Paragraph(f"<b>Target:</b> {scan.url}", body))
    story.append(Paragraph(f"<b>Inicio:</b> {scan.started_at:%Y-%m-%d %H:%M:%S}", body))
    story.append(Paragraph(f"<b>Fin:</b> {scan.finished_at:%Y-%m-%d %H:%M:%S}", body))
    duration = (scan.finished_at - scan.started_at).total_seconds()
    story.append(Paragraph(f"<b>Duración:</b> {duration:.1f}s", body))
    story.append(Paragraph(f"<b>Motores:</b> {', '.join(scan.tools)}", body))
    story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph("Resumen ejecutivo", h2))
    tot = sum(summary.values())
    data = [
        ['Severidad', 'Hallazgos'],
        ['Críticas', str(summary['high'])],
        ['Medias', str(summary['medium'])],
        ['Bajas', str(summary['low'])],
        ['Informativas', str(summary['info'])],
        ['TOTAL', str(tot)],
    ]
    tbl = Table(data, colWidths=[8 * cm, 4 * cm])
    tbl.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f2937')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#fee2e2')),
        ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor('#fef3c7')),
        ('BACKGROUND', (0, 3), (-1, 3), colors.HexColor('#dbeafe')),
        ('BACKGROUND', (0, 4), (-1, 4), colors.HexColor('#cffafe')),
        ('BACKGROUND', (0, 5), (-1, 5), colors.HexColor('#e5e7eb')),
        ('FONTNAME', (0, 5), (-1, 5), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 0.5 * cm))

    if os.path.isfile(charts['sev']):
        story.append(Paragraph("Gráficos", h2))
        story.append(Image(charts['sev'], width=11 * cm, height=8 * cm))
        story.append(Spacer(1, 0.3 * cm))
        story.append(Image(charts['tools'], width=14 * cm, height=8 * cm))
    story.append(PageBreak())

    story.append(Paragraph("Hallazgos detallados", h2))
    if not scan.findings:
        story.append(Paragraph("No se detectaron hallazgos relevantes.", body))
    else:
        sev_order = {'high': 0, 'medium': 1, 'low': 2, 'info': 3}
        sev_color = {'high': '#ef4444', 'medium': '#f59e0b', 'low': '#3b82f6', 'info': '#06b6d4'}
        sev_label = {'high': 'CRÍTICA', 'medium': 'MEDIA', 'low': 'BAJA', 'info': 'INFO'}
        sorted_f = sorted(scan.findings, key=lambda f: sev_order.get(f.get('severity', 'info'), 9))
        for i, f in enumerate(sorted_f, 1):
            sev = f.get('severity', 'info')
            color = sev_color.get(sev, '#06b6d4')
            box = [[
                Paragraph(f"<font color='white'><b>{sev_label.get(sev, '?')}</b></font>", body),
                Paragraph(f"<b>#{i} · {f.get('title', '?')}</b>", body),
            ], [
                Paragraph(f"<i>Motor: {f.get('tool', '?')}</i>", body),
                Paragraph(str(f.get('description', ''))[:1000], body),
            ]]
            t = Table(box, colWidths=[3 * cm, 13 * cm])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor(color)),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('PADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.3, colors.HexColor('#d1d5db')),
            ]))
            story.append(KeepTogether(t))
            story.append(Spacer(1, 0.2 * cm))

    story.append(PageBreak())

    story.append(Paragraph("Salida cruda por motor", h2))
    for tool, result in scan.results.items():
        story.append(Paragraph(tool.upper(), h3))
        text = result.get('output') or result.get('error', '(vacío)')
        text = str(text)[:8000]
        for line in text.splitlines() or ['(vacío)']:
            safe = line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            story.append(Paragraph(f"<font face='Courier' size='7'>{safe}</font>", code))
        story.append(Spacer(1, 0.3 * cm))

    story.append(PageBreak())
    story.append(Paragraph("Recomendaciones generales", h2))
    recs = [
        "Configurar todas las cabeceras de seguridad: HSTS, CSP, X-Frame-Options, X-Content-Type-Options.",
        "Mantener TLS ≥ 1.2, deshabilitar SSLv3/TLSv1.0/1.1 y cifrados con menos de 128 bits.",
        "Establecer flags Secure y HttpOnly en todas las cookies sensibles; SameSite=Strict cuando sea posible.",
        "Eliminar archivos sensibles expuestos (.env, .git, backups, dumps SQL).",
        "Ocultar headers Server y X-Powered-By para reducir fingerprinting.",
        "Validar y sanear toda entrada de usuario; usar consultas parametrizadas para prevenir SQLi.",
        "Implementar WAF y rate-limiting para mitigar ataques automatizados.",
        "Mantener todas las dependencias y CMS al día con los últimos parches de seguridad.",
        "Realizar auditorías periódicas y monitorización continua de logs.",
    ]
    for r in recs:
        story.append(Paragraph("• " + r, body))
        story.append(Spacer(1, 0.15 * cm))

    doc.build(story)
    return pdf_path


@app.route('/report/<scan_id>')
def report(scan_id):
    with scans_lock:
        scan = scans.get(scan_id)
    if scan is None or not scan.completed:
        abort(404)
    pdf_path = scan.pdf_path
    if not pdf_path or not os.path.isfile(pdf_path):
        try:
            pdf_path = build_pdf_report(scan)
            scan.pdf_path = pdf_path
        except Exception as e:
            return jsonify({'error': f'PDF error: {e}'}), 500
    return send_file(pdf_path, as_attachment=True,
                     download_name=os.path.basename(pdf_path))


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
