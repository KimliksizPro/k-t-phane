import re
import time
import os
import json
import logging
import urllib.parse
import html
import random
import math
import hashlib
import uuid
import datetime
import ipaddress
import copy
from functools import wraps
from flask import request, abort, Response, session, g

from flask_login import current_user

class ShieldConfig:
    VERSION = "2025.2.0-TITANIUM-ULTRA-TR"
    MODE = "STRICT"
    LOG_FILE = "titanium_defense.log"
    BAN_FILE = "titanium_banned.json"
    
    RISK_SCORE_WARNING = 25
    RISK_SCORE_BLOCK = 50
    RISK_SCORE_BAN = 100
    
    RATE_LIMIT_ENABLED = True
    RATE_LIMIT_CAPACITY = 100
    RATE_LIMIT_FILL_RATE = 2.0
    BURST_TOLERANCE = 20
    
    ENTROPY_THRESHOLD = 4.8
    MAX_PARAM_LENGTH = 1024
    
    SESSION_FINGERPRINT_CHECK = True
    REQUIRE_STRONG_HEADERS = True
    
    BAN_DURATION_INITIAL = 3600
    BAN_DURATION_ESCALATED = 86400
    BAN_DURATION_PERMANENT = 315360000

class SecurityUtils:
    @staticmethod
    def get_time_iso():
        return datetime.datetime.now().isoformat()

    @staticmethod
    def calculate_entropy(text):
        if not text:
            return 0
        entropy = 0
        length = len(text)
        counts = {}
        for char in text:
            counts[char] = counts.get(char, 0) + 1
        
        for count in counts.values():
            p = float(count) / length
            if p > 0:
                entropy -= p * math.log(p, 2)
        return entropy

    @staticmethod
    def normalize_payload(text):
        if not text: return ""
        try:
            prev = text
            for _ in range(3):
                text = urllib.parse.unquote(text)
                if text == prev: break
                prev = text
            
            text = html.unescape(text)
            text = text.encode('utf-8', 'ignore').decode('utf-8')
            text = text.lower()
            text = re.sub(r'/\*.*?\*/', '', text)
            text = re.sub(r'--.*$', '', text)
            text = re.sub(r'\s+', ' ', text).strip()
            return text
        except Exception:
            return text

    @staticmethod
    def generate_fingerprint(req):
        data = [
            req.remote_addr,
            req.headers.get('User-Agent', ''),
            req.headers.get('Accept-Language', ''),
            req.headers.get('Accept-Encoding', ''),
            req.headers.get('DNT', '0'),
            req.headers.get('Sec-Ch-Ua', ''),
            req.headers.get('Sec-Ch-Ua-Platform', '')
        ]
        seed = "|".join(str(d) for d in data)
        return hashlib.sha256(seed.encode()).hexdigest()

class SignatureDatabase:
    def __init__(self):
        self.sql_signatures = [
            (r"UNION\s+(ALL\s+)?SELECT", 80, "Kritik SQL Enjeksiyonu (UNION)"),
            (r"SELECT\s+.*\s+FROM", 60, "Klasik SQL Enjeksiyonu (SELECT)"),
            (r"INSERT\s+INTO\s+.*VALUES", 60, "SQL Enjeksiyonu (INSERT)"),
            (r"UPDATE\s+.*\s+SET", 60, "SQL Enjeksiyonu (UPDATE)"),
            (r"DELETE\s+FROM", 70, "Kritik SQL Enjeksiyonu (DELETE)"),
            (r"DROP\s+(TABLE|DATABASE|VIEW)", 100, "Yikici SQL Enjeksiyonu (DROP)"),
            (r"TRUNCATE\s+TABLE", 100, "Yikici SQL Enjeksiyonu (TRUNCATE)"),
            (r"ALTER\s+TABLE", 90, "Sema Degistirme Girisimi"),
            (r"EXEC\s*\(", 90, "SQL Calistirma Girisimi"),
            (r"XP_CMDSHELL", 100, "MSSQL Komut Kabugu"),
            (r"WAITFOR\s+DELAY", 70, "Zaman Tabanli SQLi (MSSQL)"),
            (r"PG_SLEEP", 70, "Zaman Tabanli SQLi (Postgres)"),
            (r"BENCHMARK\s*\(", 70, "Zaman Tabanli SQLi (MySQL)"),
            (r"OR\s+1\s*=\s*1", 40, "Boolean Totolojisi (OR)"),
            (r"AND\s+1\s*=\s*1", 40, "Boolean Totolojisi (AND)"),
            (r"'\s+OR\s+'", 40, "Tirnak Kacirma"),
            (r"\"\s+OR\s+\"", 40, "Cift Tirnak Kacirma"),
            (r"ORDER\s+BY\s+\d+", 30, "Kolon Numaralandirma"),
            (r"GROUP\s+BY", 30, "Gruplama Enjeksiyonu"),
            (r"HAVING\s+", 30, "Having Enjeksiyonu"),
            (r"INFORMATION_SCHEMA", 60, "Metadata Numaralandirma"),
            (r"@@VERSION", 50, "Versiyon Numaralandirma"),
            (r"LOAD_FILE", 90, "Dosya Okuma Enjeksiyonu"),
            (r"INTO\s+OUTFILE", 100, "Dosya Yazma Enjeksiyonu"),
            (r"RLIKE", 40, "Regex Enjeksiyonu (MySQL)"),
            (r"SLEEP\(", 60, "Uyutma Enjeksiyonu"),
            (r"DBMS_PIPE", 80, "Oracle Enjeksiyonu"),
            (r"CTXSYS\.DRITCTX", 80, "Oracle Enjeksiyonu (CTXSYS)"),
        ]
        
        self.xss_signatures = [
            (r"<script.*?>", 50, "XSS (Script Etiketi)"),
            (r"javascript:\s*", 50, "XSS (Pseudo Protokol)"),
            (r"vbscript:\s*", 50, "XSS (VB Protokol)"),
            (r"onload\s*=", 40, "XSS (Yukleme Olayi)"),
            (r"onerror\s*=", 40, "XSS (Hata Olayi)"),
            (r"onclick\s*=", 40, "XSS (Tiklama Olayi)"),
            (r"onmouseover\s*=", 40, "XSS (Fare Olayi)"),
            (r"onfocus\s*=", 40, "XSS (Odaklanma Olayi)"),
            (r"alert\s*\(", 30, "XSS (Uyari Testi)"),
            (r"prompt\s*\(", 30, "XSS (Giris Testi)"),
            (r"confirm\s*\(", 30, "XSS (Onay Testi)"),
            (r"eval\s*\(", 60, "Tehlikeli Kod Calistirma"),
            (r"document\.cookie", 50, "Cerez Calma Girisimi"),
            (r"document\.domain", 40, "Alan Adi Erisim Girisimi"),
            (r"<iframe>", 40, "Iframe Enjeksiyonu"),
            (r"<object>", 40, "Nesne Enjeksiyonu"),
            (r"<embed>", 40, "Gomulu Nesne Enjeksiyonu"),
            (r"base64\s*,", 50, "Base64 Veri URI"),
            (r"<svg.*?>", 40, "SVG Enjeksiyonu"),
            (r"<math.*?>", 40, "MathML Enjeksiyonu"),
            (r"expression\(", 50, "CSS Ifade Enjeksiyonu"),
        ]
        
        self.rce_signatures = [
            (r"/bin/sh", 100, "Shell Erisimi (sh)"),
            (r"/bin/bash", 100, "Shell Erisimi (bash)"),
            (r"cmd\.exe", 100, "Windows Komut Satiri"),
            (r"powershell(\.exe)?", 100, "Powershell Calistirma"),
            (r"nc\s+-e", 100, "Netcat Ters Shell"),
            (r"wget\s+http", 70, "Zararli Dosya Indirme (wget)"),
            (r"curl\s+http", 70, "Zararli Dosya Indirme (curl)"),
            (r"net\s+user", 80, "Windows Kullanici Numaralandirma"),
            (r"whoami", 60, "Sistem Kesfi (whoami)"),
            (r"cat\s+/etc/passwd", 90, "Kritik Dosya Okuma (passwd)"),
            (r"type\s+c:\\windows", 90, "Windows Kritik Dosya Okuma"),
            (r"system\s*\(", 90, "Kod Calistirma (system)"),
            (r"passthru\s*\(", 90, "Kod Calistirma (passthru)"),
            (r"exec\s*\(", 90, "Kod Calistirma (exec)"),
            (r"shell_exec", 90, "Kod Calistirma (shell_exec)"),
            (r"proc_open", 90, "Kod Calistirma (proc_open)"),
            (r"popen", 90, "Kod Calistirma (popen)"),
            (r"`.*?`", 80, "Backtick Calistirma"),
            (r"\$\(.*\)", 80, "Komut Degistirme"),
            (r"bash\s+-i", 100, "Ters Shell (Bash -i)"),
            (r"perl\s+-e", 90, "Perl Calistirma"),
            (r"python\s+-c", 90, "Python Calistirma"),
        ]
        
        self.lfi_signatures = [
            (r"\.\./", 30, "Dizin Gecisi (Standart)"),
            (r"\.\.\\", 30, "Dizin Gecisi (Windows)"),
            (r"%2e%2e/", 30, "Dizin Gecisi (Sifreli)"),
            (r"/etc/shadow", 100, "Shadow Dosyasi Erisimi"),
            (r"/etc/group", 60, "Group Dosyasi Erisimi"),
            (r"/proc/self/environ", 80, "Proc Ortam Erisimi"),
            (r"c:\\windows\\system32", 80, "System32 Erisimi"),
            (r"boot\.ini", 70, "Boot Yapilandirma Erisimi"),
            (r"php://filter", 60, "PHP Akis Filtresi"),
            (r"php://input", 70, "PHP Giris Akisi"),
            (r"file://", 60, "Dosya Protokolu Erisimi"),
            (r"zip://", 50, "Zip Protokolu Erisimi"),
            (r"expect://", 80, "Expect Protokolu Erisimi"),
        ]
        
        self.ssti_signatures = [
            (r"{{.*}}", 90, "Jinja2 SSTi Temel"),
            (r"{%.*%}", 80, "Jinja2 SSTi Blok"),
            (r"class\.__mro__", 100, "Python MRO Kesfi"),
            (r"__subclasses__", 100, "Python Alt Sinif Kesfi"),
            (r"__globals__", 100, "Python Global Kesfi"),
            (r"request\.application", 90, "Flask İstek Manipulasyonu"),
            (r"\['__builtins__'\]", 100, "Python Builtins Erisimi"),
            (r"lipsum", 70, "Flask Lipsum Acigi"),
            (r"cycler", 70, "Flask Cycler Acigi"),
            (r"attr\s*\(", 70, "Jinja2 Attr Acigi"),
            (r"config\.items", 80, "Yapilandirma İfsasi"),
        ]
        
        self.java_signatures = [
            (r"java\.lang", 80, "Java Sinif Erisimi"),
            (r"Runtime\.getRuntime", 100, "Java Runtime Calistirma"),
            (r"ProcessBuilder", 90, "Java Islem Olusturucu"),
            (r"\$\{.+\}", 70, "Java EL Enjeksiyonu"),
            (r"org\.apache", 60, "Apache Sinif Erisimi"),
        ]
        
        self.scanner_agents = [
            (r"sqlmap", 100), (r"nikto", 100), (r"wpscan", 100),
            (r"burp", 70), (r"nmap", 70), (r"acunetix", 80),
            (r"netsparker", 80), (r"nessus", 80), (r"havij", 90),
            (r"morpheus", 80), (r"jndi", 80), (r"log4j", 90),
            (r"zgrab", 60), (r"masscan", 60), (r"openvas", 80),
            (r"dirbuster", 80), (r"gobuster", 80), (r"feroxbuster", 80),
            (r"python-requests", 40), (r"axios", 20), (r"aiohttp", 20),
            (r"curl", 30), (r"wget", 30), (r"libwww-perl", 50),
            (r"httpx", 60), (r"whatweb", 60), (r"qualys", 70),
        ]

class TrafficShaper:
    def __init__(self):
        self.buckets = {}
        
    def _refill(self, ip):
        now = time.time()
        bucket = self.buckets.get(ip, {'tokens': ShieldConfig.RATE_LIMIT_CAPACITY, 'last_update': now})
        
        elapsed = now - bucket['last_update']
        refill_amount = elapsed * ShieldConfig.RATE_LIMIT_FILL_RATE
        
        bucket['tokens'] = min(ShieldConfig.RATE_LIMIT_CAPACITY, bucket['tokens'] + refill_amount)
        bucket['last_update'] = now
        
        self.buckets[ip] = bucket
        return bucket
        
    def allow_request(self, ip, cost=1):
        if not ShieldConfig.RATE_LIMIT_ENABLED:
            return True
            
        bucket = self._refill(ip)
        
        if bucket['tokens'] >= cost:
            bucket['tokens'] -= cost
            self.buckets[ip] = bucket
            return True
            
        return False
        
    def get_stats(self, ip):
        if ip in self.buckets:
            return self.buckets[ip]['tokens']
        return ShieldConfig.RATE_LIMIT_CAPACITY

class EntropyAnalyzer:
    def __init__(self):
        self.threshold = ShieldConfig.ENTROPY_THRESHOLD
        
    def analyze_request(self, params_dict):
        results = []
        for key, value in params_dict.items():
            if len(value) < 16:
                continue
                
            e = SecurityUtils.calculate_entropy(value)
            if e > self.threshold:
                results.append({
                    'param': key,
                    'entropy': e,
                    'msg': 'Yuksek Entropi (Olası Sifreleme)'
                })
        return results

class FingerprintVault:
    def __init__(self):
        pass
        
    def check_integrity(self, session_obj):
        if not ShieldConfig.SESSION_FINGERPRINT_CHECK:
            return True
            
        if 'client_fingerprint' not in session_obj:
            session_obj['client_fingerprint'] = SecurityUtils.generate_fingerprint(request)
            return True
            
        current_fp = SecurityUtils.generate_fingerprint(request)
        stored_fp = session_obj['client_fingerprint']
        
        if current_fp != stored_fp:
            return False
            
        return True

class ForensicsLogger:
    def __init__(self):
        self.logger = logging.getLogger('TitaniumForensics')
        self.logger.setLevel(logging.INFO)
        
        handler = logging.FileHandler(ShieldConfig.LOG_FILE)
        formatter = logging.Formatter('%(message)s')
        handler.setFormatter(formatter)
        try:
            self.logger.addHandler(handler)
        except:
             pass
        
    def log_threat(self, threat_data):
        log_entry = json.dumps(threat_data, default=str)
        self.logger.critical(log_entry)
        
    def build_report(self, ip, reasons, score, action):
        user_id = "ANONYMOUS"
        try:
            if current_user.is_authenticated:
                user_id = f"{current_user.id} ({current_user.username})"
        except:
            pass

        return {
            "zaman_damgasi": SecurityUtils.get_time_iso(),
            "olay_id": str(uuid.uuid4()),
            "tehdit_seviyesi": "KRITIK" if score >= 80 else "YUKSEK",
            "kaynak": {
                "ip": ip,
                "IslemYapanKullaniciID": user_id,
                "tarayici": request.headers.get('User-Agent'),
                "yontem": request.method,
                "url": request.url,
                "parmak_izi": SecurityUtils.generate_fingerprint(request)
            },
            "analiz": {
                "risk_skoru": score,
                "bulgular": reasons,
                "aksiyon": action
            },
            "veri_goruntusu": {
                "parametreler": dict(request.args),
                "form_verisi": dict(request.form) if len(request.form) < 1000 else "COK_BUYUK",
                "basliklar": dict(request.headers),
                "cerezler": dict(request.cookies)
            }
        }

class BehavioralAnalyzer:
    def __init__(self):
        self.history = {}
        self.max_history = 10
        self.sensitive_sequence = ['/login', '/admin', '/config', '/install']
        
    def track(self, ip, path):
        now = time.time()
        if ip not in self.history:
            self.history[ip] = {'paths': [], 'last_hit': now}
        
        user_hist = self.history[ip]
        if now - user_hist['last_hit'] > 300:
            user_hist['paths'] = []
            
        user_hist['paths'].append(path)
        if len(user_hist['paths']) > self.max_history:
            user_hist['paths'].pop(0)
            
        user_hist['last_hit'] = now
        
        return self.analyze_sequence(user_hist['paths'])
        
    def analyze_sequence(self, paths):
        score = 0
        reasons = []
        matched_sensitive = [p for p in paths if any(s in p for s in self.sensitive_sequence)]
        if len(matched_sensitive) >= 3:
            score += 40
            reasons.append("Hassas Yollarda Sirali Tarama")
            
        return score, reasons

class GeoFence:
    def __init__(self):
        self.blocked_countries = {'XX', 'YY'}
        
    def check_ip(self, ip):
        return True

class ReputationManager:
    def __init__(self):
        self.ban_store = {}
        self.load()
        
    def load(self):
        if os.path.exists(ShieldConfig.BAN_FILE):
            try:
                with open(ShieldConfig.BAN_FILE, 'r') as f:
                    self.ban_store = json.load(f)
            except:
                self.ban_store = {}
                
    def save(self):
        try:
            with open(ShieldConfig.BAN_FILE, 'w') as f:
                json.dump(self.ban_store, f)
        except:
            pass
            
    def is_banned(self, ip):
        if ip in self.ban_store:
            record = self.ban_store[ip]
            if time.time() < record['deadline']:
                return True, record['reason']
            else:
                del self.ban_store[ip]
                self.save()
        return False, None
        
    def ban(self, ip, reason, score):
        if ip in {'127.0.0.1', 'localhost', '::1', '10.0.0.1'}: return

        base_duration = ShieldConfig.BAN_DURATION_INITIAL
        if score >= 150: base_duration = ShieldConfig.BAN_DURATION_PERMANENT
        elif score >= 100: base_duration = ShieldConfig.BAN_DURATION_ESCALATED
        
        deadline = time.time() + base_duration
        
        self.ban_store[ip] = {
            'deadline': deadline,
            'reason': reason,
            'score': score,
            'banned_at': SecurityUtils.get_time_iso()
        }
        self.save()

    def manual_unban(self, ip):
        """Manually remove an IP from the ban list."""
        if ip in self.ban_store:
            del self.ban_store[ip]
            self.save()
            return True
        return False

class SecurityGuardian:
    def __init__(self, app=None):
        self.sigs = SignatureDatabase()
        self.traffic = TrafficShaper()
        self.entropy = EntropyAnalyzer()
        self.reputation = ReputationManager()
        self.forensics = ForensicsLogger()
        self.fingerprint = FingerprintVault()
        self.behavior = BehavioralAnalyzer()
        self.geofence = GeoFence()
        
        self.whitelist = {'127.0.0.1', '::1', 'localhost'}
        
        if app:
            self.init_app(app)

    @property
    def banned_ips(self):
        return self.reputation.ban_store
            
    def init_app(self, app):
        @app.before_request
        def firewall_entry():
            self.execute_defense_protocol()
            
        @app.after_request
        def firewall_exit(response):
            return self.secure_response(response)
    
    def manual_ban_ip(self, ip, reason="Manuel Yasaklama"):
        """Manually bans an IP via admin action."""
        # Force a high score ban
        self.reputation.ban(ip, reason, 1000)
        
    def manual_unban_ip(self, ip):
        """Manually unbans an IP."""
        self.reputation.manual_unban(ip)
        
    def reset_ip_status(self, ip):
        """Clears all tracking data for an IP (Traffic, Behavior, Ban)."""
        # 1. Remove from Ban List
        self.reputation.manual_unban(ip)
        
        # 2. Reset Traffic Bucket
        if ip in self.traffic.buckets:
            del self.traffic.buckets[ip]
            
        # 3. Reset Behavioral History
        if ip in self.behavior.history:
            del self.behavior.history[ip]

    def execute_defense_protocol(self):
        client_ip = request.remote_addr
        
        is_banned, ban_reason = self.reputation.is_banned(client_ip)
        if is_banned and client_ip not in self.whitelist:
            abort(403, description=f"TITANIUM KALKANI: Erisim Engellendi. Sebep: {ban_reason}")
            
        if client_ip in self.whitelist:
            return
            
        if not self.geofence.check_ip(client_ip):
            abort(403, description="GeoBlock: Ulke İzni Yok")
            
        if not self.traffic.allow_request(client_ip):
            self.reputation.ban(client_ip, "Hiz Limiti Asimi (DoS Saldirisi)", 50)
            abort(429, description="TITANIUM KALKANI: Cok Fazla Istek (Hiz Limiti)")
            
        if session:
            if not self.fingerprint.check_integrity(session):
                session.clear()
                abort(403, description="TITANIUM KALKANI: Oturum Ihlali (Session Hijacking)")

        payloads = [
            request.path,
            request.query_string.decode('utf-8', errors='ignore'),
            request.data.decode('utf-8', errors='ignore')
        ]
        
        for k, v in request.form.items():
            payloads.append(k)
            payloads.append(str(v))
            
        full_payload = " ".join(payloads)
        
        beh_score, beh_findings = self.behavior.track(client_ip, request.path)
        
        risk_score, findings = self.scan_threats(client_ip, full_payload, request.headers)
        
        risk_score += beh_score
        findings.extend(beh_findings)
        
        entropy_findings = self.entropy.analyze_request(request.form)
        if entropy_findings:
            risk_score += 20 * len(entropy_findings)
            for ef in entropy_findings:
                findings.append(f"{ef['msg']} in {ef['param']}")

        if risk_score > 0:
            action = "LOG"
            if risk_score >= ShieldConfig.RISK_SCORE_BAN:
                action = "BAN"
            elif risk_score >= ShieldConfig.RISK_SCORE_BLOCK:
                action = "BLOCK"
                
            report = self.forensics.build_report(client_ip, findings, risk_score, action)
            self.forensics.log_threat(report)
            
            if action == "BAN":
                self.reputation.ban(client_ip, ", ".join(findings), risk_score)
                abort(403, description="TITANIUM KALKANI: Kritik Tehdit Algilandi (BAN)")
            elif action == "BLOCK":
                abort(403, description="TITANIUM KALKANI: Supheli Icerik Tespit Edildi")

    def scan_threats(self, ip, payload, headers):
        score = 0
        findings = []
        user_agent = headers.get('User-Agent', '')
        
        for pattern, weight in self.sigs.scanner_agents:
            if re.search(pattern, user_agent, re.IGNORECASE):
                score += weight
                findings.append(f"Zararli Istemci ({pattern})")
        
        if len(user_agent) < 5 and ip not in self.whitelist:
             score += 10
             findings.append("Supheli User-Agent Uzunlugu")

        norm_payload = SecurityUtils.normalize_payload(payload)
        
        for pattern, weight, name in self.sigs.sql_signatures:
            if re.search(pattern, norm_payload, re.IGNORECASE):
                score += weight
                findings.append(name)
                
        for pattern, weight, name in self.sigs.xss_signatures:
            if re.search(pattern, norm_payload, re.IGNORECASE):
                score += weight
                findings.append(name)
                
        for pattern, weight, name in self.sigs.rce_signatures:
            if re.search(pattern, norm_payload, re.IGNORECASE):
                score += weight
                findings.append(name)
                
        for pattern, weight, name in self.sigs.lfi_signatures:
            if re.search(pattern, norm_payload, re.IGNORECASE):
                score += weight
                findings.append(name)
                
        for pattern, weight, name in self.sigs.ssti_signatures:
            if re.search(pattern, norm_payload, re.IGNORECASE):
                score += weight
                findings.append(name)
                
        for pattern, weight, name in self.sigs.java_signatures:
            if re.search(pattern, norm_payload, re.IGNORECASE):
                score += weight
                findings.append(name)
        
        host = headers.get('Host', '').split(':')[0]
        allowed_hosts = {'127.0.0.1', 'localhost', request.remote_addr} 
        if host not in allowed_hosts and not host.replace('.','').isdigit(): 
             pass
             
        if request.method not in ['GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'DELETE']:
            score += 20
            findings.append(f"Gecersiz HTTP Yontemi ({request.method})")
            
        return score, findings

    def secure_response(self, response):
        response.headers['Server'] = "Titanium-Shield/2.0"
        response.headers['X-Powered-By'] = "Titanium-Core-TR"
        
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['X-Download-Options'] = 'noopen'
        response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
        
        csp_rules = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://code.jquery.com https://unpkg.com",
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com",
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com",
            "img-src 'self' data: blob:",
            "media-src 'self' blob: data:",
            "connect-src 'self'",
            "frame-ancestors 'self'",
            "object-src 'none'",
            "base-uri 'self'"
        ]
        response.headers['Content-Security-Policy'] = "; ".join(csp_rules)
        
        if response.content_type and 'text' in response.content_type:
             try:
                 content = response.get_data(as_text=True)
                 
                 sensitive_patterns = [
                     r"You have an error in your SQL syntax",
                     r"Warning: mysql_", 
                     r"Unclosed quotation mark",
                     r"werkzeug.exceptions",
                     r"jinja2\.exceptions",
                     r"Traceback \(most recent call last\)",
                     r"Internal Server Error",
                     r"KeyError:",
                     r"ValueError:",
                     r"NameError:"
                 ]
                 
                 found_leak = False
                 for pattern in sensitive_patterns:
                     if re.search(pattern, content, re.IGNORECASE):
                         found_leak = True
                         break
                         
                 if found_leak:
                     self.forensics.log_threat({
                        "event": "VERI_SIZINTISI_ENGELLENDI",
                        "zaman": SecurityUtils.get_time_iso(),
                        "url": request.url
                     })
                     
                     safe_html = """
                     <!DOCTYPE html>
                     <html lang="tr">
                     <head>
                         <meta charset="UTF-8">
                         <title>Guvenlik Uyarisi</title>
                         <style>
                             body { font-family: sans-serif; text-align: center; padding: 50px; background: #f8f9fa; color: #333; }
                             .error-box { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); display: inline-block; }
                             h1 { color: #dc3545; margin-bottom: 20px; }
                             p { color: #6c757d; }
                             .ref { font-size: 0.8em; margin-top: 20px; color: #adb5bd; }
                         </style>
                     </head>
                     <body>
                         <div class="error-box">
                            <h1>Güvenlik Protokolü Devrede</h1>
                            <p>Sistem işlenemeyen bir veri tespit etti ve işlemi durdurdu.</p>
                            <p>Lütfen daha sonra tekrar deneyiniz.</p>
                            <div class="ref">Referans Kodu: TITANIUM-ERR-TR</div>
                         </div>
                     </body>
                     </html>
                     """
                     response.set_data(safe_html)
                     response.status_code = 500
                     
             except Exception:
                 pass
        
        return response

guardian = SecurityGuardian()
