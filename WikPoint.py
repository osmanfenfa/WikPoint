"""
  Vulnerability Scanner
  Modes: URL · Password · Code · Port · HTTP Headers · File
"""
import re
import sys
import math
import socket
import os
from datetime import datetime
from urllib.parse import urlparse, parse_qs

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
WHITE  = "\033[97m"
DIM    = "\033[2m"

def c(text, colour): return f"{colour}{text}{RESET}"
def header(title):
    line = "─" * 60
    print(f"\n{c(line, CYAN)}\n  {c(title, BOLD + WHITE)}\n{c(line, CYAN)}")
def badge(sev):
    return {
        "CRITICAL": c("[CRITICAL]", RED + BOLD),
        "WARNING" : c("[WARNING] ", YELLOW + BOLD),
        "INFO"    : c("[INFO]    ", CYAN),
        "PASS"    : c("[PASS]    ", GREEN),
    }.get(sev, f"[{sev}]")
def finding(sev, title, detail=""):
    print(f"  {badge(sev)} {c(title, WHITE)}")
    if detail:
        print(f"            {c(detail, DIM)}")
def summary_line(counts):
    parts = []
    if counts["CRITICAL"]: parts.append(c(f"{counts['CRITICAL']} critical", RED))
    if counts["WARNING"] : parts.append(c(f"{counts['WARNING']} warning",  YELLOW))
    if counts["INFO"]    : parts.append(c(f"{counts['INFO']} info",        CYAN))
    if counts["PASS"]    : parts.append(c(f"{counts['PASS']} passed",      GREEN))
    print(f"\n  Summary: {' · '.join(parts) if parts else 'No findings.'}\n")


#  URL Scanner
URL_CHECKS = [
    # (severity, regex/callable, title, detail)
    ("CRITICAL", lambda u: u.startswith("http://"),
     "Unencrypted HTTP",
     "All data is transmitted in plain text. Upgrade to HTTPS."),

    ("CRITICAL", lambda u: bool(re.search(r"[?&](redirect|url|callback|next|return|goto|dest|target)=", u, re.I)),
     "Open-redirect parameter",
     "redirect= / next= style params can be abused to send users to malicious sites."),

    ("CRITICAL", lambda u: bool(re.search(r"[?&][^=]+=.*(<script|javascript:|onerror=|onload=|alert\()", u, re.I)),
     "XSS payload in query string",
     "Script-like content in parameters suggests a cross-site scripting attempt."),

    ("CRITICAL", lambda u: bool(re.search(r"[?&][^=]+=(.*('|%27|%22|--|UNION\s|SELECT\s|DROP\s|INSERT\s|OR\s1=1))", u, re.I)),
     "SQL injection pattern",
     "Quote chars or SQL keywords detected. May indicate an injection attempt."),

    ("CRITICAL", lambda u: bool(re.search(r"[?&][^=]+=.*(\.\./|%2e%2e|%252e)", u, re.I)),
     "Path traversal pattern",
     "../ sequences in parameters can expose server files."),

    ("WARNING", lambda u: bool(re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", urlparse(u).netloc)),
     "Raw IP address instead of domain",
     "Legitimate services rarely use bare IPs — possible phishing indicator."),

    ("WARNING", lambda u: len(u) > 200,
     "Unusually long URL",
     f"URLs over 200 chars often hide malicious payloads via obfuscation."),

    ("WARNING", lambda u: bool(re.search(r"[?&][^=]+=.*\.(exe|bat|sh|ps1|msi|dmg|vbs|cmd)", u, re.I)),
     "Executable extension in parameter",
     "May trigger an automatic download of a potentially malicious file."),

    ("WARNING", lambda u: (lambda h: h.count('.') > 4)(urlparse(u).netloc),
     "Excessive subdomain depth",
     "4+ subdomain levels are a common phishing trick (e.g. paypal.com.evil.io)."),

    ("WARNING", lambda u: bool(re.search(r"%[0-9a-fA-F]{2}", u)),
     "Percent-encoded characters",
     "Encoding can be used to bypass naïve input filters."),

    ("INFO", lambda u: bool(re.search(r"[?&](id|user|username|email|phone)=\d+", u, re.I)),
     "Numeric ID in URL parameter",
     "Direct object references without auth checks may expose other users' data (IDOR)."),

    ("INFO", lambda u: bool(re.search(r"token=|api_key=|apikey=|access_token=", u, re.I)),
     "Token/API key in URL",
     "Secrets in URLs appear in server logs, browser history, and referrer headers."),
]

def scan_url(url):
    header("URL Vulnerability Scan")
    print(f"  Target: {c(url, CYAN)}\n")
    counts = {"CRITICAL": 0, "WARNING": 0, "INFO": 0, "PASS": 0}
    found  = False
    for sev, check, title, detail in URL_CHECKS:
        try:
            hit = check(url) if callable(check) else bool(re.search(check, url, re.I))
        except Exception:
            hit = False
        if hit:
            finding(sev, title, detail)
            counts[sev] += 1
            found = True
    if not found:
        finding("PASS", "No obvious vulnerability patterns detected.")
        counts["PASS"] += 1
    # parsed extras
    parsed = urlparse(url)
    parampapapa = parse_qs(parsed.query)
    if parampapapa:
        print(f"\n  {c('Parameters found:', DIM)}")
        for k, v in parampapapa.items():
            print(f"    {c(k, YELLOW)} = {v}")
    summary_line(counts)


#Password Auditor
COMMON_PASSWORDS = {
    "password","123456","123456789","12345678","12345","1234567","qwerty",
    "abc123","football","iloveyou","admin","letmein","monkey","1234567890",
    "welcome","login","dragon","master","sunshine","princess","shadow",
    "superman","michael","baseball","batman","trustno1","password1",
}

def password_entropy(pw):
    charset = 0
    if re.search(r"[a-z]", pw): charset += 26
    if re.search(r"[A-Z]", pw): charset += 26
    if re.search(r"[0-9]", pw): charset += 10
    if re.search(r"[^a-zA-Z0-9]", pw): charset += 32
    return len(pw) * math.log2(charset) if charset else 0
def scan_password(pw):
    header("Password Audit")
    counts = {"CRITICAL": 0, "WARNING": 0, "INFO": 0, "PASS": 0}

    if pw.lower() in COMMON_PASSWORDS:
        finding("CRITICAL", "Extremely common password", "Appears in every brute-force wordlist — change immediately.")
        counts["CRITICAL"] += 1
        summary_line(counts)
        return
    if len(pw) < 8:
        finding("CRITICAL", f"Too short ({len(pw)} chars)", "Minimum 12 recommended. Short passwords cracked in seconds.")
        counts["CRITICAL"] += 1
    elif len(pw) < 12:
        finding("WARNING", f"Short password ({len(pw)} chars)", "At least 12 characters strongly recommended.")
        counts["WARNING"] += 1
    else:
        finding("PASS", f"Good length ({len(pw)} chars)")
        counts["PASS"] += 1
    
    # Character classes
    checks = [
        (r"[A-Z]",        "Uppercase letters"),
        (r"[a-z]",        "Lowercase letters"),
        (r"[0-9]",        "Digits"),
        (r"[^A-Za-z0-9]", "Special characters"),
    ]
    for pattern, label in checks:
        if re.search(pattern, pw):
            finding("PASS", f"Contains {label}")
            counts["PASS"] += 1
        else:
            finding("WARNING", f"Missing {label}", "Each character class multiplies the search space.")
            counts["WARNING"] += 1

    # Patterns
    if re.search(r"(.)\1{2,}", pw):
        finding("WARNING", "Repeated characters (e.g. 'aaa')", "Lowers effective entropy.")
        counts["WARNING"] += 1
    if re.search(r"(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)", pw, re.I):
        finding("WARNING", "Sequential characters detected", "Sequences like '123' or 'abc' are tried first.")
        counts["WARNING"] += 1
    if re.search(r"(qwerty|asdf|zxcv)", pw, re.I):
        finding("WARNING", "Keyboard walk pattern detected", "e.g. 'qwerty' is trivially guessable.")
        counts["WARNING"] += 1

    # Entropy
    entropy = password_entropy(pw)
    ent_label = (
        "Excellent" if entropy >= 80 else
        "Good"      if entropy >= 60 else
        "Fair"      if entropy >= 40 else
        "Weak"
    )
    sev = "PASS" if entropy >= 60 else "WARNING" if entropy >= 40 else "CRITICAL"
    finding(sev, f"Estimated entropy: {entropy:.1f} bits ({ent_label})",
            ">=60 bits is considered reasonably secure.")
    counts[sev] += 1

    # Overall strength
    score = counts["PASS"] - counts["CRITICAL"] * 2 - counts["WARNING"]
    strength = (
        c("STRONG ",   GREEN)  if score >= 5 else
        c("MODERATE",  YELLOW) if score >= 2 else
        c("WEAK ",     RED)
    )
    print(f"\n  Overall strength: {strength}")
    summary_line(counts)


# Code Scanner
CODE_RULES = [
    ("CRITICAL", r"eval\s*\(",                        "eval() call",                  "Executes arbitrary strings — enables RCE if input is unsanitised."),
    ("CRITICAL", r"exec\s*\(",                        "exec() call",                  "Same risk as eval()."),
    ("CRITICAL", r"innerHTML\s*=",                    "innerHTML assignment",          "Use textContent or DOMPurify instead."),
    ("CRITICAL", r"document\.write\s*\(",             "document.write()",             "Can be abused for XSS injection."),
    ("CRITICAL", r"(password|secret|api.?key|token|passwd)\s*[:=]\s*['\"][^'\"]{4,}", "Hardcoded credential",    "Store secrets in env vars, not source code."),
    ("CRITICAL", r"(SELECT|INSERT|UPDATE|DELETE|DROP)\s+.+\s+(FROM|INTO|TABLE|WHERE)", "Raw SQL string",         "Use parameterised queries or an ORM to prevent SQLi."),
    ("CRITICAL", r"(subprocess\.call|os\.system|os\.popen|shell=True|popen\s*\()",    "Shell execution",         "User input reaching shell commands enables command injection."),
    ("CRITICAL", r"pickle\.loads?\s*\(",              "pickle.load() call",           "Deserialising untrusted data with pickle leads to RCE."),
    ("CRITICAL", r"(yaml\.load\s*\([^,)]+\)(?!.*Loader))", "yaml.load() without Loader", "Use yaml.safe_load() to prevent arbitrary code execution."),
    ("WARNING",  r"(Math\.random|random\.random)\s*\(\).*(?:token|key|nonce|csrf|secret)", "Weak PRNG for secret", "Use secrets.token_hex() or crypto.getRandomValues() instead."),
    ("WARNING",  r"(MD5|md5|SHA1|sha1)\s*\(",         "Weak hash algorithm (MD5/SHA1)", "Use SHA-256+ for security-sensitive hashing."),
    ("WARNING",  r"console\.(log|warn|info)\s*\(.*?(password|token|secret|key)", "Sensitive data logged", "Secrets in logs are a common data-leak vector."),
    ("WARNING",  r"print\s*\(.*?(password|secret|token|key)",                    "Sensitive data printed","Remove debug prints before deployment."),
    ("WARNING",  r"verify\s*=\s*False",               "SSL verification disabled",   "Never disable certificate verification in production."),
    ("WARNING",  r"ALLOWED_HOSTS\s*=\s*\[?\s*['\"]?\*",    "Wildcard ALLOWED_HOSTS",      "Restrict ALLOWED_HOSTS to known domains."),
    ("WARNING",  r"DEBUG\s*=\s*True",                 "DEBUG mode enabled",           "Never run DEBUG=True in production."),
    ("WARNING",  r"//\s*noqa|#\s*nosec|#\s*type:\s*ignore", "Security linter suppression","Review each suppression comment carefully."),
    ("INFO",     r"(TODO|FIXME|HACK|XXX|WORKAROUND).{0,60}(auth|security|xss|sql|injection|vuln)", "Security-related TODO/FIXME", "Track and resolve security debt."),
    ("INFO",     r"https?://\S+",                     "Hardcoded URL",               "Hard-coded URLs complicate environment rotation."),
    ("INFO",     r"(127\.0\.0\.1|localhost)",         "Localhost reference",          "Ensure this is intentional and not an accidental staging leak."),
]

def scan_code(code, source="<input>"):
    header(f"Code Vulnerability Scan  —  {source}")
    lines   = code.splitlines()
    counts  = {"CRITICAL": 0, "WARNING": 0, "INFO": 0, "PASS": 0}
    matched = set()
    for sev, pattern, title, detail in CODE_RULES:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.I):
                if title not in matched:
                    finding(sev, title, detail)
                    print(f"            {c(f'Line {i}:', DIM)} {c(line.strip()[:80], DIM)}")
                    counts[sev] += 1
                    matched.add(title)
                break  # one report per rule
    if not matched:
        finding("PASS", "No obvious vulnerability patterns detected.")
        counts["PASS"] += 1

    summary_line(counts)


#Port Scanner
WELL_KNOWN_PORTS = {
    21: "FTP",   22: "SSH",    23: "Telnet",  25: "SMTP",
    53: "DNS",   80: "HTTP",   110: "POP3",   143: "IMAP",
    443: "HTTPS",445: "SMB",   3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-alt", 27017: "MongoDB",
}
RISKY_PORTS = {21, 23, 110, 143, 445, 3389, 6379, 27017}

def scan_ports(host, ports=None, timeout=0.5):
    header(f"Port Scanner  —  {host}")
    if ports is None:
        ports = sorted(WELL_KNOWN_PORTS.keys())
    try:
        ip = socket.gethostbyname(host)
        print(f"  Resolved: {c(ip, CYAN)}\n")
    except socket.gaierror:
        print(c(f"  Cannot resolve host: {host}\n", RED))
        return

    open_ports = []
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                open_ports.append(port)
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
    if not open_ports:
        finding("PASS", "No open ports found in the scanned range.")
    else:
        for port in open_ports:
            service = WELL_KNOWN_PORTS.get(port, "Unknown")
            sev     = "WARNING" if port in RISKY_PORTS else "INFO"
            risk    = " ← potentially risky service" if port in RISKY_PORTS else ""
            finding(sev, f"Port {port}/tcp OPEN  [{service}]", risk.strip())
    print(f"\n  Scanned {len(ports)} ports · {len(open_ports)} open\n")


# File Scanner
def scan_file(filepath):
    if not os.path.isfile(filepath):
        print(c(f"\n  File not found: {filepath}\n", RED))
        return
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            code = f.read()
    except Exception as e:
        print(c(f"\n  Cannot read file: {e}\n", RED))
        return
    scan_code(code, source=os.path.basename(filepath))


#Main Menu
MENU = """
  ╔══════════════════════════════════════╗
  ║   Vulnerability Scanner              ║
  ╠══════════════════════════════════════╣
  ║  1. Scan a URL                       ║
  ║  2. Audit a password                 ║
  ║  3. Scan a code snippet              ║
  ║  4. Scan open ports on a host        ║
  ║  5. Scan a source file               ║
  ║  0. Exit                             ║
  ╚══════════════════════════════════════╝
"""

def main():
    print(c(MENU, CYAN))
    while True:
        choice = input(c("  Select option: ", BOLD)).strip()

        if choice == "1":
            url = input("  Enter URL: ").strip()
            if url:
                scan_url(url)
        elif choice == "2":
            import getpass
            pw = getpass.getpass("  Enter password to audit: ")
            if pw:
                scan_password(pw)
        elif choice == "3":
            print("  Paste code (enter a blank line when done):")
            lines = []
            while True:
                line = input()
                if line == "" and lines and lines[-1] == "":
                    break
                lines.append(line)
            if lines:
                scan_code("\n".join(lines))
        elif choice == "4":
            host  = input("  Host/IP: ").strip()
            raw   = input("  Ports (comma-separated, blank for defaults): ").strip()
            ports = [int(p.strip()) for p in raw.split(",") if p.strip().isdigit()] if raw else None
            if host:
                scan_ports(host, ports)
        elif choice == "5":
            path = input("  File path: ").strip()
            if path:
                scan_file(path)
        elif choice == "0":
            print(c("\n  Goodbye!\n", GREEN))
            sys.exit(0)
        else:
            print(c("  Invalid option.\n", YELLOW))

        again = input(c("\n  Return to menu? (y/n): ", DIM)).strip().lower()
        if again != "y":
            print(c("\n  Goodbye!\n", GREEN))
            break
        print(c(MENU, CYAN))

if __name__ == "__main__":
    main()