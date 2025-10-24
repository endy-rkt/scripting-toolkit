from ctypes import *
import ipaddress
import os
import socket
import struct
import sys
import threading
import time

#SUBNET TO TARGET
SUBNET = "127.0.0.0/24"
#magic string for ICMP responses
MESSAGE = "MAGIC_STRING"

DATA_LEN = 65535

ICMP_ = "ICMP"

class IP(Structure):
	def __init__(self, buff=None):
		header = struct.unpack('<BBHHHBBH4s4s', buff)
		self.ver = header[0] >> 4
		self.ihl = header[0] & 1
		
		self.tos = header[1]
		self.len = header[2]
		self.id = header[3]
		self.offset = header[4]
		self.ttl = header[5]
		self.protocol_num = header[6]
		self.sum = header[7]
		self.src = header[8]
		self.dst = header[9]

		self.src_address = socket.inet_ntoa(self.src)
		self.dst_address = socket.inet_ntoa(self.dst)

		self.protocol_map = {
			1:"ICMP",
			6:"TCP",
			17:"UDP"
		}
		try:
			self.protocol = self.protocol_map[self.protocol_num]
		except Exception as e:
			print(f"{str(e)} No protocol for {self.protocol_num}")
			self.protocol = str(self.protocol_num)

class	ICMP:
	def	__init__(self, buff):
		header = struct.unpack("<BBHHH", buff)
		self.type = header[0]
		self.code = header[1]
		self.sum = header[2]
		self.id = header[3]
		self.seq = header[4]

#spray out UDP datagram with our magic string
def	udp_sender():
	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
		min = None 
		for ip in ipaddress.ip_network(SUBNET).hosts():
			if min == None:
				min = ip
			max = ip
			sender.sendto(bytes(MESSAGE, 'utf8'), (str(ip), 65212))
		print(f"[+] Scan done from {min} to {max}")

class Scanner:
	def __init__(self, host):
		self.host = host
		if os.name == "nt":
			socket_protocol = socket.IPPROTO_IP
		else:
			sockt_protocol = socket.IPPROTO_ICMP

		self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, sockt_protocol)
		self.socket.bind((host, 0))
		self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
		if os.name == "nt":
			self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
	
	def	sniff(self):
		hosts_up = set([f'{str(self.host)} *'])
		try:
			while True:
				#read a packet
				raw_buffer = self.socket.recvfrom(DATA_LEN)[0]
				ip_header = IP(raw_buffer[0:20])
				
				if ip_header.protocol == ICMP_:
					#calcute where icmp packets start
					offset = ip_header.ihl * 4
					buf = raw_buffer[offset:offset + 8]
					#create our icmp structure
					icmp_header = ICMP(buf)

					if icmp_header.type == 3 and icmp_header.code == 3:
						if ipaddress.ip_address(ip_header.src_address) in ipaddress.IPv4Address(SUBNET):
							if raw_buffer[len(raw_buffer) - len(MESSAGE):] == bytes(MESSAGE, "utf8"):
								tgt = str(ip_header.src_address)
								if tgt != self.host and tgt not in hosts_up:
									hosts_up.add(str(ip_header.src_address))
									print(f"Host up: {tgt}")
		
		except KeyboardInterrupt:
			if os.name == "nt":
				self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
			print("\n User Interrupted.")
			if hosts_up:
				print(f"\n\nSummary: Hosts up on {SUBNET}")
				for host in sorted(hosts_up):
					print(f"{host}")
			sys.exit()


if __name__ == "__main__":
	if len(sys.argv) == 2:
		host = sys.argv[1]
	else:
		host = "127.0.0.1"
	s = Scanner(host)
	time.sleep(5)
	print("[+] Start scanning...")
	t = threading.Thread(target=udp_sender)
	t.start()
	s.sniff()