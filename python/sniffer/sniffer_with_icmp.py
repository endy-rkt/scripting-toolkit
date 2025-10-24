from ctypes import *
import ipaddress
import os
import socket
import struct
import sys

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

def	sniff(host):
	if os.name == "nt":
		socket_protocol = socket.IPPROTO_IP
	else:
		sockt_protocol = socket.IPPROTO_ICMP
	
	sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, sockt_protocol)
	sniffer.bind((host, 0))
	sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
	if os.name == "nt":
		sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
	
	try:
		print("[+] Sniffing packet on...")
		while True:
			raw_buffer = sniffer.recvfrom(DATA_LEN)[0]
			ip_header = IP(raw_buffer[0:20])
			# print(f"Protocol: {ip_header.protocol} {ip_header.src_address} -> {ip_header.dst_address}")
			if ip_header.protocol == ICMP_:
				print(f"Protocol: {ip_header.protocol} {ip_header.src_address} -> {ip_header.dst_address}")
				print(f"Version: {ip_header.ver}")
				print(f"Header Length: {ip_header.ihl} TTL: {ip_header.ttl}")
				#calcute where icmp packets start
				offset = ip_header.ihl * 4
				buf = raw_buffer[offset:offset + 8]
				#create our icmp structure
				icmp_header = ICMP(buf)
				print(f"ICMP -> Type: {icmp_header.type} Code: {icmp_header.code}\n")
	except KeyboardInterrupt:
		if os.name == "nt":
			sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
		sys.exit()

if __name__ == "__main__":
	if len(sys.argv) == 2:
		host = sys.argv[1]
	else:
		host = "127.0.0.1"
	sniff(host)