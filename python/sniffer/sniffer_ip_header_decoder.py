from ctypes import *
import os
import socket
import struct
import sys

# class	IP(Structure):
# 	_fields_ = [
# 		("ihl", c_ubyte, 4),
# 		("version", c_ubyte, 4),
# 		("tos", c_ubyte, 8),
# 		("len", c_ushort, 16),
# 		("id", c_ushort, 16),
# 		("offset", c_ushort, 16),
# 		("ttl", c_ubyte, 8),
# 		("protocol_num", c_ubyte, 8),
# 		("sum", c_ushort, 16),
# 		("src", c_uint32, 32),
# 		("dst", c_uint32, 32)
# 	]

# 	def	__new__(cls, socket_buffer=None):
# 		return cls.from_buffer_copy(socket_buffer)
	
# 	def __init__(self, socket_buffer=None):
# 		self.src_address = socket.inet_ntoa(struct.pack("<L",self.src))
# 		self.dst_address = socket.inet_ntoa(struct.pack("<L",self.dst))

DATA_LEN = 65535

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
			print(f"Protocol: {ip_header.protocol} {ip_header.src_address} -> {ip_header.dst_address}")
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