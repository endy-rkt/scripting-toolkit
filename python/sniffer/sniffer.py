# can we retrieve like packet layer details from socket using sock_stream like ethernet, packet?
# why we doesn't retrieve like a full network datagram when using sock_stream like ethernet + packet + datagram + data? why we see just the data when for eg sending some text?
# why in c we see directly text no raw byte like in python for sock_stream?
# why we don't see text like in sock_stream for sock_raw?

import os
import socket

DATA_LEN = 65565

HOST = "127.0.0.1"

def	main():
	if os.name == "nt":
		socket_protocol = socket.IPPROTO_IP
	else:
		socket_protocol = socket.IPPROTO_ICMP
	
	sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
	sniffer.bind((HOST, 0))
	sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

	if os.name == "nt":
		sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
	print("[+] Sniffing packet on...")
	print(sniffer.recvfrom(DATA_LEN))

	if os.name == "nt":
		sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
	
if __name__ == "__main__":
	main()