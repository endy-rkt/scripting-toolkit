import sys
import socket
import threading

CONN_NUMBER = 5

DATA_LEN = 4096

HEX_FILTER = ''.join([(len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)])

MAX_DATA_LEN = DATA_LEN * 100

TIMEOUT = 2

#Print hexadump (hexa + printable str) from bytes
def hexdump(src, length=16, show=True):
	if isinstance(src, bytes):
		src = src.decode()
	
	results = list()
	for i in range(0, len(src), length):
		word = str(src[i:i+length])
		printable = word.translate(HEX_FILTER)
		hexa = ' '.join([f"{ord(c):02X}" for c in word])
		hexwidth = length*3
		results.append(f"{i:04x} {hexa:<{hexwidth}} {printable}")
	
	if show:
		for line in results:
			print(line)
	else:
		return results

def	receive_from(connection):
	buffer = b""
	dataSize = 0
	connection.settimeout(TIMEOUT)
	try:
		while True:
			data = connection.recv(DATA_LEN)
			if not data or dataSize + DATA_LEN > MAX_DATA_LEN:
				break
			buffer += data
			dataSize += DATA_LEN
	except Exception as e:
		pass
	return buffer

def	request_handler(buffer):
	#perform packet modifications
	return buffer

def	response_handler(buffer):
	#perform packet modifications
	return buffer

def proxy_handler(client_socket, remote_host, remote_port, receive_first):
	remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	remote_socket.connect((remote_host, remote_port))

	remote_buffer = b""
	if receive_first:
		remote_buffer = receive_from(remote_socket)
		hexdump(remote_buffer)
	
	remote_buffer = response_handler(remote_buffer)
	if len(remote_buffer):
		print(f"[<==] Sending {len(remote_buffer)} bytes to localhost.")
		client_socket.send(remote_buffer)
	
	while True:
		local_buffer = receive_from(client_socket)
		if len(local_buffer):
			print(f"[==>] Received {len(local_buffer)} bytes from localhost.")
			hexdump(local_buffer)

			local_buffer = request_handler(local_buffer)
			remote_socket.send(local_buffer)
			print("[==>] Sent to remote.")
		
		remote_buffer = receive_from(remote_socket)
		if len(remote_buffer):
			print(f"[<==] Received {len(remote_buffer)} bytes from remote.")
			hexdump(remote_buffer)

			remote_buffer = response_handler(remote_buffer)
			client_socket.send(remote_buffer)
			print("[<==] Sent to localhost.")
		
		if not len(local_buffer) or not len(remote_buffer):
			client_socket.close()
			remote_socket.close()
			print("[*] No more data. Closing connections.")
			break

def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	
	try:
		server.bind((local_host, local_port))
	except Exception as e:
		print(f"problem on bind {e}")

		print(f"[!!] Failed to listen on {local_host}:{local_port}")
		print(f"[!!] Check for other listening sockets or correct permissions.")
		sys.exit(0)

	print(f"[*] Listening on {local_host}:{local_port}")
	server.listen(CONN_NUMBER)
	while True:
		client_socket, addr = server.accept()
		print(f"> received incoming connection from {addr[0]}:{addr[1]}")
		proxy_thread = threading.Thread(target=proxy_handler, args=(client_socket, remote_host, remote_port, receive_first))
		proxy_thread.start()

def	main():
	if len(sys.argv[1:]) != 5:
		print("Usage: ./my_proxy.py [localhost] [localport] [remotehost] [remoteport] [receive_first]")
		print("Example:	./my_proxy.py 127.0.0.1 9000 10.12.132.1 9000 True")
		sys.exit(0)

	local_host = sys.argv[1]
	local_port = int(sys.argv[2])
	remote_host = sys.argv[3]
	remote_port = int(sys.argv[4])
	receive_first = sys.argv[5]
	receive_first = "True" in receive_first

	server_loop(local_host, local_port, remote_host, remote_port, receive_first)

if __name__ == "__main__":
	main()
