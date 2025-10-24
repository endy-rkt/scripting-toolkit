import os
import paramiko
import socket
import sys
import threading

CONN_NUM = 10

CWD = os.path.dirname(os.path.realpath(__file__))

DATA_LEN = 1024

DEFAULT_USER = "user"

DEFAULT_PASSWD = "passwd"

#test key from paramiko repo
HOSTKEY = paramiko.RSAKey(filename=os.path.join(CWD, "test_rsa.key"))

SESSION_NUM = 20

SSH_BANNER = "Welcome to bh_ssh"

class Server(paramiko.ServerInterface):
	def __init__(self):
		self.event = threading.Event()
	
	def	check_channel_request(self, kind, chanid):
		if kind == "session":
			return paramiko.OPEN_SUCCEEDED
		return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

	def	check_auth_password(self, username, password):
		if username == DEFAULT_USER and password == DEFAULT_PASSWD:
			return paramiko.AUTH_SUCCESSFUL
	
if	__name__ == "__main__":
	server_ip = "127.0.0.1"
	ssh_port = 9000
	try:
		server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		server_socket.bind((server_ip, ssh_port))
		server_socket.listen(CONN_NUM)
		print("[+] Listening for connection...")
		client, addr = server_socket.accept()
	except Exception as e:
		print("[-] Listen failed: " + str(e))
		sys.exit(1)
	else:
		print("[+] Got a connection!", client, addr)

	bhSession = paramiko.Transport(client)
	bhSession.add_server_key(HOSTKEY)
	server = Server()
	bhSession.start_server(server=server)

	chan = bhSession.accept(SESSION_NUM)
	if chan is None:
		print("*** No channel.")
		sys.exit(1)
	
	print("[+] Authenticated!")
	print(chan.recv(DATA_LEN))
	chan.send(SSH_BANNER)
	try:
		while True:
			command = input("Enter command: ")
			if command != "exit":
				chan.send(command)
				r = chan.recv(DATA_LEN * 8)
				print(r.decode())
			else:
				chan.send("exit")
				print("exiting")
				bhSession.close()
				break
	except KeyboardInterrupt:
		bhSession.close()
		