import getpass
import paramiko

def	ssh_command(ip, port, user, passwd, cmd):
	client = paramiko.SSHClient()
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	client.connect(hostname=ip, port=port, username=user, password=passwd)

	_, stdout, stderr = client.exec_command(command=cmd)
	output = stdout.readlines() + stderr.readlines()
	if output:
		print("------ Output ------")
		for line in output:
			print(line.strip())

if __name__ == "__main__":
	#user = getpass.getuser()
	user = input("Username: ")
	passwd = getpass.getpass()

	ip = input("Enter server IP: ") or "127.0.0.1"
	port = input("Enter port or <CR>: ") or 22
	cmd = input("Enter command or <CR>: ") or "id"
	ssh_command(ip, port, user, passwd, cmd)
	