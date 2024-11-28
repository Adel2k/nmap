import socket
import sys

if len(sys.argv) > 1:
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	ip = sys.argv[1]
	if len(sys.argv) > 2:
		port = sys.argv[2]
		result = server.connect_ex((ip, int(port)))
		if result == 0:
			print(f"port {port} is open")
	else:
		port = 0
		while port <= 1000:
			result = server.connect_ex((ip, int(port)))
			if result == 0:
				print(f"port {port} is open")
			port = port + 1
			

else:
	print("nmap -v -A scanme.nmap.org")
	print("nmap -v -sn 192.168.0.0/16 10.0.0.0/8")
	print("nmap -v -iR 10000 -Pn -p 80")