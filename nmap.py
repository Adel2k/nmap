import socket
import sys
from datetime import datetime

if len(sys.argv) > 1:
	now = datetime.now()
	today = datetime.today()
	name = socket.gethostname()
	user_ip = socket.gethostbyname(socket.gethostname())

	print("Starting Nmap RELQ at", today.date().isoformat() ,now.strftime("%H:%M"))
	print("Nmap scan report for ", name, user_ip)

	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	ip = sys.argv[1]
	if len(sys.argv) > 2:
		port = sys.argv[2]
		try:
			result = server.connect_ex((ip, int(port)))
		except OverflowError:
			print("Error: port must be 0-65535")
			server.close()
			exit(1)
		except ValueError:
			print("Error: invalid literal for int() with base 10")
			server.close()
			exit(1)
		if result == 0:
			print("PORT", "  STATE", "SERVICE")
			print("42/tcp", "open")
	else:
		port = 0
		while port <= 1000:
			try:
				result = server.connect_ex((ip, int(port)))
			except OverflowError:
				print("Error: port must be 0-65535")
				server.close()
				exit(1)
			except ValueError:
				print("Error: invalid literal for int() with base 10")
				server.close()
				exit(1)
			if result == 0:
				print(f"port {port} is open")
			port = port + 1
			

else:
	print("nmap -v -A scanme.nmap.org")
	print("nmap -v -sn 192.168.0.0/16 10.0.0.0/8")
	print("nmap -v -iR 10000 -Pn -p 80")