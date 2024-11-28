import os
from datetime import datetime
import sys
import socket

def checking_args():
	if len(sys.argv) > 1:
		now = datetime.now()
		today = datetime.today()
		name = socket.gethostname()
		user_ip = socket.gethostbyname(socket.gethostname())

		print("Starting Nmap RELQ at", today.date().isoformat() ,now.strftime("%H:%M"))
		print("Nmap scan report for ", name, user_ip)

	else: #if no args
		print("nmap -v -A scanme.nmap.org")
		print("nmap -v -sn 192.168.0.0/16 10.0.0.0/8")
		print("nmap -v -iR 10000 -Pn -p 80")


def socket_setup():
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
			print(port, "/tcp", "open")
		if result == 110:
			print(port, "/tcp", "filtered")

	else:
		port = 0
		closed_ports = 0
		while port < 100:
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
			if result != 0:
				closed_ports += 1

			if result == 110:
				print(port, "/tcp", "filtered")

			if result == 0:
				print(port, "/tcp", "open")
			port += 1

		print("Not shown:", closed_ports,"closed ports")
		print("PORT", "  STATE", "SERVICE")