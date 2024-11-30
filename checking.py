import os
from datetime import datetime
import sys
import socket

def starting():
	now = datetime.now()
	today = datetime.today()
	name = socket.gethostname()
	user_ip = socket.gethostbyname(socket.gethostname())

	print("Starting Nmap RELQ at", today.date().isoformat() ,now.strftime("%H:%M"))
	print("Nmap scan report for ", name, user_ip)

def reading_sockets(importent_ports):
	ports = []
	with open(importent_ports, 'r') as f:
		for line in f:
			if line and not line.startswith('#'):
				parts = line.split()
				if len(parts) >= 2:
					port_protocol = parts[1]
					port = port_protocol.split('/')[0]
					if port.isdigit():
						ports.append(int(port))
	return ports
	
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
		closed_ports = 0
		status_array= []
		ports_array = []
		ports = reading_sockets("/home/adel/Desktop/cyber/project2/Nmap/importent_ports")
		for port in ports:
			try:
				result = server.connect_ex((ip, port))
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
			else:
				ports_array.append(port)
				status_array.append(result)

		print("Not shown:", closed_ports,"closed ports")
		print("PORT", "   STATE", "SERVICE")
		for p in ports_array and status_array:
			if status_array[p] == 0:
				print(*ports_array, "/tcp", "open")
			elif status_array[p] == 110:
				print(*ports_array, "/tcp", "filtered")


