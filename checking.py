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

def reading_ports(importent_ports):
	ports = []
	service = []
	models = []
	with open(importent_ports, 'r') as f:
		for line in f:
			if line and not line.startswith('#'):
				parts = line.split()
				if len(parts) >= 2:
					port_protocol = parts[1]
					service_name = parts[0]
					port = port_protocol.split('/')[0]
					model = port_protocol.split('/')[1]
					if port.isdigit():
						ports.append(int(port))
					models.append(model)
					service.append(service_name)

	return ports, service, models
	
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
			print(port, models, "open")
		if result == 110:
			print(port, models, "filtered")

	else:
		closed_ports = 0
		status_array = []
		ports_array = []
		models_array = []
		service_array = []
		ports, service, models = reading_ports("/home/adel/Desktop/cyber/project2/Nmap/importent_ports")
		for port,service_name,model in zip(ports, service, models):
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
				models_array.append(model)
				service_array.append(service_name)

		print("Not shown:", closed_ports,"closed ports")
		print("PORT", "   STATE", "SERVICE")
		for p, s, m, a in zip(ports_array, status_array, models_array, service_array):
			if s == 0:
				print(p, m, "open", a)
			elif s == 110:
				print(p, m, "filltered", a)



