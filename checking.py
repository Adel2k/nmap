import os
from datetime import datetime
import sys
import socket
from ping3 import ping, verbose_ping
import time
import argparse
import re
import ipaddress

def if_ip(arg):
	try:
		ipaddress.ip_address(arg)
		return True
	except ValueError:
		pass
	domain_pattern = re.compile(
		r"^(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,6}$"
	)
	if domain_pattern.match(arg):
		return False

	return False


def parse_ports(arg):
	if '-' in arg:
		start, end = arg.split('-')
		try:
			start = int(start)
			end = int(end)
			if start > end:
				raise argparse.ArgumentTypeError("Start port must be less than or equal to end port.")
			return list(range(start, end + 1))
		except ValueError:
			raise argparse.ArgumentTypeError("Ports must be integers.")
	else:
		try:
			return [int(arg)]
		except ValueError:
			raise argparse.ArgumentTypeError("Port must be an integer.")


def starting():
	parser = argparse.ArgumentParser(description="Can pass hostnames, IP addresses, networks, etc.")
	parser.add_argument("host", help="Hostname or IP address to nmap.")
	parser.add_argument("-p", "--port", type=parse_ports, help="Specify a port (optional).")
	args = parser.parse_args()


	now = datetime.now()
	today = datetime.today()
	if if_ip(args.host) == True:
		name = socket.gethostbyaddr(args.host)[0]
	else:
		name = args.host

	user_ip = socket.gethostbyname(name)
	latency = ping(user_ip, unit='ms')

	print("Starting Nmap RELQ at", today.date().isoformat() ,now.strftime("%H:%M"))
	print(f"Nmap scan report for {name} ({user_ip})")
	if latency is None:
		print("Host is unreachable.")
	else:
		print(f"Host is up ({latency:.2f}s latency).")
	return args.host, args.port

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
					model = port_protocol
					port = port_protocol.split('/')[0]
					if port.isdigit():
						ports.append(int(port))
					models.append(model)
					service.append(service_name)

	return ports, service, models
	



def find_service(port, ports, servie):
	for p, s in zip(ports,servie):
		if port[0] == p:
			return s
		


def socket_setup(ip, port):
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	if len(port) == 1:
		try:
			result = server.connect_ex((ip, *port))

		except OverflowError:
			print("Error: port must be 0-65535")
			server.close()
			exit(1)

		except ValueError:
			print("Error: invalid literal for int() with base 10")
			server.close()
			exit(1)
		
		ports, service, models = reading_ports("/home/adel/Desktop/cyber/project2/Nmap/importent_ports")

		print("PORT", "  STATE", "SERVICE")
		if result == 0:
			ss = find_service(port,ports, service)
			print(f"{port[0]}/tcp  open {ss}")
		elif result == 110:
			ss = find_service(port,ports, service)
			print(f"{port[0]}/tcp  filtered {ss}")
		elif result == 111:
			ss = find_service(port,ports, service)
			print(f"{port[0]}/tcp  closed {ss}")
		server.close()

	else:
		closed_ports = 0
		status_array = []
		ports_array = []
		models_array = []
		service_array = []
		ports, service, models = reading_ports("/home/adel/Desktop/cyber/project2/Nmap/importent_ports")
		for port, service_name, model in zip(ports, service, models):
			server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			server.settimeout(1)
			result = server.connect_ex((ip, port))
			if result == 111:
				closed_ports += 1
			elif result == 0:
				ports_array.append(port)
				status_array.append(result)
				models_array.append(model)
				service_array.append(service_name)
				
			server.close()
			time.sleep(0.1)
		print("Not shown:", closed_ports,"closed ports")
		print("PORT", "  STATE", "SERVICE")
		for p, s, m, a in zip(ports_array, status_array, models_array, service_array):
			if s == 0:
				print(m, "open", a)
			elif s == 11:
				print(m, "filltered", a)




