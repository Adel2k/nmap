import re
import ipaddress
import argparse
import socket

#############################################################
def check_port(ip, port, server, type):
	server.settimeout(3)
	if type == "udp":
		try:
			server.sendto(b"", (ip, port))
			server.recvfrom(1024)
			if socket.timeout:
				return 111
			return 0
		except KeyboardInterrupt:
			exit(1)
		except socket.error as e:
			if e.errno == 111:
				return 111
			return 111
	elif type == "tcp":
		return server.connect_ex((ip, port))

#############################################################
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

#############################################################
def find_service(port, ports, servie):
	for p, s in zip(ports,servie):
		if port[0] == p:
			return s

#############################################################
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

