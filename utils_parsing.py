import re
import ipaddress
import argparse

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

def find_service(port, ports, servie):
	for p, s in zip(ports,servie):
		if port[0] == p:
			return s

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


def parse_ports(arg):
	global flag_for_range
	if '-' in arg:
		start, end = arg.split('-')
		try:
			flag_for_range = True
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

