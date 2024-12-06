import re
import ipaddress
import argparse
import binascii
import socket
from headers import *
from scapy.all import IP, TCP, sr1
from syn_scan import *


def set_header(source_ip, dest_ip, port):
	ip_header = create_ip_header(source_ip, dest_ip)
	tcp_header = create_tcp_header(source_ip, dest_ip, 12345, port)
	return ip_header, tcp_header

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
	elif type == "syn":
		server.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
		ip_header, tcp_header = set_header(socket.gethostbyname(socket.gethostname()), socket.gethostbyaddr(ip)[2][0], port)
		packet = ip_header + tcp_header
		server.sendto(packet, (ip, 0))
		recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
		recv_socket.settimeout(3)
		packet, _ = recv_socket.recvfrom(65565)
		flags = unpack_tcp_header(packet)
		# recv_packet, addr = server.recvfrom(65565)
		# print(recv_packet)
		# flags = unpack_tcp_header(recv_packet)
		# print(flags)
		return (check_flags(flags))


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

