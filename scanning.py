import os
from datetime import datetime
import socket
from ping3 import ping, verbose_ping
import time
import sys
from utils_parsing import *

def check_port(ip, port, server, type):
	server.settimeout(3)
	# print(port)
	if type == "udp":
		try:
			server.sendto(b"", (ip, port))
			server.recvfrom(1024)
			if socket.timeout:
				return 111
			return 0
		except socket.error as e:
			if e.errno == 111:
				return 111
			return 111
	elif type == "tcp":
		return server.connect_ex((ip, port))
	
#############################################################

def scan_all(ports, service, models, ip, type):
	closed_ports = 0
	status_array = []
	ports_array = []
	models_array = []
	service_array = []
	for port, service_name, model in zip(ports, service, models):
		server = socket_setup(type)
		server.settimeout(1)
		result = check_port(ip, port, server, type)
		if result == 111:
			closed_ports += 1
		elif result == 0:
			ports_array.append(port)
			status_array.append(result)
			models_array.append(model)
			service_array.append(service_name)
	
		server.close()
		time.sleep(0.1)
	if len(ports) == closed_ports:
		print(f"All {closed_ports} scanned ports on {ip} are closed")
	else:
		print("Not shown:", closed_ports,"closed ports")
		print("PORT", "  STATE", "SERVICE")
		for p, s, m, a in zip(ports_array, status_array, models_array, service_array):
			if s == 0:
				print(m, "open", a)
			elif s == 11:
				print(m, "filltered", a)
	

#############################################################
def scan_for_range(port, service, models, ip, type):
	closed = 0
	status_array = []
	ports_array = []
	models_array = []
	service_array = []
	if len(port) <= 25:
		print("PORT", "  STATE", "SERVICE")
		for p in port:
			server = socket_setup(type)
			server.settimeout(1)
			result = check_port(ip, p, server, type)
			server.close()
			time.sleep(0.1)
			if result == 111:
				print(models[p - 1], "closed", service[p - 1])
			if result == 0:
				print(models[p - 1], "open", service[p - 1])
	else:
		for p in port:
			server = socket_setup(type)
			server.settimeout(1)
			result = check_port(ip, p, server, type)
			server.close()
			time.sleep(0.1)
			if result == 111:
				closed += 1
			if result == 0:
				ports_array.append(port)
				status_array.append(result)
				models_array.append(models[p - 1])
				service_array.append(service[p - 1])
		if len(port) == closed:
			print(f"All {closed} scanned ports on {ip} are closed")
		else:	
			print("Not shown:", closed, "closed ports")
			print("PORT", "  STATE", "SERVICE")
			for p, s, m, a in zip(ports_array, status_array, models_array, service_array):
				if s == 0:
					print(m, "open", a)
				elif s == 11:
					print(m, "filltered", a)

#############################################################
def scan_one(port, ports, ip, service, type):
	server = socket_setup(type)
	try:
		result = check_port(ip, port[0], server, type)

	except OverflowError:
		print("Error: port must be 0-65535")
		server.close()
		exit(1)

	except ValueError:
		print("Error: invalid literal for int() with base 10")
		server.close()
		exit(1)
	print("PORT", "  STATE", "SERVICE")
	if result == 0:
		ss = find_service(port,ports, service)
		print(f"{port[0]}/{type}  open {ss}")
	elif result == 110:
		ss = find_service(port,ports, service)
		print(f"{port[0]}/{type}  filtered {ss}")
	elif result == 111:
		ss = find_service(port,ports, service)
		print(f"{port[0]}/{type}  closed {ss}")
	server.close()


#############################################################
def tcp_scan(args, type):
	try:
		ports, service, models = reading_ports("/home/adel/Desktop/cyber/project2/Nmap/importent_ports_tcp")
	except FileNotFoundError:
		print("Error: No such file or directory")
		exit(1)
	if args.port is None:
		scan_all(ports, service, models, args.host, type)
	elif len(args.port) == 1:
		scan_one(args.port, ports, args.host, service, type)
	elif len(args.port) != 1:
		scan_for_range(args.port, service, models, args.host, type)


def udp_scan(args, type):
	try:
		ports, service, models = reading_ports("/home/adel/Desktop/cyber/project2/Nmap/importent_ports_udp")
	except FileNotFoundError:
		print("Error: No such file or directory")
		exit(1)
	if args.port is None:
		scan_all(ports, service, models, args.host, type)
	elif len(args.port) == 1:
		scan_one(args.port, ports, args.host, service, type)
	elif len(args.port) != 1:
		scan_for_range(args.port, service, models, args.host, type)
	


def socket_setup(type):
	if type == "udp":
		server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	elif type == "tcp":
		server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	return server