import os
from datetime import datetime
import socket
from ping3 import ping, verbose_ping
import time
import sys
from utils_parsing import *

#############################################################
def scan_for_range(port, service, models, ip):
	print("PORT", "  STATE", "SERVICE")
	for p in port:
		server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server.settimeout(1)
		result = server.connect_ex((ip, p))
		server.close()
		time.sleep(0.1)
		if result == 111:
			print(models[p - 2], "closed", service[p - 2])
		if result == 0:
			print(models[p - 2], "open", service[p - 2])

#############################################################
def scan_all(ports, service, models, ip):
	closed_ports = 0
	status_array = []
	ports_array = []
	models_array = []
	service_array = []
	if flag_for_range == True:
		scan_for_range(port, service, models, ip)
	else:
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

#############################################################
def scan_one(port, ports, ip, service):
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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

#############################################################
def socket_setup(ip, port):
	try:
		ports, service, models = reading_ports("/home/adel/Desktop/cyber/project2/Nmap/importent_ports_tcp")
	except FileNotFoundError:
		print("Error: No such file or directory")
		exit(1)

	if len(sys.argv) == 4:
		scan_one(port, ports, ip, service)
	else:
		scan_all(ports, service, models, ip)




