import os
from datetime import datetime
import socket
from ping3 import ping, verbose_ping
import time
import sys
from utils_parsing import *
from nmap import scan_all


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
			print(models[p - 1], "closed", service[p - 1])
		if result == 0:
			print(models[p - 1], "open", service[p - 1])

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
def socket_setup(args):
	try:
		ports, service, models = reading_ports("/home/adel/Desktop/cyber/project2/Nmap/importent_ports_tcp")
	except FileNotFoundError:
		print("Error: No such file or directory")
		exit(1)
	if len(sys.argv) == 4 and len(args.port) == 1:
		scan_one(args.port, ports, args.host, service)
	elif len(sys.argv) == 4 and len(args.port) != 1:
		scan_for_range(args.port, service, models, args.host)
	elif args.port is None:
		scan_all(ports, service, models, args.host)



