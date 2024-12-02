from scanning import *


#############################################################
def starting():
	parser = argparse.ArgumentParser(description="Can pass hostnames, IP addresses, networks, etc.")
	parser.add_argument("host", help="Hostname or IP address to nmap.")
	parser.add_argument("-p", "--port", type=parse_ports, help="Specify a port (optional).")
	parser.add_argument("-sU", action="store_true", help="Specify a scan (optional).")
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
	return args

#############################################################

def scan_all(ports, service, models, ip):
	closed_ports = 0
	status_array = []
	ports_array = []
	models_array = []
	service_array = []
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
def main():
	if len(sys.argv) > 1:
		args = starting()
		socket_setup(args)

	else: #if no args
		print("nmap -v -A scanme.nmap.org")
		print("nmap -v -sn 192.168.0.0/16 10.0.0.0/8")
		print("nmap -v -iR 10000 -Pn -p 80")


if __name__ == "__main__":
	main()

