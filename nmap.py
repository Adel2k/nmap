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

def main():
	if len(sys.argv) > 1:
		args = starting()
		if args.sU:
			udp_scan(args, "udp")
			exit(0)
		tcp_scan(args, "tcp")

	else: #if no args
		print("nmap -v -A scanme.nmap.org")
		print("nmap -v -sn 192.168.0.0/16 10.0.0.0/8")
		print("nmap -v -iR 10000 -Pn -p 80")


if __name__ == "__main__":
	main()

