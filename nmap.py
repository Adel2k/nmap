from scanning import *

#############################################################
def parse_ports(arg):
	if '-' in arg:
		start, end = arg.split('-')
		try:
			start = int(start)
			end = int(end)
			if start >= end:
				raise argparse.ArgumentTypeError("Start port must be less than or equal to end port.")
			return list(range(start, end + 1))
		except ValueError:
			raise argparse.ArgumentTypeError("Ports must be integers.")
	else:
		try:
			return [int(arg)]
		except ValueError:
			raise argparse.ArgumentTypeError("Port must be an integer.")

#############################################################
def starting():
	parser = argparse.ArgumentParser(description="Can pass hostnames, IP addresses, networks, etc.")
	parser.add_argument("host", help="Hostname or IP address to nmap.")
	parser.add_argument("-p", "--port", type=parse_ports, help="Specify a port (optional).")
	parser.add_argument("-sU", action="store_true", help="Specify a scan (optional).")
	parser.add_argument("-sT", action="store_true", help="Specify a scan (optional).")
	parser.add_argument("-sS", action="store_true", help="Specify a scan (optional).")
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
		start_time = time.time()
		args = starting()
		if args.sT:
			tcp_scan(args, "tcp")
		if args.sU:
			udp_scan(args, "udp")
		if args.sS:
			syn_scan(args, "syn")
		else:
			tcp_scan(args, "tcp")
		end_time = time.time()
		duration = end_time - start_time
		print(f"Nmap done: 1 IP addres scanned in {duration:.2f} seconds")
	else: #if no args
		print("nmap -v -A scanme.nmap.org")
		print("nmap -v -sn 192.168.0.0/16 10.0.0.0/8")
		print("nmap -v -iR 10000 -Pn -p 80")


if __name__ == "__main__":
	main()

