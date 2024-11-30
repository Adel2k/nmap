import socket
import sys
from checking import starting, socket_setup

def main():
	if len(sys.argv) > 1:
		ip = starting()
		socket_setup(ip)

	else: #if no args
		print("nmap -v -A scanme.nmap.org")
		print("nmap -v -sn 192.168.0.0/16 10.0.0.0/8")
		print("nmap -v -iR 10000 -Pn -p 80")


if __name__ == "__main__":
	main()
