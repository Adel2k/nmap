import socket
import struct

def checksum(data):
	s = 0
	for i in range(0, len(data), 2):
		w = (data[i] << 8) + (data[i+1] if i+1 < len(data) else 0)
		s = (s + w) & 0xffff
	s = (s >> 16) + (s & 0xffff)
	s = s + (s >> 16)
	return ~s & 0xffff

def create_ip_header(source_ip, dest_ip):
	ip_ver = 4
	ihl = 5
	version_ihl = (ip_ver << 4) + ihl
	tos = 0
	total_length = 40
	packet_id = 54321
	fragment_offset = 0
	ttl = 64
	protocol = socket.IPPROTO_TCP
	checksum_placeholder = 0
	source_ip = socket.inet_aton(source_ip)
	dest_ip = socket.inet_aton(dest_ip)

	ip_header = struct.pack('!BBHHHBBH4s4s',
							version_ihl,
							tos,
							total_length,
							packet_id,
							fragment_offset,
							ttl,
							protocol,
							checksum_placeholder,
							source_ip,
							dest_ip)
	ip_checksum = checksum(ip_header)
	ip_header = struct.pack('!BBHHHBBH4s4s',
							version_ihl,
							tos,
							total_length,
							packet_id,
							fragment_offset,
							ttl,
							protocol,
							ip_checksum,
							source_ip,
							dest_ip)
	return ip_header

def create_tcp_header(source_ip, dest_ip, source_port, dest_port):
	seq = 0
	ack_seq = 0
	data_offset = (5 << 4)
	flags = 0x02  # SYN flag
	window = socket.htons(5840)
	checksum_placeholder = 0
	urgent_pointer = 0

	tcp_header = struct.pack('!HHLLBBHHH',
								source_port,
								dest_port,
								seq,
								ack_seq,
								data_offset | flags,
								0,
								window,
								checksum_placeholder,
								urgent_pointer)

	pseudo_header = struct.pack('!4s4sBBH',
								socket.inet_aton(source_ip),
								socket.inet_aton(dest_ip),
								0,
								socket.IPPROTO_TCP,
								len(tcp_header))

	pseudo_packet = pseudo_header + tcp_header
	tcp_checksum = checksum(pseudo_packet)

	tcp_header = struct.pack('!HHLLBBHHH',
								source_port,
								dest_port,
								seq,
								ack_seq,
								data_offset | flags,
								0,
								window,
								tcp_checksum,
								urgent_pointer)
	return tcp_header
