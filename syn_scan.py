import struct
import socket

def unpack_tcp_header(packet):
	ip_header = packet[:20]
	tcp_header = packet[20:40]
	flags= tcp_header[5]
	print(f"{bin(flags)}")
	return flags


def check_flags(flags):
	if (flags & 0x12) == 0x12:
		return 0
	elif (flags & 0x04) == 0x04:
		return 111
	else:
		return 110

def debug_packet(packet):
    # Print raw packet data in hexadecimal format for better readability
    print("Raw packet:", packet.hex())

    # Unpack and print the IP and TCP headers
    ip_header = packet[:20]
    tcp_header = packet[20:40]
    
    print("IP Header:", ip_header.hex())
    print("TCP Header:", tcp_header.hex())

    # Extract TCP flags
    flags_byte = tcp_header[13]
    print(f"Flags byte: {flags_byte:#04x} (binary: {bin(flags_byte)})")
    
    return flags_byte
