#!/usr/bin/python2
# -*- coding: utf-8 -*-

# python 2.7 + yerel ağa bağlı bilgisayarların mac ve ıp adreslerini buluyor.
# by Süleyman Onur Mirioglu
# only for legal purpose

import sys
from scapy.all import *
from datetime import datetime
from sys import argv, exit
dosya =open('Veriler.dat','w+')
a=dosya.readlines()
print a;
try:
	interface = raw_input("[*] Enter Desired Interface:")
	ips = raw_input("[*] Enter Range of IPs to scan for: ")
except KeyboardInterrupt:
	print "\n[*] User Requested Shutdown"
	print "[*] Quitting"
	sys.exit(1)
print "\n[*] Scanning...."
start_time = datetime.now()


conf.verb = 0
ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = ips),timeout = 2,iface=interface,inter=0.1)


print "Mac -IP\n"
for snd,rcv in ans:
	print rcv.sprintf(r"%Ether.src% - %ARP.psrc%")
	dosya.write(rcv.sprintf(r"%Ether.src% - %ARP.psrc%"))
dosya.close()
stop_time =datetime.now()
total_time =stop_time - start_time
print "\n[*] Scan Complete!"
print "[*] Scan Duration :%s"%(total_time)


