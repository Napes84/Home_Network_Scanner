#!/usr/bin/env python3

import nmap
import socket

hostname = socket.gethostname()
IPAddr = socket.gethostbyname(hostname)
print("Computername = " + hostname)
print("Client IP = " + IPAddr + "\n")

# make network ip with cidr
ip_strip = '.'.join(IPAddr.split('.')[:-1]+["0"])
ip_cidr = ip_strip + "/24"
print("\t---------------------------------------------------------------------\n\tFound Network IP addresses to be scanned: " + ip_cidr + "\n")

# scanning network for ip-addresses
def ip_scanner(hosts_list):
    scanner = nmap.PortScanner()
    scanner.scan(hosts=ip_cidr, arguments="-n -sP")
    hosts_list = [(x, scanner[x]['status']['state']) for x in scanner.all_hosts()]
    for host, status in hosts_list:
        print('\t{0}:{1}'.format(host, status))
    print('\n\t---------------------------------------------------------------------')
    return hosts_list

#ip_scanner()
ip_list = ip_scanner(hosts_list=[])
ips = [x[0] for x in ip_list]

# scan ports on found ip-addresses
def port_scanner(ips):
    for ip in ips:
        scanner = nmap.PortScanner()
        scanner.scan(ip, '1-1024')
        for host in scanner.all_hosts():
            print('\t----------------------------------------')
            print('\n\tHost : %s (%s)' % (host, scanner[host].hostname()))
            print('\tState : %s' % scanner[host].state())
            for proto in scanner[host].all_protocols():
                print('\tProtocol : %s' % proto)
 
                lport = sorted(scanner[host][proto].keys())
                for port in lport:
                    print ('\tport : %s\tstate : %s' % (port, scanner[host][proto][port]['state']))
                print(" ")

port_scanner(ips)
