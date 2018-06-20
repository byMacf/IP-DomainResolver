#Created by DM
#Resolve domain -> IP 
#Resolve IP -> hostname
#List resolutions

import socket 

usr_selection = 0
run_times = 0
resolved_ips = []
resolved_domains = []

def resolve_domain(domain):
	resolved_domain = socket.gethostbyname(domain)
	resolved_domains.append(tuple([domain, resolved_domain]))
	print("Resolved '{}' to {}\n".format(domain, resolved_domain))
	
def resolve_ip(ip):
	resolved_ip = socket.gethostbyaddr(ip)
	resolved_ips.append(tuple([ip, resolved_ip]))
	print("Resolved '{}' to {}\n".format(ip, resolved_ip))

while usr_selection != '5':
	run_times += 1
	print("1. Domain to IP\n2. IP to hostname\n3. List resolved domains\n4. List resolved IPs\n5. Quit\n\nTimes program has run: {}".format(run_times))
	usr_selection = input("Select an option: ")
	
	if usr_selection == '1':
		domain = input("\nPlease enter domain to resolve: ")
		if len(domain) > 0:
			try:
				resolve_domain(domain)
			except (socket.herror, socket.gaierror):
				print("Could not resolve '{}'\n".format(domain))
		else:
			print("Domain not valid")
			
	elif usr_selection == '2':
		ip = input("\nPlease enter IP to resolve: ")
		if len(ip) > 0:
			try:
				resolve_ip(ip)
			except (socket.herror, socket.gaierror):
				print("Could not resolve '{}'\n".format(ip))
		else:
			print("IP not valid")
			
	elif usr_selection == '3':
		print("\nResolved domains: ")
		if len(resolved_domains) > 0:
			for domain in resolved_domains:
				print("{} --> {}".format(domain[0], domain[1]))
			print("\n")
		else:
			print("No entries\n")
		
	elif usr_selection == '4':
		print("\nResolved IPs: ")
		if len(resolved_ips) > 0:
			for ip in resolved_ips:
				print("{} --> {}".format(ip[0], ip[1][0]))
			print("\n") 
		else:
			print("No entries\n")
