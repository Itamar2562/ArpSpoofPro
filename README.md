arp spoofing tool that sends arp to the router and target in order to make them send massages to you.

How to use:
    start the program and follow the instructions.
    1.enter default gatway (router's IP).
    2.enter subnet mask (in CIDR Notation or dotted decimal Format).
    3.enter the ip of whoever you would like to spoof.
    4.KeyboardInterrupt (usually ctnl C) to finish spoofing and restore connection.

libraries:
    -scapy used to craft and send the arp packets.
    -getmac used to get the mac adress using IP.
    -time. 
    -multiprocessing.

Dependencies:
    you will need to install scapy and getmac using pip:
    pip install scapy
    pip install getmac
