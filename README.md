# ARP Spoofing Tool 
A simple ARP spoofing tool developed for **ethical hacking practice** and **self-learning** in network security.

---

## What It Does

This script performs **ARP spoofing** by sending malicious ARP packets to mislead both a target device and the router. It tricks them into sending their network traffic through your machine — enabling packet interception.

---

## How to Use

1. **Start the script**.
2. Follow the prompts:
   - Enter the **default gateway IP address** (router).
   - Enter the **subnet mask** (in CIDR notation or dotted decimal format).
   - Enter the **target IP address** (device you want to spoof).
3. Press `Ctrl + C` (KeyboardInterrupt) to **stop spoofing and restore the connection**.

---

## Libraries Used

- `scapy` – for crafting and sending ARP packets.
- `getmac` – for retrieving MAC addresses using IP.
- `time` – for handling time-related operations.
- `multiprocessing` – for running background processes.

---

## Dependencies

Make sure to install the required libraries using pip:

```
pip install scapy
pip install getmac
```
