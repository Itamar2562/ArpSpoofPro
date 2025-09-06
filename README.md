# ARP Spoofing Tool

A simple ARP spoofing tool developed for **ethical hacking practice** and **self-learning** in network security.

---

## What It Does

This script performs **ARP spoofing** by sending malicious ARP packets to mislead both a target device and the router. It tricks them into sending their network traffic through your machine — enabling packet interception.
It also includes a **sniffer** to capture and display packets.

---

## How to Use

1. **Start the script**.
2. Follow the prompts:

   * Enter the **default gateway IP address** (router).
   * Enter the **subnet mask** (in CIDR notation or dotted decimal format).
   * Choose a target:

     * Enter the **target IP address** (device you want to spoof), **or**
     * Press **A** to spoof all available targets, **or**
     * Press **S** to rescan the network.
3. Press `Ctrl + C` (KeyboardInterrupt) to **stop spoofing, restore the connection, and stop the sniffer**.

---

## Libraries Used

* `scapy` – for crafting/sending ARP packets and sniffing.
* `getmac` – for retrieving MAC addresses using IP.
* `time` – for handling time-related operations.
* `threading` – for running spoofing and sniffing in parallel.
* `sys` – to exit the script gracefully when no live devices are found.
* `ipaddress` – to validate subnet masks and obtain them in CIDR format.

---

## Dependencies

Make sure to install the required libraries using pip:

```terminal
pip install scapy
pip install getmac
```
