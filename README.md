# Python Network Packet Sniffer

## Description
This Python program captures and analyzes network packets using the **Scapy** library. It displays useful information such as IP addresses, protocols, ports, DNS queries, and packet payloads.

## Features
- Captures network packets continuously.
- Supports IPv4 and IPv6 packets.
- Detects TCP, UDP, and ICMP protocols.
- Displays source and destination IP addresses.
- Shows source and destination ports for TCP/UDP.
- Displays DNS queries when available.
- Shows a small payload preview in hexadecimal and text format.

## Requirements
- Python 3
- Scapy
- Npcap on Windows

Install Scapy using:
```bash
pip install scapy
```

## How to Run
Run the program from a terminal:

```bash
python Task1.py
```

On Linux/macOS, administrator privileges may be required:

```bash
sudo python Task1.py
```

On Windows, make sure **Npcap** is installed.

## Stop the Program
Press:

```text
Ctrl + C
```

The program will stop packet capturing and display a confirmation message.
