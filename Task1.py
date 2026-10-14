from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, Raw
from datetime import datetime
import string

PRINTABLE = set(string.printable) - set("\r\n\t\x0b\x0c")


def printable_preview(data: bytes) -> str:
    """Return payload text with non-printable bytes replaced by dots."""
    return "".join(chr(b) if chr(b) in PRINTABLE else "." for b in data)


def analyze_packet(packet):
    print("\n" + "=" * 60)

    # Use the actual capture time instead of the processing time
    ts = datetime.fromtimestamp(float(packet.time)).strftime("%H:%M:%S.%f")[:-3]
    print("Time           :", ts)
    print("Packet Length  :", len(packet))

    # IPv4 or IPv6
    if IP in packet:
        ip_layer = packet[IP]
    elif IPv6 in packet:
        ip_layer = packet[IPv6]
    else:
        print("Non-IP packet captured (e.g., ARP)")
        print("Summary        :", packet.summary())
        print("=" * 60)
        return

    print("IP Version     :", ip_layer.version)
    print("Source IP      :", ip_layer.src)
    print("Destination IP :", ip_layer.dst)

    # Transport protocol
    if TCP in packet:
        print("Protocol       : TCP")
        print("Source Port    :", packet[TCP].sport)
        print("Dest Port      :", packet[TCP].dport)
        print("TCP Flags      :", packet[TCP].flags)
    elif UDP in packet:
        print("Protocol       : UDP")
        print("Source Port    :", packet[UDP].sport)
        print("Dest Port      :", packet[UDP].dport)
    elif ICMP in packet:
        print("Protocol       : ICMP")
        print("ICMP Type      :", packet[ICMP].type)
    else:
        print("Protocol       : Other IP protocol")

    # DNS details
    if DNS in packet and packet.haslayer(DNSQR):
        qname = packet[DNSQR].qname.decode(errors="replace")
        print("DNS Query      :", qname)

    # Payload preview
    if Raw in packet:
        payload = bytes(packet[Raw].load)[:80]
        print("Payload (hex)  :", payload.hex())
        print("Payload (text) :", printable_preview(payload))

    print("=" * 60)


def start_sniffer():
    print("Python Network Packet Sniffer")
    print("Press Ctrl+C to stop capturing.")
    print("Capturing packets...\n")

    try:
        sniff(prn=analyze_packet, store=False)
    except PermissionError:
        print("Permission denied. Run as root/Administrator "
              "(sudo python sniffer.py).")
    except OSError as error:
        print("Capture error (on Windows, make sure Npcap is installed):", error)
    except Exception as error:
        print("Error:", error)
    finally:
        # Runs on Ctrl+C too, since sniff() swallows the interrupt
        print("\nPacket capturing stopped.")


if __name__ == "__main__":
    start_sniffer()