"""
==============================================
  Packet Sniffer
  Author: Abdulhakeem Umar Toyin
  GitHub: github.com/feliue
  Description: A network packet analyzer that
               captures and dissects live network
               traffic to inspect protocols,
               payloads, and detect anomalies
==============================================

  ⚠️  IMPORTANT: Run as Administrator/Root
      Windows: Right-click CMD → Run as Administrator
      Linux/Mac: sudo python3 packet_sniffer.py

  ⚠️  LEGAL: Only capture traffic on networks
      you own or have permission to monitor.
"""

import socket
import struct
import time
import threading
from datetime import datetime
import sys
import os


# ── COLOUR CODES ──────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
PURPLE = "\033[95m"
WHITE  = "\033[97m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
DIM    = "\033[2m"


# ── BANNER ────────────────────────────────────────────────────────────────────
def banner():
    print(f"""
{CYAN}{BOLD}
  ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗
  ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝
  ██████╔╝███████║██║     █████╔╝ █████╗     ██║
  ██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║
  ██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║
  ╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝
{RESET}
{PURPLE}{BOLD}
  ███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗
  ██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
  ███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
  ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
  ███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
  ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
{RESET}
{WHITE}  Author : {GREEN}Abdulhakeem Umar Toyin{RESET}
{WHITE}  GitHub : {CYAN}github.com/feliue{RESET}
{WHITE}  Tool   : {YELLOW}Packet Sniffer v1.0{RESET}
  {'─'*60}
""")


# ── PROTOCOL NUMBERS ──────────────────────────────────────────────────────────
PROTOCOLS = {
    1:   "ICMP",
    6:   "TCP",
    17:  "UDP",
    47:  "GRE",
    50:  "ESP",
    51:  "AH",
    58:  "ICMPv6",
    89:  "OSPF",
    132: "SCTP",
}

# ── WELL KNOWN PORTS ──────────────────────────────────────────────────────────
PORT_SERVICES = {
    20:   "FTP-Data",   21:  "FTP",      22:   "SSH",
    23:   "Telnet",     25:  "SMTP",     53:   "DNS",
    67:   "DHCP",       80:  "HTTP",     110:  "POP3",
    143:  "IMAP",       443: "HTTPS",    445:  "SMB",
    3306: "MySQL",      3389:"RDP",      5432: "PostgreSQL",
    6379: "Redis",      8080:"HTTP-Alt", 27017:"MongoDB",
}

# ── SUSPICIOUS PORTS ─────────────────────────────────────────────────────────
SUSPICIOUS_PORTS = {4444, 1337, 31337, 8888, 9999, 6666, 1234}

# ── STATS ─────────────────────────────────────────────────────────────────────
stats = {
    "total":     0,
    "tcp":       0,
    "udp":       0,
    "icmp":      0,
    "other":     0,
    "http":      0,
    "https":     0,
    "dns":       0,
    "suspicious":0,
    "bytes":     0,
}

captured_packets = []
running          = True
lock             = threading.Lock()


# ── ETHERNET FRAME PARSER ─────────────────────────────────────────────────────
def parse_ethernet(data):
    """Parse Ethernet frame header."""
    # Ethernet header is 14 bytes
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return (
        format_mac(dest_mac),
        format_mac(src_mac),
        socket.htons(proto),
        data[14:]
    )


def format_mac(bytes_addr):
    """Format MAC address bytes to readable string."""
    return ':'.join(map('{:02x}'.format, bytes_addr))


# ── IPv4 HEADER PARSER ────────────────────────────────────────────────────────
def parse_ipv4(data):
    """Parse IPv4 packet header."""
    version_ihl = data[0]
    ihl         = (version_ihl & 0xF) * 4  # Header length in bytes
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return (
        ttl,
        proto,
        socket.inet_ntoa(src),
        socket.inet_ntoa(target),
        data[ihl:]
    )


# ── TCP HEADER PARSER ─────────────────────────────────────────────────────────
def parse_tcp(data):
    """Parse TCP segment header."""
    src_port, dest_port, sequence, ack, offset_flags = struct.unpack(
        '! H H L L H', data[:14]
    )
    offset   = (offset_flags >> 12) * 4
    # Extract TCP flags
    flag_urg = (offset_flags & 32) >> 5
    flag_ack = (offset_flags & 16) >> 4
    flag_psh = (offset_flags & 8)  >> 3
    flag_rst = (offset_flags & 4)  >> 2
    flag_syn = (offset_flags & 2)  >> 1
    flag_fin = offset_flags & 1

    flags = []
    if flag_syn: flags.append("SYN")
    if flag_ack: flags.append("ACK")
    if flag_fin: flags.append("FIN")
    if flag_rst: flags.append("RST")
    if flag_psh: flags.append("PSH")
    if flag_urg: flags.append("URG")

    return src_port, dest_port, sequence, '+'.join(flags) or "NONE", data[offset:]


# ── UDP HEADER PARSER ─────────────────────────────────────────────────────────
def parse_udp(data):
    """Parse UDP datagram header."""
    src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, length, data[8:]


# ── ICMP PARSER ───────────────────────────────────────────────────────────────
def parse_icmp(data):
    """Parse ICMP packet."""
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    icmp_types = {
        0:  "Echo Reply (Ping Response)",
        3:  "Destination Unreachable",
        5:  "Redirect",
        8:  "Echo Request (Ping)",
        11: "Time Exceeded",
        13: "Timestamp Request",
    }
    type_name = icmp_types.get(icmp_type, f"Type {icmp_type}")
    return icmp_type, code, checksum, type_name


# ── GET SERVICE NAME ──────────────────────────────────────────────────────────
def get_service(port):
    return PORT_SERVICES.get(port, "")


# ── CHECK SUSPICIOUS ─────────────────────────────────────────────────────────
def is_suspicious(src_port, dest_port):
    return src_port in SUSPICIOUS_PORTS or dest_port in SUSPICIOUS_PORTS


# ── FORMAT PAYLOAD ────────────────────────────────────────────────────────────
def format_payload(data, max_bytes=64):
    """Format payload as hex and ASCII."""
    if not data:
        return ""
    data  = data[:max_bytes]
    hex_  = ' '.join(f'{byte:02x}' for byte in data)
    ascii_= ''.join(chr(byte) if 32 <= byte < 127 else '.' for byte in data)
    return f"\n    {DIM}HEX  : {hex_[:48]}{'...' if len(data)>16 else ''}{RESET}" \
           f"\n    {DIM}ASCII: {ascii_[:48]}{RESET}"


# ── PRINT PACKET ─────────────────────────────────────────────────────────────
def print_packet(num, timestamp, src_ip, dst_ip, protocol,
                 src_port=None, dst_port=None, flags=None,
                 extra="", payload=None, suspicious=False):
    """Print a formatted packet summary."""

    time_str  = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S.%f')[:12]
    proto_col = {
        "TCP":  CYAN,
        "UDP":  GREEN,
        "ICMP": YELLOW,
    }.get(protocol, WHITE)

    service = ""
    if src_port and dst_port:
        svc = get_service(dst_port) or get_service(src_port)
        service = f" {DIM}[{svc}]{RESET}" if svc else ""

    port_str = f":{src_port} → :{dst_port}" if src_port else ""
    flag_str = f" {PURPLE}[{flags}]{RESET}" if flags else ""
    warn_str = f" {RED}{BOLD}⚠ SUSPICIOUS PORT!{RESET}" if suspicious else ""

    print(f"  {DIM}#{num:<5}{RESET} "
          f"{DIM}{time_str}{RESET}  "
          f"{proto_col}{BOLD}{protocol:<6}{RESET}  "
          f"{WHITE}{src_ip}{RESET} → "
          f"{CYAN}{dst_ip}{RESET}"
          f"{port_str}{flag_str}{service}{warn_str}")

    if extra:
        print(f"         {DIM}{extra}{RESET}")

    if payload and len(payload) > 0:
        print(format_payload(payload))


# ── LIVE STATS DISPLAY ────────────────────────────────────────────────────────
def display_stats():
    """Show live packet statistics."""
    print(f"\n  {'─'*60}")
    print(f"  {BOLD}{WHITE}LIVE CAPTURE STATISTICS{RESET}")
    print(f"  {'─'*60}")
    print(f"  {WHITE}Total Packets  :{RESET} {CYAN}{stats['total']}{RESET}")
    print(f"  {CYAN}TCP            :{RESET} {stats['tcp']}")
    print(f"  {GREEN}UDP            :{RESET} {stats['udp']}")
    print(f"  {YELLOW}ICMP           :{RESET} {stats['icmp']}")
    print(f"  {WHITE}Other          :{RESET} {stats['other']}")
    print(f"  {WHITE}HTTP           :{RESET} {stats['http']}")
    print(f"  {WHITE}HTTPS          :{RESET} {stats['https']}")
    print(f"  {WHITE}DNS            :{RESET} {stats['dns']}")
    if stats['suspicious'] > 0:
        print(f"  {RED}⚠ Suspicious   :{RESET} {RED}{stats['suspicious']}{RESET}")
    print(f"  {WHITE}Data Captured  :{RESET} {stats['bytes'] / 1024:.1f} KB")
    print(f"  {'─'*60}\n")


# ── SNIFFER CORE ──────────────────────────────────────────────────────────────
def sniff(packet_count, show_payload, filter_protocol):
    """Main packet capture loop."""
    global running

    try:
        # Create raw socket
        if sys.platform == 'win32':
            # Windows raw socket
            sniffer = socket.socket(
                socket.AF_INET,
                socket.SOCK_RAW,
                socket.IPPROTO_IP
            )
            sniffer.bind((socket.gethostbyname(socket.gethostname()), 0))
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            # Linux/Mac raw socket
            sniffer = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.ntohs(3)
            )

    except PermissionError:
        print(f"\n  {RED}{BOLD}[ERROR] Permission denied!{RESET}")
        print(f"  {YELLOW}Run as Administrator (Windows) or use sudo (Linux/Mac){RESET}")
        print(f"\n  {WHITE}Windows: Right-click CMD → Run as Administrator{RESET}")
        print(f"  {WHITE}Linux  : sudo python3 packet_sniffer.py{RESET}\n")
        return

    except Exception as e:
        print(f"\n  {RED}[ERROR] Could not create socket: {e}{RESET}\n")
        return

    print(f"\n  {GREEN}[*]{RESET} Packet capture started!")
    print(f"  {YELLOW}[!]{RESET} Press {WHITE}Ctrl+C{RESET} to stop\n")
    print(f"  {'─'*60}")
    print(f"  {DIM}{'#':<7} {'TIME':<13} {'PROTO':<7} {'SOURCE':<18} "
          f"{'DESTINATION'}{RESET}")
    print(f"  {'─'*60}\n")

    packet_num = 0

    try:
        while running:
            if packet_count and packet_num >= packet_count:
                break

            raw_data, addr = sniffer.recvfrom(65535)

            with lock:
                stats['total']  += 1
                stats['bytes']  += len(raw_data)

            # Parse based on platform
            if sys.platform == 'win32':
                # Windows gives us IP directly
                ip_data = raw_data
                try:
                    ttl, proto, src_ip, dst_ip, data = parse_ipv4(ip_data)
                except Exception:
                    continue
            else:
                # Linux gives us Ethernet frame first
                try:
                    dest_mac, src_mac, eth_proto, data = parse_ethernet(raw_data)
                    if eth_proto != 8:  # Only IPv4
                        continue
                    ttl, proto, src_ip, dst_ip, data = parse_ipv4(data)
                except Exception:
                    continue

            proto_name = PROTOCOLS.get(proto, f"PROTO-{proto}")

            # Apply protocol filter
            if filter_protocol and filter_protocol != proto_name:
                continue

            packet_num += 1

            # ── TCP ──────────────────────────────────────────────────────────
            if proto == 6:
                with lock:
                    stats['tcp'] += 1
                try:
                    src_port, dst_port, seq, flags, payload = parse_tcp(data)

                    # Update service stats
                    if dst_port == 80 or src_port == 80:
                        stats['http'] += 1
                    elif dst_port == 443 or src_port == 443:
                        stats['https'] += 1

                    susp = is_suspicious(src_port, dst_port)
                    if susp:
                        stats['suspicious'] += 1

                    print_packet(
                        packet_num, time.time(),
                        src_ip, dst_ip, "TCP",
                        src_port, dst_port, flags,
                        f"SEQ:{seq}  TTL:{ttl}",
                        payload if show_payload else None,
                        susp
                    )
                except Exception:
                    pass

            # ── UDP ──────────────────────────────────────────────────────────
            elif proto == 17:
                with lock:
                    stats['udp'] += 1
                try:
                    src_port, dst_port, length, payload = parse_udp(data)

                    if dst_port == 53 or src_port == 53:
                        stats['dns'] += 1

                    susp = is_suspicious(src_port, dst_port)
                    if susp:
                        stats['suspicious'] += 1

                    print_packet(
                        packet_num, time.time(),
                        src_ip, dst_ip, "UDP",
                        src_port, dst_port, None,
                        f"Length:{length}  TTL:{ttl}",
                        payload if show_payload else None,
                        susp
                    )
                except Exception:
                    pass

            # ── ICMP ─────────────────────────────────────────────────────────
            elif proto == 1:
                with lock:
                    stats['icmp'] += 1
                try:
                    icmp_type, code, checksum, type_name = parse_icmp(data)
                    print_packet(
                        packet_num, time.time(),
                        src_ip, dst_ip, "ICMP",
                        extra=f"{type_name}  Code:{code}  TTL:{ttl}"
                    )
                except Exception:
                    pass

            # ── OTHER ─────────────────────────────────────────────────────────
            else:
                with lock:
                    stats['other'] += 1
                print_packet(
                    packet_num, time.time(),
                    src_ip, dst_ip, proto_name,
                    extra=f"TTL:{ttl}"
                )

    except KeyboardInterrupt:
        print(f"\n\n  {YELLOW}[!]{RESET} Capture stopped by user.")

    finally:
        # Cleanup Windows socket
        if sys.platform == 'win32':
            try:
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
        sniffer.close()
        display_stats()


# ── EDUCATION MODE ────────────────────────────────────────────────────────────
def education_mode():
    print(f"""
  {YELLOW}{BOLD}📚 HOW PACKET SNIFFING WORKS{RESET}

  {WHITE}Every time you use the internet, your computer sends
  and receives small chunks of data called {CYAN}packets{WHITE}.
  A packet sniffer {GREEN}captures these packets{WHITE} and lets
  you inspect what's inside them.{RESET}

  {YELLOW}{BOLD}Packet Structure:{RESET}
  {WHITE}┌─────────────────────────────────────────┐
  │  ETHERNET HEADER  (14 bytes)            │  ← MAC addresses
  │  IP HEADER        (20 bytes)            │  ← IP addresses
  │  TCP/UDP HEADER   (20/8 bytes)          │  ← Ports & flags
  │  PAYLOAD          (variable)            │  ← Actual data
  └─────────────────────────────────────────┘{RESET}

  {YELLOW}{BOLD}TCP Flags explained:{RESET}
  {CYAN}SYN{WHITE} → Start a connection (synchronize)
  {CYAN}ACK{WHITE} → Acknowledge received data
  {CYAN}FIN{WHITE} → End a connection (finish)
  {CYAN}RST{WHITE} → Reset/abort connection
  {CYAN}PSH{WHITE} → Push data immediately
  {CYAN}URG{WHITE} → Urgent data{RESET}

  {YELLOW}{BOLD}TCP 3-Way Handshake:{RESET}
  {WHITE}Client  ──SYN──►  Server   (Hello!)
  Client  ◄─SYN+ACK─  Server   (Hello back!)
  Client  ──ACK──►  Server   (Got it!){RESET}

  {YELLOW}{BOLD}Legal uses of packet sniffing:{RESET}
  {GREEN}✓{WHITE} Network troubleshooting
  {GREEN}✓{WHITE} Security monitoring
  {GREEN}✓{WHITE} Penetration testing (with permission)
  {GREEN}✓{WHITE} Learning how protocols work{RESET}

  {RED}{BOLD}Illegal uses:{RESET}
  {RED}✗{WHITE} Intercepting others' traffic without permission
  {RED}✗{WHITE} Stealing passwords or credentials
  {RED}✗{WHITE} Corporate espionage{RESET}
""")


# ── MAIN MENU ─────────────────────────────────────────────────────────────────
def main():
    banner()

    # Warn about permissions
    print(f"  {YELLOW}⚠ This tool requires Administrator/Root privileges{RESET}")
    print(f"  {YELLOW}⚠ Only use on networks you own or have permission to monitor{RESET}\n")

    while True:
        print(f"  {BOLD}{WHITE}MAIN MENU{RESET}")
        print(f"  {'─'*40}")
        print(f"  {WHITE}[1]{RESET} 📡 Start packet capture")
        print(f"  {WHITE}[2]{RESET} 📚 How packet sniffing works")
        print(f"  {WHITE}[3]{RESET} ❌ Exit")
        print(f"  {'─'*40}")

        choice = input(f"\n  {CYAN}Choose option (1-3):{RESET} ").strip()

        if choice == '1':
            print(f"\n  {YELLOW}Configure capture settings:{RESET}\n")

            # Packet count
            try:
                count_input = input(
                    f"  {CYAN}How many packets to capture? "
                    f"(0 = unlimited, default 50):{RESET} "
                ).strip()
                packet_count = int(count_input) if count_input else 50
            except ValueError:
                packet_count = 50

            # Show payload
            payload_input = input(
                f"  {CYAN}Show packet payload? (y/n, default n):{RESET} "
            ).strip().lower()
            show_payload = payload_input == 'y'

            # Protocol filter
            print(f"\n  {CYAN}Filter by protocol?{RESET}")
            print(f"  {WHITE}[1]{RESET} All protocols")
            print(f"  {WHITE}[2]{RESET} TCP only")
            print(f"  {WHITE}[3]{RESET} UDP only")
            print(f"  {WHITE}[4]{RESET} ICMP only")
            filter_choice = input(
                f"\n  {CYAN}Choose filter (1-4, default 1):{RESET} "
            ).strip()

            filter_map = {"2": "TCP", "3": "UDP", "4": "ICMP"}
            filter_protocol = filter_map.get(filter_choice, None)

            sniff(packet_count, show_payload, filter_protocol)

        elif choice == '2':
            education_mode()

        elif choice == '3':
            print(f"\n  {GREEN}Stay curious and ethical! 🛡{RESET}\n")
            break

        else:
            print(f"\n  {RED}Invalid option. Choose 1-3.{RESET}\n")


if __name__ == "__main__":
    main()
