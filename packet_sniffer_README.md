# 📡 Packet Sniffer

A Python network packet analyzer that captures and dissects live network traffic — inspecting protocols, payloads, TCP flags, and detecting suspicious activity on your network.

---

## 📌 Features

- ✅ **Captures live network traffic** in real time
- ✅ **Parses TCP, UDP, ICMP** packets fully
- ✅ **TCP flag detection** — SYN, ACK, FIN, RST, PSH, URG
- ✅ **Service identification** — HTTP, HTTPS, DNS, SSH, FTP etc.
- ✅ **Suspicious port detection** — flags dangerous ports
- ✅ **Payload inspection** — hex and ASCII display
- ✅ **Protocol filter** — capture only TCP, UDP, or ICMP
- ✅ **Live statistics** — packets, bytes, protocol breakdown
- ✅ **Cross-platform** — works on Windows and Linux/Mac
- ✅ **Education mode** — learn how packets work

---

## ⚠️ Requirements

```bash
# Windows — Run CMD as Administrator
# Linux/Mac — Use sudo

sudo python3 packet_sniffer.py   # Linux/Mac
# Right-click CMD → Run as Administrator → python packet_sniffer.py
```

---

## 🖥️ Demo

```
#       TIME          PROTO   SOURCE             DESTINATION
────────────────────────────────────────────────────────────

#1      14:23:05.123  TCP     192.168.1.5 → 142.250.185.78:443 [SYN] [HTTPS]
#2      14:23:05.124  TCP     142.250.185.78 → 192.168.1.5:443 [SYN+ACK]
#3      14:23:05.125  UDP     192.168.1.5 → 8.8.8.8:53 [DNS]
#4      14:23:05.200  ICMP    192.168.1.5 → 192.168.1.1 Echo Request (Ping)

LIVE CAPTURE STATISTICS
────────────────────────────────────────────────────────────
Total Packets  : 150
TCP            : 98
UDP            : 35
ICMP           : 12
HTTP           : 23
HTTPS          : 45
DNS            : 18
Data Captured  : 48.3 KB
```

---

## 🔬 What Gets Parsed

### Ethernet Frame
- Source & Destination MAC addresses
- Protocol type

### IPv4 Header
- Source & Destination IP addresses
- TTL (Time to Live)
- Protocol number

### TCP Segment
- Source & Destination ports
- Sequence number
- Flags: SYN, ACK, FIN, RST, PSH, URG
- Payload data

### UDP Datagram
- Source & Destination ports
- Length
- Payload data

### ICMP Packet
- Type & Code
- Checksum
- Message type (Ping, Unreachable etc.)

---

## 🚀 Getting Started

```bash
git clone https://github.com/feliue/packet-sniffer.git
cd packet-sniffer

# Linux/Mac
sudo python3 packet_sniffer.py

# Windows (as Administrator)
python packet_sniffer.py
```

---

## 📁 Project Structure

```
packet-sniffer/
│
├── packet_sniffer.py    # Main sniffer
└── README.md            # Documentation
```

---

## 📚 What I Learned

- Raw socket programming in Python
- Network packet structure (Ethernet, IP, TCP, UDP)
- Binary data parsing with `struct.unpack`
- TCP flags and the 3-way handshake
- Protocol numbers and port services
- Real-time data capture and display
- Cross-platform network programming

---

## ⚠️ Legal Disclaimer

> **Only capture traffic on networks you own or have explicit permission to monitor.**
> Unauthorized packet sniffing is illegal in most countries.
> This tool is for **educational and ethical security purposes only**.

---

## 📜 License

MIT License — free to use and modify.

---

## 👤 Author

**Abdulhakeem Umar Toyin**
Cybersecurity Student
GitHub: [@feliue](https://github.com/feliue)
Email: abdulhakeemumar616@gmail.com
