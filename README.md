# SpoofCheck

A lightweight tool for testing IPHM(IP Spoofing) without using tools from Caida.

## Features

- Send ICMP Echo Request packets with any spoofed source IP address
- Embed your real IP address in the data payload for server-side identification

## Quick Start

### Client Setup

```bash
wget https://github.com/Lv-Max/SpoofCheck/releases/latest/download/client -O icmp_client && chmod +x icmp_client
```

### Server Setup

```bash
wget https://github.com/Lv-Max/SpoofCheck/releases/latest/download/server -O icmp_server && chmod +x icmp_server
```

## Usage

### Client

```bash
sudo ./icmp_client -t [target_ip] -s [source_ip]
```

Parameters:

- `-t` Target IP address (required)
- `-s` Source IP address to spoof (default: 69.69.69.69)

Example:

```bash
# Using default spoofed IP (69.69.69.69)
sudo ./icmp_client -t 192.168.1.100

# Using custom spoofed IP
sudo ./icmp_client -t 192.168.1.100 -s 8.8.8.8
```

### Server

```bash
sudo ./icmp_server -s [filter_ip]
```

Parameters:

- `-s` Filter for packets from this IP address (default: 69.69.69.69)

## How It Works

1. The client creates raw IP packets with customized source IP
2. The real source IP is embedded within the ICMP payload
3. The server captures ICMP packets from the specified source IP
4. When packets are received, the server extracts and displays both the spoofed IP and the real IP

## Legal Disclaimer

This tool is provided for educational and testing purposes only. Using this tool to send packets with spoofed IP addresses may be illegal in some jurisdictions or violate terms of service of your network provider. Always obtain proper authorization before using on networks you don't own.

## License

MIT License
