package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func main() {
	filterIP := flag.String("s", "69.69.69.69", "Monitor for ICMP packets from this IP address")
	flag.Parse()

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatalf("ListenPacket error: %v", err)
	}
	defer conn.Close()

	fmt.Printf("Capturing ICMP packets, waiting for packets from %s ...\n", *filterIP)

	buffer := make([]byte, 1500)
	for {
		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			log.Printf("Error reading packet: %v", err)
			continue
		}

		if addr.String() == *filterIP {
			msg, err := icmp.ParseMessage(ipv4.ICMPType(buffer[0]).Protocol(), buffer[:n])
			if err != nil {
				log.Printf("Error parsing ICMP message: %v", err)
				continue
			}

			fmt.Printf("Received ICMP packet from %s, type: %v\n", addr.String(), msg.Type)

			if msg.Type == ipv4.ICMPTypeEcho {
				echo := msg.Body.(*icmp.Echo)
				if len(echo.Data) >= 16 {
					realIP := net.IP(echo.Data[0:4])
					marker := string(echo.Data[4:10])
					if marker == "RealIP" {
						fmt.Printf(" -> Spoofed packet from %s, real IP: %s\n", addr.String(), realIP)
					}
				}
			}
		}
	}
}
