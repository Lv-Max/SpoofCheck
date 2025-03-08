package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"syscall"
)

func checksum(data []byte) uint16 {
	var sum uint32
	length := len(data)
	for i := 0; i < length-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if length%2 == 1 {
		sum += uint32(data[length-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// Get local IP address
func getRealIP() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.To4(), nil
}

func main() {
	// Define command line arguments
	targetIPFlag := flag.String("t", "", "Target server IP address")
	sourceIPFlag := flag.String("s", "69.69.69.69", "Source IP address to use")
	flag.Parse()

	// Get target IP
	reader := bufio.NewReader(os.Stdin)
	var targetIPStr string

	if *targetIPFlag == "" {
		fmt.Print("Enter server IP address: ")
		input, _ := reader.ReadString('\n')
		targetIPStr = strings.TrimSpace(input)
	} else {
		targetIPStr = *targetIPFlag
	}

	// Display parameters
	fmt.Printf("Target IP: %s\n", targetIPStr)
	fmt.Printf("Source IP: %s\n", *sourceIPFlag)

	// Get real IP to embed in the packet
	realIP, err := getRealIP()
	if err != nil {
		log.Fatalf("Failed to get real IP: %v", err)
	}
	fmt.Printf("Real IP (embedded in packet): %s\n", realIP.String())

	// Set source IP from command line
	sourceIP := net.ParseIP(*sourceIPFlag).To4()
	if sourceIP == nil {
		log.Fatal("Invalid source IP address")
	}

	// Parse target IP address
	targetIP := net.ParseIP(targetIPStr).To4()
	if targetIP == nil {
		log.Fatal("Invalid target IP address")
	}

	// Create raw socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Fatalf("Failed to create raw socket: %v", err)
	}
	defer syscall.Close(fd)

	// Set IP_HDRINCL to indicate that the IP header is included
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		log.Fatalf("Failed to set IP_HDRINCL: %v", err)
	}

	// Prepare custom data payload containing real IP
	payload := make([]byte, 16)
	copy(payload[0:4], realIP)
	copy(payload[4:], []byte("RealIP"))

	// Construct IP header (20 bytes)
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45                   // Version 4, IHL=5
	ipHeader[1] = 0                      // TOS
	totalLength := 20 + 8 + len(payload) // IP header + ICMP header + payload
	binary.BigEndian.PutUint16(ipHeader[2:], uint16(totalLength))
	binary.BigEndian.PutUint16(ipHeader[4:], uint16(rand.Intn(0xffff))) // ID
	binary.BigEndian.PutUint16(ipHeader[6:], 0)                         // Flags and fragment offset
	ipHeader[8] = 64                                                    // TTL
	ipHeader[9] = 1                                                     // Protocol = ICMP
	// Source IP from command line
	copy(ipHeader[12:16], sourceIP)
	// Destination IP
	copy(ipHeader[16:20], targetIP)
	// Calculate IP header checksum
	cs := checksum(ipHeader)
	binary.BigEndian.PutUint16(ipHeader[10:], cs)

	// Construct ICMP Echo Request with payload
	icmpHeader := make([]byte, 8+len(payload))
	icmpHeader[0] = 8 // Type = Echo Request
	icmpHeader[1] = 0 // Code
	// Identifier and Sequence Number
	binary.BigEndian.PutUint16(icmpHeader[4:], uint16(rand.Intn(0xffff)))
	binary.BigEndian.PutUint16(icmpHeader[6:], 1)
	// Add payload with real IP
	copy(icmpHeader[8:], payload)

	// Calculate ICMP checksum
	csICMP := checksum(icmpHeader)
	binary.BigEndian.PutUint16(icmpHeader[2:], csICMP)

	// Assemble complete packet
	packet := append(ipHeader, icmpHeader...)

	// Construct target address structure
	var addr syscall.SockaddrInet4
	copy(addr.Addr[:], targetIP)

	// Send packet
	err = syscall.Sendto(fd, packet, 0, &addr)
	if err != nil {
		log.Fatalf("Failed to send packet: %v", err)
	}
	fmt.Println("ICMP packet sent. Check if the server received it.")
}
