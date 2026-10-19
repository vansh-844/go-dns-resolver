package main

import (
	"fmt"
	"net"
)

const (
	DNSPort = "8080"
)

func main() {
	fmt.Println("DNS Resolver running on port", DNSPort)
	addr, err := net.ResolveUDPAddr("udp", ":"+DNSPort)
	if err != nil {
		fmt.Println("Error resolving UDP address:", err)
		return
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Println("Error listening on UDP port:", err)
		return
	}
	defer conn.Close()
	buffer := make([]byte, 1024)

	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Printf("Error reading from UDP connection: %v\n", err)
			continue
		}
		msg := buffer[:n]
		fmt.Printf("Received message from %s of bytes %d: %s\n", remoteAddr, n, string(msg))
		returnMsg := []byte("Message received")
		_, err = conn.WriteToUDP(returnMsg, remoteAddr)
		if err != nil {
			fmt.Printf("Error writing to UDP connection: %v\n", err)
		}
	}

}
