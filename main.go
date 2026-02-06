package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync/atomic"
)

func main() {
	fmt.Println("Starting server on 127.0.0.1:8080")

	// listen for incoming traffic on port 8080
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Println("Error listening on port 8080")
		os.Exit(1)
	}
	defer ln.Close()

	log.Println("Listening on port 8080")
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("Error accepting client connection")
			continue
		}
		go handleConnection(conn)
	}
}

// Global counter to track active agents
var activeAgents int32

func handleConnection(conn net.Conn) {
	defer func() {
		conn.Close()
		atomic.AddInt32(&activeAgents, -1)
		log.Printf("Agent disconnected. Total active: %d", atomic.LoadInt32(&activeAgents))
	}()

	clientAddr := conn.RemoteAddr().String()
	log.Printf("New agent connected: %s\n", clientAddr)

	reader := bufio.NewReader(conn)

	for {
		buf := make([]byte, 1024)
		n, err := reader.Read(buf)
		if err != nil {
			if err == io.EOF {
				log.Printf("Agent %s disconnected", clientAddr)
			} else {
				log.Printf("Read error from %s: %v", clientAddr, err)
			}
			break
		}
		data := string(buf[:n])
		log.Printf("[%s] Received Metric: %s%%", clientAddr, data)

	}
}
