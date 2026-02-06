package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync/atomic"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	fmt.Println("Starting socket server on 127.0.0.1:8080")

	// connect to the database
	dbpool, err := pgxpool.New(context.Background(), "postgres://sakib:5001@192.168.1.10:5432/rihno-db")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer dbpool.Close()
	fmt.Println("Connected to the database")

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
		go handleConnection(conn, dbpool)
	}
}

// Global counter to track active agents
var activeAgents int32

func handleConnection(conn net.Conn, dbpool *pgxpool.Pool) {
	defer func() {
		conn.Close()
		atomic.AddInt32(&activeAgents, -1)
		log.Printf("Agent disconnected. Total active: %d", atomic.LoadInt32(&activeAgents))
	}()

	// Increment active agents when connection starts
	atomic.AddInt32(&activeAgents, 1)
	clientAddr := conn.RemoteAddr().String()
	log.Printf("New agent connected: %s. Total active: %d\n", clientAddr, atomic.LoadInt32(&activeAgents))

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

		// Clean and parse the data
		dataStr := string(buf[:n])
		var metric float64
		_, err = fmt.Sscanf(dataStr, "%f", &metric)
		if err != nil {
			log.Printf("Error parsing float from %s: %v", clientAddr, err)
			continue
		}

		// Save to database
		query := `INSERT INTO "test" ("cpu") VALUES ($1)`
		_, err = dbpool.Exec(context.Background(), query, metric)
		if err != nil {
			log.Printf("Database insert error: %v", err)
			continue
		}
		log.Printf("[%s] Saved Metric to DB: %.2f", clientAddr, metric)
	}
}
