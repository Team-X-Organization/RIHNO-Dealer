package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Global counter to track active agents
var activeAgents int32

func main() {
	fmt.Println("Starting socket server on 127.0.0.1:8080")

	// connect to the database
	// If running Go on your machine and Postgres in Docker mapped to 5432:
	connStr := "postgres://postgres:5001@192.168.1.10:5432/rihno_db"

	dbpool, err := pgxpool.New(context.Background(), connStr)

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

	log.Println("Server started on :8080. Waiting for agents...")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("Error accepting client connection")
			continue
		}
		go handleConnection(conn, dbpool)
	}
}

func handleConnection(conn net.Conn, dbpool *pgxpool.Pool) {
	atomic.AddInt32(&activeAgents, 1)
	clientAddr := conn.RemoteAddr().String()

	defer func() {
		conn.Close()
		atomic.AddInt32(&activeAgents, -1)
		log.Printf("Agent disconnected. Total active: %d", atomic.LoadInt32(&activeAgents))
	}()

	// Increment active agents when connection starts
	log.Printf("New agent connected: %s. Total active: %d\n", clientAddr, atomic.LoadInt32(&activeAgents))

	reader := bufio.NewReader(conn)

	for {
		// Matches the client's fmt.Fprintf(conn, "%.2f\n", cpuVal)
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("[%s] Read error: %v", clientAddr, err)
			}
			break
		}

		// Clean up string and parse to float
		line = strings.TrimSpace(line)
		var metric float64
		_, err = fmt.Sscanf(line, "%f", &metric)
		if err != nil {
			log.Printf("[%s] Data parsing error: %v", clientAddr, err)
			continue
		}

		// Save to TimescaleDB (INSERT DATA)
		query := `INSERT INTO rihno_metrics (time, agent_id, cpu_usage) VALUES ($1, $2, $3)`
		_, err = dbpool.Exec(context.Background(), query, time.Now(), clientAddr, metric)
		if err != nil {
			log.Printf("Database insert error: %v", err)
			continue
		}
		log.Printf("[%s] Saved Metric to DB: %.2f", clientAddr, metric)
	}
}
