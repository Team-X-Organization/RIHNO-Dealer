// dealer/main.go

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/kafka-go"
)

var activeAgents int32
var kafkaWriter *kafka.Writer

// ========== DATA STRUCTURES (must match agent) ==========

type MetricsPayload struct {
	Timestamp  string            `json:"timestamp"`
	Email      string            `json:"email"`
	AgentName  string            `json:"agent_name"`
	AgentType  string            `json:"agent_type"`
	Metrics    FeatureMetrics    `json:"metrics"`
	NetworkMap NetworkMapPayload `json:"network_map"`
}

type FeatureMetrics struct {
	ProcessCount              int     `json:"process_count"`
	ProcessCreationRate       int     `json:"process_creation_rate"`
	ProcessTermRate           int     `json:"process_termination_rate"`
	HighCPUProcessCount       int     `json:"high_cpu_process_count"`
	HighMemProcessCount       int     `json:"high_mem_process_count"`
	AvgProcessCPU             float64 `json:"avg_process_cpu"`
	AvgProcessMemory          float64 `json:"avg_process_memory"`
	AvgProcessRSS             uint64  `json:"avg_process_rss"`
	AvgProcessVMS             uint64  `json:"avg_process_vms"`
	TotalThreads              int     `json:"total_threads"`
	ZombieProcessCount        int     `json:"zombie_process_count"`
	RootProcessCount          int     `json:"root_process_count"`
	AvgProcessAge             float64 `json:"avg_process_age_seconds"`
	ProcessWithManyThreads    int     `json:"process_with_many_threads"`
	SuspiciousProcessNames    int     `json:"suspicious_process_names"`
	TotalFileDescriptors      int     `json:"total_file_descriptors"`
	SystemCPU                 float64 `json:"system_cpu"`
	AvgCoreCPU                float64 `json:"avg_core_cpu"`
	SystemMemoryPercent       float64 `json:"system_memory_percent"`
	SystemMemoryUsed          uint64  `json:"system_memory_used"`
	SystemMemoryAvail         uint64  `json:"system_memory_available"`
	SystemMemoryTotal         uint64  `json:"system_memory_total"`
	SwapUsedPercent           float64 `json:"swap_used_percent"`
	SwapTotal                 uint64  `json:"swap_total"`
	SwapUsed                  uint64  `json:"swap_used"`
	DiskReadBytes             uint64  `json:"disk_read_bytes"`
	DiskWriteBytes            uint64  `json:"disk_write_bytes"`
	DiskReadRate              float64 `json:"disk_read_rate"`
	DiskWriteRate             float64 `json:"disk_write_rate"`
	DiskReadCount             uint64  `json:"disk_read_count"`
	DiskWriteCount            uint64  `json:"disk_write_count"`
	DiskIORate                float64 `json:"disk_io_rate"`
	LoggedInUsers             int     `json:"logged_in_users"`
	SystemUptime              uint64  `json:"system_uptime"`
	SystemBootTime            uint64  `json:"system_boot_time"`
	CPUUsageSpike             float64 `json:"cpu_usage_spike"`
	MemoryUsageSpike          float64 `json:"memory_usage_spike"`
	TotalConnections          int     `json:"total_connections"`
	TCPConnections            int     `json:"tcp_connections"`
	UDPConnections            int     `json:"udp_connections"`
	EstablishedConnections    int     `json:"established_connections"`
	ListenConnections         int     `json:"listen_connections"`
	TimeWaitConnections       int     `json:"time_wait_connections"`
	SynSentConnections        int     `json:"syn_sent_connections"`
	SynRecvConnections        int     `json:"syn_recv_connections"`
	CloseWaitConnections      int     `json:"close_wait_connections"`
	FinWaitConnections        int     `json:"fin_wait_connections"`
	NetBytesSent              uint64  `json:"net_bytes_sent"`
	NetBytesRecv              uint64  `json:"net_bytes_recv"`
	NetPacketsSent            uint64  `json:"net_packets_sent"`
	NetPacketsRecv            uint64  `json:"net_packets_recv"`
	NetErrorsIn               uint64  `json:"net_errors_in"`
	NetErrorsOut              uint64  `json:"net_errors_out"`
	NetDropsIn                uint64  `json:"net_drops_in"`
	NetDropsOut               uint64  `json:"net_drops_out"`
	NetSendRate               float64 `json:"net_send_rate"`
	NetRecvRate               float64 `json:"net_recv_rate"`
	NetPacketSendRate         float64 `json:"net_packet_send_rate"`
	NetPacketRecvRate         float64 `json:"net_packet_recv_rate"`
	UniqueSourceIPs           int     `json:"unique_source_ips"`
	UniqueDestIPs             int     `json:"unique_dest_ips"`
	NewSourceIPs              int     `json:"new_source_ips"`
	PrivateIPConnections      int     `json:"private_ip_connections"`
	PublicIPConnections       int     `json:"public_ip_connections"`
	TopSourceIPCount          int     `json:"top_source_ip_count"`
	TopSourceIP               string  `json:"top_source_ip"`
	UniqueLocalPorts          int     `json:"unique_local_ports"`
	UniqueRemotePorts         int     `json:"unique_remote_ports"`
	WellKnownPortConns        int     `json:"well_known_port_connections"`
	EphemeralPortConns        int     `json:"ephemeral_port_connections"`
	SuspiciousPortConns       int     `json:"suspicious_port_connections"`
	PortScanIndicators        int     `json:"port_scan_indicators"`
	TCPRatio                  float64 `json:"tcp_ratio"`
	UDPRatio                  float64 `json:"udp_ratio"`
	TCPUDPRatio               float64 `json:"tcp_udp_ratio"`
	ProcessesWithNetActivity  int     `json:"processes_with_net_activity"`
	AvgConnectionsPerProcess  float64 `json:"avg_connections_per_process"`
	ConnectionCreationRate    int     `json:"connection_creation_rate"`
	ConnectionTerminationRate int     `json:"connection_termination_rate"`
	ExternalIPCount           int     `json:"external_ip_count"`
	LoopbackConnections       int     `json:"loopback_connections"`
	BroadcastConnections      int     `json:"broadcast_connections"`
	ConnectionChurnRate       float64 `json:"connection_churn_rate"`
	ConnectionDensity         float64 `json:"connection_density"`
	PortScanningScore         float64 `json:"port_scanning_score"`
	DataExfiltrationScore     float64 `json:"data_exfiltration_score"`
	BandwidthAsymmetry        float64 `json:"bandwidth_asymmetry"`
	C2CommunicationScore      float64 `json:"c2_communication_score"`
	FailedConnectionRatio     float64 `json:"failed_connection_ratio"`
	TotalIncomingConnections  int     `json:"total_incoming_connections"`
	TotalOutgoingConnections  int     `json:"total_outgoing_connections"`
	UniqueIncomingIPs         int     `json:"unique_incoming_ips"`
	UniqueOutgoingIPs         int     `json:"unique_outgoing_ips"`
	LocalIPsCount             int     `json:"local_ips_count"`
}

type NetworkMapPayload struct {
	Connections []ConnectionDetail `json:"connections"`
	LocalIPs    []string           `json:"local_ips"`
}

type ConnectionDetail struct {
	RemoteIP     string `json:"remote_ip"`
	RemotePort   uint32 `json:"remote_port"`
	LocalIP      string `json:"local_ip"`
	LocalPort    uint32 `json:"local_port"`
	Protocol     string `json:"protocol"`
	State        string `json:"state"`
	PID          int32  `json:"pid"`
	ProcessName  string `json:"process_name"`
	Direction    string `json:"direction"`
	IsPrivate    bool   `json:"is_private"`
	IsLoopback   bool   `json:"is_loopback"`
	IsSuspicious bool   `json:"is_suspicious"`
}

// ========== KAFKA FUNCTIONS ==========

// initKafkaWriter initializes the Kafka writer for producing messages
func initKafkaWriter(brokers []string, topic string) *kafka.Writer {
	return &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		Topic:        topic,
		Balancer:     &kafka.LeastBytes{},
		BatchSize:    1,
		RequiredAcks: kafka.RequireOne,
		WriteTimeout: 10 * time.Second,
		ReadTimeout:  10 * time.Second,
	}
}

// sendToKafka sends the MetricsPayload to Kafka topic
func sendToKafka(payload *MetricsPayload) error {
	// Marshal payload to JSON
	messageValue, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Create a unique key using email:agent_name for partitioning
	// This ensures all metrics from the same agent go to the same partition
	messageKey := fmt.Sprintf("%s:%s", payload.Email, payload.AgentName)

	// Create Kafka message
	msg := kafka.Message{
		Key:   []byte(messageKey),
		Value: messageValue,
		Time:  time.Now(),
	}

	// Send message to Kafka with context timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = kafkaWriter.WriteMessages(ctx, msg)
	if err != nil {
		return fmt.Errorf("failed to write message to kafka: %w", err)
	}

	log.Printf("[Kafka] Successfully sent metrics for %s (key: %s)", payload.AgentName, messageKey)
	return nil
}

// ========== CORS MIDDLEWARE ==========

func enableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		// Handle preflight request
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next(w, r)
	}
}

// ========== MAIN ==========

func main() {
	fmt.Println("Starting Rihno Dealer...")

	// Initialize Kafka Writer
	kafkaBrokers := []string{"localhost:9092"}
	kafkaTopic := "rihno-metrics"
	kafkaWriter = initKafkaWriter(kafkaBrokers, kafkaTopic)
	defer kafkaWriter.Close()
	log.Printf("Kafka writer initialized for topic '%s' at %v", kafkaTopic, kafkaBrokers)

	// 1. Connect to PostgreSQL/TimescaleDB
	connStr := os.Getenv("DB_URL")
	if connStr == "" {
		connStr = "postgres://postgres:5001@my_rihno_db:5432/rihnodb?sslmode=disable"
		log.Println("WARNING: DB_URL environment variable is not set. Falling back to default.")
	}

	dbpool, err := pgxpool.New(context.Background(), connStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer dbpool.Close()

	// Verify connection
	if err := dbpool.Ping(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "Database ping failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Connected to TimescaleDB")

	// 2. Register the route with CORS middleware
	http.HandleFunc("/metrics/cpu", enableCORS(getSystemCPU(dbpool)))
	http.HandleFunc("/metrics/latest_full", enableCORS(getLatestFullMetrics(dbpool)))
	http.HandleFunc("/metrics/history", enableCORS(getMetricsHistory(dbpool)))
	http.HandleFunc("/metrics/network_map", enableCORS(getNetworkMap(dbpool)))
	http.HandleFunc("/alerts/recent", enableCORS(getRecentAlerts(dbpool)))
	http.HandleFunc("/agents/status", enableCORS(getAgentsStatus(dbpool)))

	// 3. Start the server
	httpPort := os.Getenv("HTTP_PORT")
	if httpPort == "" {
		httpPort = "8000" // default for Frontend API
	}

	go func() {
		log.Printf("Starting HTTP server on :%s (Metrics API)", httpPort)
		if err := http.ListenAndServe(":"+httpPort, nil); err != nil {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()

	// 4. Start listening on TCP port
	tcpPort := os.Getenv("TCP_PORT")
	if tcpPort == "" {
		tcpPort = "8080" // default for raw agent connections
	}

	listener, err := net.Listen("tcp", ":"+tcpPort)
	if err != nil {
		log.Fatalf("Error listening: %v", err)
	}
	defer listener.Close()

	fmt.Printf("Dealer listening on :%s for agent connections...\n", tcpPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		go handleConnection(conn, dbpool)
	}
}

func handleConnection(conn net.Conn, dbpool *pgxpool.Pool) {
	atomic.AddInt32(&activeAgents, 1)
	clientAddr := conn.RemoteAddr().String()
	var connectedAgentName string

	defer func() {
		conn.Close()
		atomic.AddInt32(&activeAgents, -1)
		log.Printf("[%s] Agent disconnected. Active: %d", clientAddr, atomic.LoadInt32(&activeAgents))
		if dbpool != nil && connectedAgentName != "" {
			dbpool.Exec(context.Background(), "UPDATE rihno_agents SET is_active = false WHERE agent_name = $1", connectedAgentName)
		}
	}()

	log.Printf("[%s] New agent connected. Active: %d", clientAddr, atomic.LoadInt32(&activeAgents))

	reader := bufio.NewReader(conn)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("[%s] Read error: %v", clientAddr, err)
			}
			break
		}

		line = trimLine(line)
		if line == "" {
			continue
		}

		// URL-decode the line first
		decoded, err := url.QueryUnescape(line)
		if err != nil {
			log.Printf("[%s] URL decode error: %v", clientAddr, err)
			continue
		}

		// Parse JSON payload
		var payload MetricsPayload
		if err := json.Unmarshal([]byte(decoded), &payload); err != nil {
			log.Printf("[%s] JSON parse error: %v", clientAddr, err)
			continue
		}

		// Insert metrics into TimescaleDB
		if err := insertMetrics(dbpool, clientAddr, &payload); err != nil {
			log.Printf("[%s] DB metrics insert error: %v", clientAddr, err)
			continue
		}

		// ========== KAFKA INTEGRATION: Send to Kafka after successful DB insertion ==========
		if err := sendToKafka(&payload); err != nil {
			log.Printf("[%s] Kafka send error: %v", clientAddr, err)
			// Don't continue here - we want to proceed even if Kafka fails
		}

		// Insert network map
		if err := insertNetworkMap(dbpool, clientAddr, &payload); err != nil {
			log.Printf("[%s] DB network map insert error: %v", clientAddr, err)
		}

		// Insert individual connections
		if err := insertConnections(dbpool, clientAddr, &payload); err != nil {
			log.Printf("[%s] DB connections insert error: %v", clientAddr, err)
		}

		connectedAgentName = payload.AgentName

		// Update agent registry
		if err := upsertAgent(dbpool, clientAddr, &payload); err != nil {
			log.Printf("[%s] DB agent upsert error: %v", clientAddr, err)
		}

		// Check for alerts
		checkAndInsertAlerts(dbpool, clientAddr, &payload)

		log.Printf("[%s] %s | CPU: %.1f%% | Mem: %.1f%% | Conns: %d | Suspicious: %d",
			clientAddr, payload.AgentName,
			payload.Metrics.SystemCPU, payload.Metrics.SystemMemoryPercent,
			payload.Metrics.TotalConnections, payload.Metrics.SuspiciousPortConns)
	}
}

func trimLine(s string) string {
	// Remove \n, \r, spaces
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	for len(s) > 0 && (s[0] == ' ') {
		s = s[1:]
	}
	return s
}

// ========== DATABASE INSERT FUNCTIONS ==========

func insertMetrics(dbpool *pgxpool.Pool, agentID string, p *MetricsPayload) error {
	m := p.Metrics
	query := `
	INSERT INTO rihno_metrics (
		time, agent_id, email, agent_name, agent_type,
		process_count, process_creation_rate, process_termination_rate,
		high_cpu_process_count, high_mem_process_count,
		avg_process_cpu, avg_process_memory, avg_process_rss, avg_process_vms,
		total_threads, zombie_process_count, root_process_count,
		avg_process_age_seconds, process_with_many_threads,
		suspicious_process_names, total_file_descriptors,
		system_cpu, avg_core_cpu,
		system_memory_percent, system_memory_used, system_memory_available, system_memory_total,
		swap_used_percent, swap_total, swap_used,
		disk_read_bytes, disk_write_bytes, disk_read_rate, disk_write_rate,
		disk_read_count, disk_write_count, disk_io_rate,
		logged_in_users, system_uptime, system_boot_time,
		cpu_usage_spike, memory_usage_spike,
		total_connections, tcp_connections, udp_connections,
		established_connections, listen_connections, time_wait_connections,
		syn_sent_connections, syn_recv_connections, close_wait_connections, fin_wait_connections,
		net_bytes_sent, net_bytes_recv, net_packets_sent, net_packets_recv,
		net_errors_in, net_errors_out, net_drops_in, net_drops_out,
		net_send_rate, net_recv_rate, net_packet_send_rate, net_packet_recv_rate,
		unique_source_ips, unique_dest_ips, new_source_ips,
		private_ip_connections, public_ip_connections,
		top_source_ip_count, top_source_ip,
		unique_local_ports, unique_remote_ports,
		well_known_port_connections, ephemeral_port_connections,
		suspicious_port_connections, port_scan_indicators,
		tcp_ratio, udp_ratio, tcp_udp_ratio,
		processes_with_net_activity, avg_connections_per_process,
		connection_creation_rate, connection_termination_rate,
		external_ip_count, loopback_connections, broadcast_connections,
		connection_churn_rate, connection_density,
		port_scanning_score, data_exfiltration_score,
		bandwidth_asymmetry, c2_communication_score, failed_connection_ratio,
		total_incoming_connections, total_outgoing_connections,
		unique_incoming_ips, unique_outgoing_ips, local_ips_count
	) VALUES (
		$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
		$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
		$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,
		$31,$32,$33,$34,$35,$36,$37,$38,$39,$40,
		$41,$42,$43,$44,$45,$46,$47,$48,$49,$50,
		$51,$52,$53,$54,$55,$56,$57,$58,$59,$60,
		$61,$62,$63,$64,$65,$66,$67,$68,$69,$70,
		$71,$72,$73,$74,$75,$76,$77,$78,$79,$80,
		$81,$82,$83,$84,$85,$86,$87,$88,$89,$90,
		$91,$92,$93,$94,$95,$96,$97,$98,$99
	)`

	_, err := dbpool.Exec(context.Background(), query,
		time.Now(),                  // $1
		agentID,                     // $2
		p.Email,                     // $3
		p.AgentName,                 // $4
		p.AgentType,                 // $5
		m.ProcessCount,              // $6
		m.ProcessCreationRate,       // $7
		m.ProcessTermRate,           // $8
		m.HighCPUProcessCount,       // $9
		m.HighMemProcessCount,       // $10
		m.AvgProcessCPU,             // $11
		m.AvgProcessMemory,          // $12
		m.AvgProcessRSS,             // $13
		m.AvgProcessVMS,             // $14
		m.TotalThreads,              // $15
		m.ZombieProcessCount,        // $16
		m.RootProcessCount,          // $17
		m.AvgProcessAge,             // $18
		m.ProcessWithManyThreads,    // $19
		m.SuspiciousProcessNames,    // $20
		m.TotalFileDescriptors,      // $21
		m.SystemCPU,                 // $22
		m.AvgCoreCPU,                // $23
		m.SystemMemoryPercent,       // $24
		m.SystemMemoryUsed,          // $25
		m.SystemMemoryAvail,         // $26
		m.SystemMemoryTotal,         // $27
		m.SwapUsedPercent,           // $28
		m.SwapTotal,                 // $29
		m.SwapUsed,                  // $30
		m.DiskReadBytes,             // $31
		m.DiskWriteBytes,            // $32
		m.DiskReadRate,              // $33
		m.DiskWriteRate,             // $34
		m.DiskReadCount,             // $35
		m.DiskWriteCount,            // $36
		m.DiskIORate,                // $37
		m.LoggedInUsers,             // $38
		m.SystemUptime,              // $39
		m.SystemBootTime,            // $40
		m.CPUUsageSpike,             // $41
		m.MemoryUsageSpike,          // $42
		m.TotalConnections,          // $43
		m.TCPConnections,            // $44
		m.UDPConnections,            // $45
		m.EstablishedConnections,    // $46
		m.ListenConnections,         // $47
		m.TimeWaitConnections,       // $48
		m.SynSentConnections,        // $49
		m.SynRecvConnections,        // $50
		m.CloseWaitConnections,      // $51
		m.FinWaitConnections,        // $52
		m.NetBytesSent,              // $53
		m.NetBytesRecv,              // $54
		m.NetPacketsSent,            // $55
		m.NetPacketsRecv,            // $56
		m.NetErrorsIn,               // $57
		m.NetErrorsOut,              // $58
		m.NetDropsIn,                // $59
		m.NetDropsOut,               // $60
		m.NetSendRate,               // $61
		m.NetRecvRate,               // $62
		m.NetPacketSendRate,         // $63
		m.NetPacketRecvRate,         // $64
		m.UniqueSourceIPs,           // $65
		m.UniqueDestIPs,             // $66
		m.NewSourceIPs,              // $67
		m.PrivateIPConnections,      // $68
		m.PublicIPConnections,       // $69
		m.TopSourceIPCount,          // $70
		m.TopSourceIP,               // $71
		m.UniqueLocalPorts,          // $72
		m.UniqueRemotePorts,         // $73
		m.WellKnownPortConns,        // $74
		m.EphemeralPortConns,        // $75
		m.SuspiciousPortConns,       // $76
		m.PortScanIndicators,        // $77
		m.TCPRatio,                  // $78
		m.UDPRatio,                  // $79
		m.TCPUDPRatio,               // $80
		m.ProcessesWithNetActivity,  // $81
		m.AvgConnectionsPerProcess,  // $82
		m.ConnectionCreationRate,    // $83
		m.ConnectionTerminationRate, // $84
		m.ExternalIPCount,           // $85
		m.LoopbackConnections,       // $86
		m.BroadcastConnections,      // $87
		m.ConnectionChurnRate,       // $88
		m.ConnectionDensity,         // $89
		m.PortScanningScore,         // $90
		m.DataExfiltrationScore,     // $91
		m.BandwidthAsymmetry,        // $92
		m.C2CommunicationScore,      // $93
		m.FailedConnectionRatio,     // $94
		m.TotalIncomingConnections,  // $95
		m.TotalOutgoingConnections,  // $96
		m.UniqueIncomingIPs,         // $97
		m.UniqueOutgoingIPs,         // $98
		m.LocalIPsCount,             // $99
	)

	return err
}

func insertNetworkMap(dbpool *pgxpool.Pool, agentID string, p *MetricsPayload) error {
	mapJSON, err := json.Marshal(p.NetworkMap)
	if err != nil {
		return fmt.Errorf("error marshaling network map: %w", err)
	}

	query := `INSERT INTO rihno_network_maps (time, agent_id, email, agent_name, network_map_json)
	           VALUES ($1, $2, $3, $4, $5)`

	_, err = dbpool.Exec(context.Background(), query,
		time.Now(), agentID, p.Email, p.AgentName, mapJSON)

	return err
}

func insertConnections(dbpool *pgxpool.Pool, agentID string, p *MetricsPayload) error {
	for _, conn := range p.NetworkMap.Connections {
		query := `
		INSERT INTO rihno_connections (
			time, agent_id, email, agent_name,
			remote_ip, remote_port, local_ip, local_port,
			protocol, state, pid, process_name, direction,
			is_private, is_loopback, is_suspicious
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16
		)
		`
		_, err := dbpool.Exec(context.Background(), query,
			time.Now(), agentID, p.Email, p.AgentName,
			conn.RemoteIP, conn.RemotePort, conn.LocalIP, conn.LocalPort,
			conn.Protocol, conn.State, conn.PID, conn.ProcessName, conn.Direction,
			conn.IsPrivate, conn.IsLoopback, conn.IsSuspicious,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func upsertAgent(dbpool *pgxpool.Pool, agentID string, p *MetricsPayload) error {
	query := `
	INSERT INTO rihno_agents (agent_name, email, agent_type, is_active, last_seen)
	VALUES ($1, $2, $3, true, NOW())
	ON CONFLICT (agent_name)
	DO UPDATE SET is_active = true, last_seen = NOW()
	`
	_, err := dbpool.Exec(context.Background(), query, p.AgentName, p.Email, p.AgentType)
	return err
}

func checkAndInsertAlerts(dbpool *pgxpool.Pool, agentID string, p *MetricsPayload) {
	// Placeholder for alert logic
	m := p.Metrics

	type AlertDef struct {
		condition   bool
		alertType   string
		severity    string
		description string
		metricName  string
		metricValue float64
		threshold   float64
	}

	alerts := []AlertDef{
		{
			condition:   m.SystemCPU > 90.0,
			alertType:   "system_cpu_high",
			severity:    "warning",
			description: "System CPU usage is critically high",
			metricName:  "system_cpu",
			metricValue: m.SystemCPU,
			threshold:   90.0,
		},
		{
			condition:   m.SystemMemoryPercent > 90.0,
			alertType:   "system_memory_high",
			severity:    "warning",
			description: "System memory usage is critically high",
			metricName:  "system_memory_percent",
			metricValue: m.SystemMemoryPercent,
			threshold:   90.0,
		},
		{
			condition:   m.SuspiciousPortConns > 10,
			alertType:   "suspicious_connections",
			severity:    "critical",
			description: "High number of suspicious port connections detected",
			metricName:  "suspicious_port_connections",
			metricValue: float64(m.SuspiciousPortConns),
			threshold:   10.0,
		},
	}

	for _, alert := range alerts {
		if alert.condition {
			insertAlert(dbpool, agentID, p, alert)
		}
	}
}

func insertAlert(dbpool *pgxpool.Pool, agentID string, p *MetricsPayload, alert interface{}) {
	type AlertDef struct {
		alertType   string
		severity    string
		description string
		metricName  string
		metricValue float64
		threshold   float64
	}
	a := alert.(AlertDef)

	query := `
	INSERT INTO rihno_alerts (
		time, agent_id, email, agent_name, alert_type, severity,
		description, metric_name, metric_value, threshold
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	`
	_, err := dbpool.Exec(context.Background(), query,
		time.Now(), agentID, p.Email, p.AgentName,
		a.alertType, a.severity, a.description,
		a.metricName, a.metricValue, a.threshold,
	)
	if err != nil {
		log.Printf("Failed to insert alert: %v", err)
	}
}

// ========== HTTP HANDLERS (copied from original file) ==========

type CPUMetrics struct {
	Value float64 `json:"value"`
}

func getSystemCPU(dbpool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")
		deviceName := r.URL.Query().Get("device_name")

		if email == "" || deviceName == "" {
			http.Error(w, "Missing email or device_name parameter", http.StatusBadRequest)
			return
		}

		query := `
			SELECT system_cpu
			FROM rihno_metrics
			WHERE email = $1 AND agent_name = $2
			ORDER BY time DESC
			LIMIT 1;
		`

		var cpu float64
		err := dbpool.QueryRow(context.Background(), query, email, deviceName).Scan(&cpu)

		if err != nil {
			if err == pgx.ErrNoRows {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(CPUMetrics{Value: 0})
				return
			}
			fmt.Fprintf(os.Stderr, "getSystemCPU query error: %v\n", err)
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(CPUMetrics{Value: cpu})
	}
}

type FullMetrics struct {
	Timestamp string         `json:"timestamp"`
	Email     string         `json:"email"`
	AgentName string         `json:"agent_name"`
	AgentType string         `json:"agent_type"`
	Metrics   FeatureMetrics `json:"metrics"`
}

func getLatestFullMetrics(dbpool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")
		deviceName := r.URL.Query().Get("device_name")

		if email == "" || deviceName == "" {
			http.Error(w, "Missing email or device_name parameter", http.StatusBadRequest)
			return
		}

		query := `
			SELECT
				time, email, agent_name, agent_type,
				process_count, process_creation_rate, process_termination_rate,
				high_cpu_process_count, high_mem_process_count,
				avg_process_cpu, avg_process_memory, avg_process_rss, avg_process_vms,
				total_threads, zombie_process_count, root_process_count,
				avg_process_age_seconds, process_with_many_threads,
				suspicious_process_names, total_file_descriptors,
				system_cpu, avg_core_cpu,
				system_memory_percent, system_memory_used, system_memory_available, system_memory_total,
				swap_used_percent, swap_total, swap_used,
				disk_read_bytes, disk_write_bytes, disk_read_rate, disk_write_rate,
				disk_read_count, disk_write_count, disk_io_rate,
				logged_in_users, system_uptime, system_boot_time,
				cpu_usage_spike, memory_usage_spike,
				total_connections, tcp_connections, udp_connections,
				established_connections, listen_connections, time_wait_connections,
				syn_sent_connections, syn_recv_connections, close_wait_connections, fin_wait_connections,
				net_bytes_sent, net_bytes_recv, net_packets_sent, net_packets_recv,
				net_errors_in, net_errors_out, net_drops_in, net_drops_out,
				net_send_rate, net_recv_rate, net_packet_send_rate, net_packet_recv_rate,
				unique_source_ips, unique_dest_ips, new_source_ips,
				private_ip_connections, public_ip_connections,
				top_source_ip_count, top_source_ip,
				unique_local_ports, unique_remote_ports,
				well_known_port_connections, ephemeral_port_connections,
				suspicious_port_connections, port_scan_indicators,
				tcp_ratio, udp_ratio, tcp_udp_ratio,
				processes_with_net_activity, avg_connections_per_process,
				connection_creation_rate, connection_termination_rate,
				external_ip_count, loopback_connections, broadcast_connections,
				connection_churn_rate, connection_density,
				port_scanning_score, data_exfiltration_score,
				bandwidth_asymmetry, c2_communication_score, failed_connection_ratio,
				total_incoming_connections, total_outgoing_connections,
				unique_incoming_ips, unique_outgoing_ips, local_ips_count
			FROM rihno_metrics
			WHERE email = $1 AND agent_name = $2
			ORDER BY time DESC
			LIMIT 1;
		`

		var fm FullMetrics
		var ts time.Time
		m := &fm.Metrics

		err := dbpool.QueryRow(context.Background(), query, email, deviceName).Scan(
			&ts, &fm.Email, &fm.AgentName, &fm.AgentType,
			&m.ProcessCount, &m.ProcessCreationRate, &m.ProcessTermRate,
			&m.HighCPUProcessCount, &m.HighMemProcessCount,
			&m.AvgProcessCPU, &m.AvgProcessMemory, &m.AvgProcessRSS, &m.AvgProcessVMS,
			&m.TotalThreads, &m.ZombieProcessCount, &m.RootProcessCount,
			&m.AvgProcessAge, &m.ProcessWithManyThreads,
			&m.SuspiciousProcessNames, &m.TotalFileDescriptors,
			&m.SystemCPU, &m.AvgCoreCPU,
			&m.SystemMemoryPercent, &m.SystemMemoryUsed, &m.SystemMemoryAvail, &m.SystemMemoryTotal,
			&m.SwapUsedPercent, &m.SwapTotal, &m.SwapUsed,
			&m.DiskReadBytes, &m.DiskWriteBytes, &m.DiskReadRate, &m.DiskWriteRate,
			&m.DiskReadCount, &m.DiskWriteCount, &m.DiskIORate,
			&m.LoggedInUsers, &m.SystemUptime, &m.SystemBootTime,
			&m.CPUUsageSpike, &m.MemoryUsageSpike,
			&m.TotalConnections, &m.TCPConnections, &m.UDPConnections,
			&m.EstablishedConnections, &m.ListenConnections, &m.TimeWaitConnections,
			&m.SynSentConnections, &m.SynRecvConnections, &m.CloseWaitConnections, &m.FinWaitConnections,
			&m.NetBytesSent, &m.NetBytesRecv, &m.NetPacketsSent, &m.NetPacketsRecv,
			&m.NetErrorsIn, &m.NetErrorsOut, &m.NetDropsIn, &m.NetDropsOut,
			&m.NetSendRate, &m.NetRecvRate, &m.NetPacketSendRate, &m.NetPacketRecvRate,
			&m.UniqueSourceIPs, &m.UniqueDestIPs, &m.NewSourceIPs,
			&m.PrivateIPConnections, &m.PublicIPConnections,
			&m.TopSourceIPCount, &m.TopSourceIP,
			&m.UniqueLocalPorts, &m.UniqueRemotePorts,
			&m.WellKnownPortConns, &m.EphemeralPortConns,
			&m.SuspiciousPortConns, &m.PortScanIndicators,
			&m.TCPRatio, &m.UDPRatio, &m.TCPUDPRatio,
			&m.ProcessesWithNetActivity, &m.AvgConnectionsPerProcess,
			&m.ConnectionCreationRate, &m.ConnectionTerminationRate,
			&m.ExternalIPCount, &m.LoopbackConnections, &m.BroadcastConnections,
			&m.ConnectionChurnRate, &m.ConnectionDensity,
			&m.PortScanningScore, &m.DataExfiltrationScore,
			&m.BandwidthAsymmetry, &m.C2CommunicationScore, &m.FailedConnectionRatio,
			&m.TotalIncomingConnections, &m.TotalOutgoingConnections,
			&m.UniqueIncomingIPs, &m.UniqueOutgoingIPs, &m.LocalIPsCount,
		)

		if err != nil {
			if err == pgx.ErrNoRows {
				http.Error(w, "No data found for this device", http.StatusNotFound)
				return
			}
			fmt.Fprintf(os.Stderr, "getLatestFullMetrics query error: %v\n", err)
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		fm.Timestamp = ts.Format(time.RFC3339)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(fm)
	}
}

type HistoryPoint struct {
	Date  string  `json:"date"`
	Count int     `json:"count"`
	Level int     `json:"level"`
	Raw   float64 `json:"raw,omitempty"`
	Raw2  float64 `json:"raw2,omitempty"`
}

func getMetricsHistory(dbpool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")
		deviceName := r.URL.Query().Get("device_name")
		metric := r.URL.Query().Get("metric")
		rangeParam := r.URL.Query().Get("range")

		if email == "" {
			http.Error(w, "email parameter is required", http.StatusBadRequest)
			return
		}

		if metric == "" {
			metric = "system_cpu"
		}

		if rangeParam == "" {
			rangeParam = "24h"
		}

		type rangeConfig struct {
			trunc      string
			interval   string
			dateFormat string
		}
		rangeMap := map[string]rangeConfig{
			"1h":  {"minute", "1 hour", time.RFC3339},
			"24h": {"hour", "1 day", time.RFC3339},
			"7d":  {"hour", "7 days", time.RFC3339},
			"30d": {"day", "30 days", "2006-01-02"},
		}

		rc, ok := rangeMap[rangeParam]
		if !ok {
			http.Error(w, "Invalid range parameter. Use 1h, 24h, 7d, or 30d", http.StatusBadRequest)
			return
		}

		type metricConfig struct {
			col    string
			col2   string
			maxPct float64
		}

		metricMap := map[string]metricConfig{
			"system_cpu":          {"system_cpu", "", 100},
			"system_memory":       {"system_memory_percent", "", 100},
			"connections":         {"total_connections", "", 0},
			"suspicious":          {"suspicious_port_connections", "", 0},
			"disk_io":             {"disk_read_rate", "disk_write_rate", 0},
			"network_throughput":  {"net_send_rate", "net_recv_rate", 0},
			"process_activity":    {"process_creation_rate", "process_termination_rate", 0},
			"connection_activity": {"connection_creation_rate", "connection_termination_rate", 0},
		}

		cfg, ok := metricMap[metric]
		if !ok {
			http.Error(w, fmt.Sprintf("Unknown metric: %s", metric), http.StatusBadRequest)
			return
		}

		var query string
		var queryArgs []interface{}

		col2Select := "0"
		if cfg.col2 != "" {
			col2Select = fmt.Sprintf("COALESCE(AVG(%s), 0)", cfg.col2)
		}

		if deviceName == "" {
			query = fmt.Sprintf(`
				SELECT
				  DATE_TRUNC('%s', time) AS the_date,
				  COALESCE(AVG(%s), 0) AS avg_val,
				  %s AS avg_val2
				FROM rihno_metrics
				WHERE email = $1
				  AND time > NOW() - INTERVAL '%s'
				GROUP BY the_date
				ORDER BY the_date ASC;
			`, rc.trunc, cfg.col, col2Select, rc.interval)
			queryArgs = []interface{}{email}
		} else {
			query = fmt.Sprintf(`
				SELECT
				  DATE_TRUNC('%s', time) AS the_date,
				  COALESCE(AVG(%s), 0) AS avg_val,
				  %s AS avg_val2
				FROM rihno_metrics
				WHERE email = $1
				  AND agent_name = $2
				  AND time > NOW() - INTERVAL '%s'
				GROUP BY the_date
				ORDER BY the_date ASC;
			`, rc.trunc, cfg.col, col2Select, rc.interval)
			queryArgs = []interface{}{email, deviceName}
		}

		rows, err := dbpool.Query(context.Background(), query, queryArgs...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "getMetricsHistory query error: %v\n", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var tempResults []struct {
			date time.Time
			val  float64
			val2 float64
		}
		var maxVal float64 = 1.0

		for rows.Next() {
			var date time.Time
			var avgVal float64
			var avgVal2 float64
			if err := rows.Scan(&date, &avgVal, &avgVal2); err != nil {
				continue
			}
			tempResults = append(tempResults, struct {
				date time.Time
				val  float64
				val2 float64
			}{date, avgVal, avgVal2})
			if avgVal > maxVal {
				maxVal = avgVal
			}
			if avgVal2 > maxVal {
				maxVal = avgVal2
			}
		}

		var history []HistoryPoint
		for _, row := range tempResults {
			count := int(row.val + row.val2)
			var level int

			var normalized float64
			if cfg.maxPct > 0 {
				normalized = (row.val / cfg.maxPct) * 100
			} else {
				normalized = (row.val / maxVal) * 100
			}

			switch {
			case normalized > 90:
				level = 5
			case normalized > 75:
				level = 4
			case normalized > 50:
				level = 3
			case normalized > 25:
				level = 2
			case normalized > 0:
				level = 1
			default:
				level = 0
			}

			history = append(history, HistoryPoint{
				Date:  row.date.Format(rc.dateFormat),
				Count: count,
				Level: level,
				Raw:   row.val,
				Raw2:  row.val2,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(history); err != nil {
			fmt.Fprintf(os.Stderr, "JSON encoding error: %v\n", err)
		}
	}
}

type AgentStatus struct {
	AgentName string    `json:"agent_name"`
	IsActive  bool      `json:"is_active"`
	LastSeen  time.Time `json:"last_seen"`
}

func getAgentsStatus(dbpool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")
		if email == "" {
			http.Error(w, "email parameter is required", http.StatusBadRequest)
			return
		}

		query := `
			SELECT agent_name, is_active, last_seen
			FROM rihno_agents
			WHERE email = $1
		`

		rows, err := dbpool.Query(context.Background(), query, email)
		if err != nil {
			http.Error(w, fmt.Sprintf("database query failed: %v", err), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var statuses []AgentStatus
		for rows.Next() {
			var s AgentStatus
			if err := rows.Scan(&s.AgentName, &s.IsActive, &s.LastSeen); err == nil {
				if time.Since(s.LastSeen) > 2*time.Minute {
					s.IsActive = false
				}
				statuses = append(statuses, s)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(statuses)
	}
}

type AlertRecord struct {
	Time        time.Time `json:"time"`
	AgentID     string    `json:"agent_id"`
	AgentName   string    `json:"agent_name"`
	AlertType   string    `json:"alert_type"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	MetricName  string    `json:"metric_name"`
	MetricValue float64   `json:"metric_value"`
	Threshold   float64   `json:"threshold"`
}

func getRecentAlerts(dbpool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")
		if email == "" {
			http.Error(w, "email parameter is required", http.StatusBadRequest)
			return
		}

		limitStr := r.URL.Query().Get("limit")
		limit := 100
		if limitStr != "" {
			if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
				limit = l
			}
		}

		query := `
			SELECT time, agent_id, agent_name, alert_type, severity, description, metric_name, metric_value, threshold
			FROM rihno_alerts
			WHERE email = $1
			ORDER BY time DESC
			LIMIT $2
		`

		rows, err := dbpool.Query(context.Background(), query, email, limit)
		if err != nil {
			http.Error(w, fmt.Sprintf("database query failed: %v", err), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var alerts []AlertRecord
		for rows.Next() {
			var a AlertRecord
			err := rows.Scan(
				&a.Time, &a.AgentID, &a.AgentName, &a.AlertType, &a.Severity,
				&a.Description, &a.MetricName, &a.MetricValue, &a.Threshold,
			)
			if err != nil {
				log.Printf("Error scanning back alert row: %v", err)
				continue
			}
			alerts = append(alerts, a)
		}

		if err := rows.Err(); err != nil {
			http.Error(w, fmt.Sprintf("row iteration failed: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(alerts)
	}
}

func getNetworkMap(dbpool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")
		deviceName := r.URL.Query().Get("device_name")

		if email == "" || deviceName == "" {
			http.Error(w, "Missing email or device_name parameter", http.StatusBadRequest)
			return
		}

		query := `
			SELECT network_map_json
			FROM rihno_network_maps
			WHERE email = $1 AND agent_name = $2
			ORDER BY time DESC
			LIMIT 1;
		`

		var networkMapJSON []byte
		err := dbpool.QueryRow(context.Background(), query, email, deviceName).Scan(&networkMapJSON)

		if err != nil {
			if err == pgx.ErrNoRows {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte("null"))
				return
			}
			fmt.Fprintf(os.Stderr, "getNetworkMap query error: %v\n", err)
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(networkMapJSON)
	}
}
