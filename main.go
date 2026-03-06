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
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var activeAgents int32

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
	fmt.Println("Starting RIHNO Dealer on 127.0.0.1:8080")

	connStr := "postgres://postgres:5001@192.168.1.10:5432/rihnodb"

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

	// 3. Start the server
	go func() {
		fmt.Println("HTTP API Server starting on port 8000...")
		if err := http.ListenAndServe(":8000", nil); err != nil {
			log.Fatalf("HTTP Server failed to start: %v", err)
		}
	}()

	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalf("Error listening on port 8080: %v", err)
	}
	defer ln.Close()

	log.Println("Dealer ready. Waiting for agents...")

	for {
		conn, err := ln.Accept()
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

	defer func() {
		conn.Close()
		atomic.AddInt32(&activeAgents, -1)
		log.Printf("[%s] Agent disconnected. Active: %d", clientAddr, atomic.LoadInt32(&activeAgents))
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

		// Insert network map
		if err := insertNetworkMap(dbpool, clientAddr, &payload); err != nil {
			log.Printf("[%s] DB network map insert error: %v", clientAddr, err)
		}

		// Insert individual connections
		if err := insertConnections(dbpool, clientAddr, &payload); err != nil {
			log.Printf("[%s] DB connections insert error: %v", clientAddr, err)
		}

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
	if len(p.NetworkMap.Connections) == 0 {
		return nil
	}

	// Use batch insert for performance
	ctx := context.Background()
	now := time.Now()

	// Build batch query
	query := `INSERT INTO rihno_connections
		(time, agent_id, agent_name, remote_ip, remote_port, local_ip, local_port,
		 protocol, state, pid, process_name, direction, is_private, is_loopback, is_suspicious)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`

	batch := &pgxBatch{}
	for _, c := range p.NetworkMap.Connections {
		batch.Queue(query,
			now, agentID, p.AgentName,
			c.RemoteIP, c.RemotePort, c.LocalIP, c.LocalPort,
			c.Protocol, c.State, c.PID, c.ProcessName,
			c.Direction, c.IsPrivate, c.IsLoopback, c.IsSuspicious)
	}

	// Execute individually if batch not available (simplified approach)
	for _, c := range p.NetworkMap.Connections {
		_, err := dbpool.Exec(ctx, query,
			now, agentID, p.AgentName,
			c.RemoteIP, c.RemotePort, c.LocalIP, c.LocalPort,
			c.Protocol, c.State, c.PID, c.ProcessName,
			c.Direction, c.IsPrivate, c.IsLoopback, c.IsSuspicious)
		if err != nil {
			return fmt.Errorf("error inserting connection: %w", err)
		}
	}

	return nil
}

// pgxBatch is a placeholder - remove this and use pgx batch properly
type pgxBatch struct{}

func (b *pgxBatch) Queue(query string, args ...interface{}) {}

func upsertAgent(dbpool *pgxpool.Pool, agentID string, p *MetricsPayload) error {
	query := `
	INSERT INTO rihno_agents (agent_id, agent_name, agent_type, email, first_seen, last_seen, is_active, ip_address)
	VALUES ($1, $2, $3, $4, NOW(), NOW(), TRUE, $5)
	ON CONFLICT (agent_id) DO UPDATE SET
		last_seen = NOW(),
		is_active = TRUE,
		agent_name = EXCLUDED.agent_name,
		agent_type = EXCLUDED.agent_type`

	_, err := dbpool.Exec(context.Background(), query,
		agentID, p.AgentName, p.AgentType, p.Email, agentID)
	return err
}

// ========== ALERT DETECTION ==========

func checkAndInsertAlerts(dbpool *pgxpool.Pool, agentID string, p *MetricsPayload) {
	m := p.Metrics
	ctx := context.Background()

	alertQuery := `INSERT INTO rihno_alerts
		(time, agent_id, agent_name, email, alert_type, severity, description, metric_name, metric_value, threshold)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	now := time.Now()

	// High CPU
	if m.SystemCPU > 95 {
		dbpool.Exec(ctx, alertQuery,
			now, agentID, p.AgentName, p.Email,
			"HIGH_CPU", "high",
			fmt.Sprintf("CPU usage at %.1f%% exceeds 95%% threshold", m.SystemCPU),
			"system_cpu", m.SystemCPU, 95.0)
	}

	// High Memory
	if m.SystemMemoryPercent > 95 {
		dbpool.Exec(ctx, alertQuery,
			now, agentID, p.AgentName, p.Email,
			"HIGH_MEMORY", "high",
			fmt.Sprintf("Memory usage at %.1f%% exceeds 95%% threshold", m.SystemMemoryPercent),
			"system_memory_percent", m.SystemMemoryPercent, 95.0)
	}

	// Suspicious ports detected
	if m.SuspiciousPortConns > 0 {
		dbpool.Exec(ctx, alertQuery,
			now, agentID, p.AgentName, p.Email,
			"SUSPICIOUS_PORTS", "critical",
			fmt.Sprintf("%d connections on suspicious ports detected", m.SuspiciousPortConns),
			"suspicious_port_connections", float64(m.SuspiciousPortConns), 0.0)
	}

	// Suspicious processes
	if m.SuspiciousProcessNames > 0 {
		dbpool.Exec(ctx, alertQuery,
			now, agentID, p.AgentName, p.Email,
			"SUSPICIOUS_PROCESSES", "critical",
			fmt.Sprintf("%d suspicious process names detected", m.SuspiciousProcessNames),
			"suspicious_process_names", float64(m.SuspiciousProcessNames), 0.0)
	}

	// Port scanning detected
	if m.PortScanningScore > 50 {
		dbpool.Exec(ctx, alertQuery,
			now, agentID, p.AgentName, p.Email,
			"PORT_SCAN", "high",
			fmt.Sprintf("Port scanning detected with score %.1f", m.PortScanningScore),
			"port_scanning_score", m.PortScanningScore, 50.0)
	}

	// Data exfiltration
	if m.DataExfiltrationScore > 50 {
		dbpool.Exec(ctx, alertQuery,
			now, agentID, p.AgentName, p.Email,
			"DATA_EXFILTRATION", "critical",
			fmt.Sprintf("Potential data exfiltration detected with score %.1f", m.DataExfiltrationScore),
			"data_exfiltration_score", m.DataExfiltrationScore, 50.0)
	}

	// C2 communication
	if m.C2CommunicationScore > 70 {
		dbpool.Exec(ctx, alertQuery,
			now, agentID, p.AgentName, p.Email,
			"C2_COMMUNICATION", "critical",
			fmt.Sprintf("Potential C2 communication detected with score %.1f", m.C2CommunicationScore),
			"c2_communication_score", m.C2CommunicationScore, 70.0)
	}

	// High connection churn
	if m.ConnectionChurnRate > 0.8 {
		dbpool.Exec(ctx, alertQuery,
			now, agentID, p.AgentName, p.Email,
			"HIGH_CONN_CHURN", "medium",
			fmt.Sprintf("High connection churn rate: %.3f", m.ConnectionChurnRate),
			"connection_churn_rate", m.ConnectionChurnRate, 0.8)
	}

	// Many SYN_SENT (potential DDoS or scan)
	if m.SynSentConnections > 100 {
		dbpool.Exec(ctx, alertQuery,
			now, agentID, p.AgentName, p.Email,
			"SYN_FLOOD", "high",
			fmt.Sprintf("%d SYN_SENT connections detected", m.SynSentConnections),
			"syn_sent_connections", float64(m.SynSentConnections), 100.0)
	}

	// High failed connection ratio
	if m.FailedConnectionRatio > 0.5 && m.TotalConnections > 50 {
		dbpool.Exec(ctx, alertQuery,
			now, agentID, p.AgentName, p.Email,
			"HIGH_FAILED_CONNECTIONS", "medium",
			fmt.Sprintf("Failed connection ratio: %.3f (%d total connections)",
				m.FailedConnectionRatio, m.TotalConnections),
			"failed_connection_ratio", m.FailedConnectionRatio, 0.5)
	}
}

type CPUResponse struct {
	SystemCPU float64 `json:"system_cpu"`
}

func getSystemCPU(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// 1. Extract query parameters from the URL
		email := r.URL.Query().Get("email")
		deviceName := r.URL.Query().Get("device_name")

		// 2. Validate that the required parameters were provided
		if email == "" || deviceName == "" {
			http.Error(w, "Missing required query parameters: 'email' and 'device_name'", http.StatusBadRequest)
			return
		}

		// 3. Use $1 and $2 as placeholders to safely inject the variables
		query := `
			SELECT system_cpu 
			FROM rihno_metrics 
			WHERE email = $1 AND agent_name = $2
			ORDER BY time DESC LIMIT 1;
		`
		var systemCPU float64

		// 4. Pass the extracted variables into QueryRow
		err := db.QueryRow(context.Background(), query, email, deviceName).Scan(&systemCPU)
		if err != nil {
			if err == pgx.ErrNoRows {
				http.Error(w, "No data found for this device", http.StatusNotFound)
				return
			}
			fmt.Fprintf(os.Stderr, "Unable to select data: %v\n", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		response := CPUResponse{SystemCPU: systemCPU}
		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "Error encoding response", http.StatusInternalServerError)
			return
		}
	}
}

type LatestFullMetricsResponse struct {
	// System & CPU
	SystemCPU           float64 `json:"system_cpu"`
	AvgCoreCPU          float64 `json:"avg_core_cpu"`
	SystemMemoryPercent float64 `json:"system_memory_percent"`
	SystemMemoryUsed    float64 `json:"system_memory_used"`
	SystemMemoryAvail   float64 `json:"system_memory_available"`
	SystemMemoryTotal   float64 `json:"system_memory_total"`
	SwapUsedPercent     float64 `json:"swap_used_percent"`
	SwapTotal           float64 `json:"swap_total"`
	SwapUsed            float64 `json:"swap_used"`
	LoggedInUsers       float64 `json:"logged_in_users"`
	SystemUptime        float64 `json:"system_uptime"`
	SystemBootTime      float64 `json:"system_boot_time"`
	CPUSpike            float64 `json:"cpu_usage_spike"`
	MemSpike            float64 `json:"memory_usage_spike"`

	// Disk
	DiskReadBytes  float64 `json:"disk_read_bytes"`
	DiskWriteBytes float64 `json:"disk_write_bytes"`
	DiskReadRate   float64 `json:"disk_read_rate"`
	DiskWriteRate  float64 `json:"disk_write_rate"`
	DiskReadCount  float64 `json:"disk_read_count"`
	DiskWriteCount float64 `json:"disk_write_count"`
	DiskIoRate     float64 `json:"disk_io_rate"`

	// Network
	NetBytesSent      float64 `json:"net_bytes_sent"`
	NetBytesRecv      float64 `json:"net_bytes_recv"`
	NetPacketsSent    float64 `json:"net_packets_sent"`
	NetPacketsRecv    float64 `json:"net_packets_recv"`
	NetErrorsIn       float64 `json:"net_errors_in"`
	NetErrorsOut      float64 `json:"net_errors_out"`
	NetDropsIn        float64 `json:"net_drops_in"`
	NetDropsOut       float64 `json:"net_drops_out"`
	NetSendRate       float64 `json:"net_send_rate"`
	NetRecvRate       float64 `json:"net_recv_rate"`
	NetPacketSendRate float64 `json:"net_packet_send_rate"`
	NetPacketRecvRate float64 `json:"net_packet_recv_rate"`

	// Connections
	TotalConnections       float64 `json:"total_connections"`
	TCPConnections         float64 `json:"tcp_connections"`
	UDPConnections         float64 `json:"udp_connections"`
	EstablishedConnections float64 `json:"established_connections"`
	ListenConnections      float64 `json:"listen_connections"`
	TimeWaitConnections    float64 `json:"time_wait_connections"`
	SynSentConnections     float64 `json:"syn_sent_connections"`
	SynRecvConnections     float64 `json:"syn_recv_connections"`
	CloseWaitConnections   float64 `json:"close_wait_connections"`
	FinWaitConnections     float64 `json:"fin_wait_connections"`
	ConnectionChurnRate    float64 `json:"connection_churn_rate"`
	FailedConnectionRatio  float64 `json:"failed_connection_ratio"`

	// IP Intelligence
	UniqueSourceIPs      float64 `json:"unique_source_ips"`
	UniqueDestIPs        float64 `json:"unique_dest_ips"`
	NewSourceIPs         float64 `json:"new_source_ips"`
	PrivateIPConnections float64 `json:"private_ip_connections"`
	PublicIPConnections  float64 `json:"public_ip_connections"`
	ExternalIPCount      float64 `json:"external_ip_count"`

	// Ports & Protocol
	UniqueLocalPorts    float64 `json:"unique_local_ports"`
	UniqueRemotePorts   float64 `json:"unique_remote_ports"`
	WellKnownPortConns  float64 `json:"well_known_port_connections"`
	EphemeralPortConns  float64 `json:"ephemeral_port_connections"`
	SuspiciousPortConns float64 `json:"suspicious_port_connections"`
	PortScanIndicators  float64 `json:"port_scan_indicators"`
	TCPRatio            float64 `json:"tcp_ratio"`
	UDPRatio            float64 `json:"udp_ratio"`
	TCPUDPRatio         float64 `json:"tcp_udp_ratio"`

	// Processes
	ProcessCount           float64 `json:"process_count"`
	ProcessCreationRate    float64 `json:"process_creation_rate"`
	ProcessTermRate        float64 `json:"process_termination_rate"`
	HighCPUProcessCount    float64 `json:"high_cpu_process_count"`
	HighMemProcessCount    float64 `json:"high_mem_process_count"`
	AvgProcessCPU          float64 `json:"avg_process_cpu"`
	AvgProcessMemory       float64 `json:"avg_process_memory"`
	AvgProcessRSS          float64 `json:"avg_process_rss"`
	AvgProcessVMS          float64 `json:"avg_process_vms"`
	TotalThreads           float64 `json:"total_threads"`
	ZombieProcessCount     float64 `json:"zombie_process_count"`
	RootProcessCount       float64 `json:"root_process_count"`
	AvgProcessAge          float64 `json:"avg_process_age_seconds"`
	ProcessWithManyThreads float64 `json:"process_with_many_threads"`
	SuspiciousProcessNames float64 `json:"suspicious_process_names"`
	TotalFileDescriptors   float64 `json:"total_file_descriptors"`

	// Process Network
	ProcessesWithNetActivity float64 `json:"processes_with_net_activity"`
	AvgConnectionsPerProcess float64 `json:"avg_connections_per_process"`

	// Traffic Rates
	ConnectionCreationRate    float64 `json:"connection_creation_rate"`
	ConnectionTerminationRate float64 `json:"connection_termination_rate"`

	// Geographic/External
	LoopbackConnections  float64 `json:"loopback_connections"`
	BroadcastConnections float64 `json:"broadcast_connections"`

	// Security
	PortScanningScore     float64 `json:"port_scanning_score"`
	DataExfiltrationScore float64 `json:"data_exfiltration_score"`
	C2CommScore           float64 `json:"c2_communication_score"`
	BandwidthAsymmetry    float64 `json:"bandwidth_asymmetry"`
	ConnectionDensity     float64 `json:"connection_density"`

	// Network Map Summary
	TotalIncomingConnections float64 `json:"total_incoming_connections"`
	TotalOutgoingConnections float64 `json:"total_outgoing_connections"`
	UniqueIncomingIPs        float64 `json:"unique_incoming_ips"`
	UniqueOutgoingIPs        float64 `json:"unique_outgoing_ips"`
	LocalIPsCount            float64 `json:"local_ips_count"`
}

func getLatestFullMetrics(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		email := r.URL.Query().Get("email")
		deviceName := r.URL.Query().Get("device_name")

		if email == "" || deviceName == "" {
			http.Error(w, "Missing required query parameters", http.StatusBadRequest)
			return
		}

		query := `
			SELECT
			    COALESCE(system_cpu, 0)::float8, COALESCE(avg_core_cpu, 0)::float8,
			    COALESCE(system_memory_percent, 0)::float8, COALESCE(system_memory_used, 0)::float8,
			    COALESCE(system_memory_available, 0)::float8, COALESCE(system_memory_total, 0)::float8,
			    COALESCE(swap_used_percent, 0)::float8, COALESCE(swap_total, 0)::float8, COALESCE(swap_used, 0)::float8,
			    COALESCE(logged_in_users, 0)::float8, COALESCE(system_uptime, 0)::float8, COALESCE(system_boot_time, 0)::float8,
			    COALESCE(cpu_usage_spike, 0)::float8, COALESCE(memory_usage_spike, 0)::float8,
			    COALESCE(disk_read_bytes, 0)::float8, COALESCE(disk_write_bytes, 0)::float8,
			    COALESCE(disk_read_rate, 0)::float8, COALESCE(disk_write_rate, 0)::float8,
			    COALESCE(disk_read_count, 0)::float8, COALESCE(disk_write_count, 0)::float8,
			    COALESCE(disk_io_rate, 0)::float8,
			    COALESCE(net_bytes_sent, 0)::float8, COALESCE(net_bytes_recv, 0)::float8,
			    COALESCE(net_packets_sent, 0)::float8, COALESCE(net_packets_recv, 0)::float8,
			    COALESCE(net_errors_in, 0)::float8, COALESCE(net_errors_out, 0)::float8,
			    COALESCE(net_drops_in, 0)::float8, COALESCE(net_drops_out, 0)::float8,
			    COALESCE(net_send_rate, 0)::float8, COALESCE(net_recv_rate, 0)::float8,
			    COALESCE(net_packet_send_rate, 0)::float8, COALESCE(net_packet_recv_rate, 0)::float8,
			    COALESCE(total_connections, 0)::float8, COALESCE(tcp_connections, 0)::float8,
			    COALESCE(udp_connections, 0)::float8, COALESCE(established_connections, 0)::float8,
			    COALESCE(listen_connections, 0)::float8, COALESCE(time_wait_connections, 0)::float8,
			    COALESCE(syn_sent_connections, 0)::float8, COALESCE(syn_recv_connections, 0)::float8,
			    COALESCE(close_wait_connections, 0)::float8, COALESCE(fin_wait_connections, 0)::float8,
			    COALESCE(connection_churn_rate, 0)::float8, COALESCE(failed_connection_ratio, 0)::float8,
			    COALESCE(unique_source_ips, 0)::float8, COALESCE(unique_dest_ips, 0)::float8,
			    COALESCE(new_source_ips, 0)::float8, COALESCE(private_ip_connections, 0)::float8,
			    COALESCE(public_ip_connections, 0)::float8, COALESCE(external_ip_count, 0)::float8,
			    COALESCE(unique_local_ports, 0)::float8, COALESCE(unique_remote_ports, 0)::float8,
			    COALESCE(well_known_port_connections, 0)::float8, COALESCE(ephemeral_port_connections, 0)::float8,
			    COALESCE(suspicious_port_connections, 0)::float8, COALESCE(port_scan_indicators, 0)::float8,
			    COALESCE(process_count, 0)::float8, COALESCE(high_cpu_process_count, 0)::float8,
			    COALESCE(high_mem_process_count, 0)::float8, COALESCE(total_threads, 0)::float8,
			    COALESCE(zombie_process_count, 0)::float8, COALESCE(root_process_count, 0)::float8,
			    COALESCE(suspicious_process_names, 0)::float8, COALESCE(total_file_descriptors, 0)::float8,
			    COALESCE(processes_with_net_activity, 0)::float8, COALESCE(avg_connections_per_process, 0)::float8,
			    COALESCE(port_scanning_score, 0)::float8, COALESCE(data_exfiltration_score, 0)::float8,
			    COALESCE(c2_communication_score, 0)::float8, COALESCE(bandwidth_asymmetry, 0)::float8
			FROM rihno_metrics
			WHERE email = $1 AND agent_name = $2
			ORDER BY time DESC LIMIT 1;
		`
		var m LatestFullMetricsResponse

		err := db.QueryRow(context.Background(), query, email, deviceName).Scan(
			&m.SystemCPU, &m.AvgCoreCPU,
			&m.SystemMemoryPercent, &m.SystemMemoryUsed,
			&m.SystemMemoryAvail, &m.SystemMemoryTotal,
			&m.SwapUsedPercent, &m.SwapTotal, &m.SwapUsed,
			&m.LoggedInUsers, &m.SystemUptime, &m.SystemBootTime,
			&m.CPUSpike, &m.MemSpike,
			&m.DiskReadBytes, &m.DiskWriteBytes,
			&m.DiskReadRate, &m.DiskWriteRate,
			&m.DiskReadCount, &m.DiskWriteCount,
			&m.DiskIoRate,
			&m.NetBytesSent, &m.NetBytesRecv,
			&m.NetPacketsSent, &m.NetPacketsRecv,
			&m.NetErrorsIn, &m.NetErrorsOut,
			&m.NetDropsIn, &m.NetDropsOut,
			&m.NetSendRate, &m.NetRecvRate,
			&m.NetPacketSendRate, &m.NetPacketRecvRate,
			&m.TotalConnections, &m.TCPConnections,
			&m.UDPConnections, &m.EstablishedConnections,
			&m.ListenConnections, &m.TimeWaitConnections,
			&m.SynSentConnections, &m.SynRecvConnections,
			&m.CloseWaitConnections, &m.FinWaitConnections,
			&m.ConnectionChurnRate, &m.FailedConnectionRatio,
			&m.UniqueSourceIPs, &m.UniqueDestIPs,
			&m.NewSourceIPs, &m.PrivateIPConnections,
			&m.PublicIPConnections, &m.ExternalIPCount,
			&m.UniqueLocalPorts, &m.UniqueRemotePorts,
			&m.WellKnownPortConns, &m.EphemeralPortConns,
			&m.SuspiciousPortConns, &m.PortScanIndicators,
			&m.ProcessCount, &m.HighCPUProcessCount,
			&m.HighMemProcessCount, &m.TotalThreads,
			&m.ZombieProcessCount, &m.RootProcessCount,
			&m.SuspiciousProcessNames, &m.TotalFileDescriptors,
			&m.ProcessesWithNetActivity, &m.AvgConnectionsPerProcess,
			&m.PortScanningScore, &m.DataExfiltrationScore,
			&m.C2CommScore, &m.BandwidthAsymmetry,
		)
		if err != nil {
			if err == pgx.ErrNoRows {
				http.Error(w, "No data found for this device", http.StatusNotFound)
				return
			}
			fmt.Fprintf(os.Stderr, "getLatestFullMetrics error: %v\n", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(m)
	}
}

type HistoryPoint struct {
	Date  string  `json:"date"`
	Count int     `json:"count"`
	Level int     `json:"level"`
	Raw   float64 `json:"raw"`
	Raw2  float64 `json:"raw2"`
}

func getMetricsHistory(db *pgxpool.Pool) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		email := r.URL.Query().Get("email")
		deviceName := r.URL.Query().Get("device_name")
		metricType := r.URL.Query().Get("metric")
		if metricType == "" {
			metricType = "cpu"
		}
		timeRange := r.URL.Query().Get("time_range")
		if timeRange == "" {
			timeRange = "1y"
		}
		// Custom date range support
		dateFrom := r.URL.Query().Get("date_from") // ISO-8601
		dateTo := r.URL.Query().Get("date_to")     // ISO-8601

		if email == "" || deviceName == "" {
			http.Error(w, "Missing required query parameters", http.StatusBadRequest)
			return
		}

		// Metric → DB column mapping
		type metricCfg struct {
			col    string
			col2   string
			maxPct float64 // 0 = use dynamic peak normalisation
		}
		metricMap := map[string]metricCfg{
			// CPU
			"cpu":       {col: "system_cpu", maxPct: 100},
			"core_avg":  {col: "avg_core_cpu", maxPct: 100},
			"cpu_spike": {col: "cpu_usage_spike", maxPct: 0},

			// Memory
			"memory":    {col: "system_memory_percent", maxPct: 100},
			"mem_used":  {col: "system_memory_used", maxPct: 0},
			"swap":      {col: "swap_used_percent", maxPct: 100},
			"mem_spike": {col: "memory_usage_spike", maxPct: 0},

			// System
			"logged_in_users": {col: "logged_in_users", maxPct: 0},

			// ==== DUAL CHARTS ====
			"disk_rw":     {col: "disk_read_rate", col2: "disk_write_rate", maxPct: 0},
			"disk_rw_cnt": {col: "disk_read_count", col2: "disk_write_count", maxPct: 0},
			"network":     {col: "net_send_rate", col2: "net_recv_rate", maxPct: 0},
			"net_pkts":    {col: "net_packet_send_rate", col2: "net_packet_recv_rate", maxPct: 0},
			"net_drops":   {col: "net_drops_in", col2: "net_drops_out", maxPct: 0},
			"net_errors":  {col: "net_errors_in", col2: "net_errors_out", maxPct: 0},
			"conn_states": {col: "established_connections", col2: "time_wait_connections + close_wait_connections", maxPct: 0},
			"conn_proto":  {col: "tcp_connections", col2: "udp_connections", maxPct: 0},
			"unique_ips":  {col: "unique_source_ips", col2: "unique_dest_ips", maxPct: 0},
			"ip_scope":    {col: "private_ip_connections", col2: "public_ip_connections", maxPct: 0},
			"port_types":  {col: "well_known_port_connections", col2: "ephemeral_port_connections", maxPct: 0},
			"port_bal":    {col: "unique_local_ports", col2: "unique_remote_ports", maxPct: 0},
			"proc_health": {col: "process_count - zombie_process_count", col2: "zombie_process_count", maxPct: 0},
			"proc_hogs":   {col: "high_cpu_process_count", col2: "high_mem_process_count", maxPct: 0},
			"proc_net":    {col: "processes_with_net_activity", col2: "process_count - processes_with_net_activity", maxPct: 0},

			// ==== SINGLE FALLBACKS & OTHERS ====
			"disk":       {col: "disk_io_rate", maxPct: 0},
			"disk_read":  {col: "disk_read_rate", maxPct: 0},
			"disk_write": {col: "disk_write_rate", maxPct: 0},
			"disk_r_cnt": {col: "disk_read_count", maxPct: 0},
			"disk_w_cnt": {col: "disk_write_count", maxPct: 0},

			"net_tx_rate":    {col: "net_send_rate", maxPct: 0},
			"net_rx_rate":    {col: "net_recv_rate", maxPct: 0},
			"net_pkt_tx":     {col: "net_packet_send_rate", maxPct: 0},
			"net_pkt_rx":     {col: "net_packet_recv_rate", maxPct: 0},
			"net_bytes_tx":   {col: "net_bytes_sent", maxPct: 0},
			"net_bytes_rx":   {col: "net_bytes_recv", maxPct: 0},
			"net_drops_in":   {col: "net_drops_in", maxPct: 0},
			"net_drops_out":  {col: "net_drops_out", maxPct: 0},
			"net_errors_in":  {col: "net_errors_in", maxPct: 0},
			"net_errors_out": {col: "net_errors_out", maxPct: 0},

			"connections":      {col: "total_connections", maxPct: 0},
			"tcp_conn":         {col: "tcp_connections", maxPct: 0},
			"udp_conn":         {col: "udp_connections", maxPct: 0},
			"established_conn": {col: "established_connections", maxPct: 0},
			"listen_conn":      {col: "listen_connections", maxPct: 0},
			"time_wait_conn":   {col: "time_wait_connections", maxPct: 0},
			"syn_sent_conn":    {col: "syn_sent_connections", maxPct: 0},
			"syn_recv_conn":    {col: "syn_recv_connections", maxPct: 0},

			"conn_create_rate": {col: "connection_creation_rate", maxPct: 0},
			"conn_term_rate":   {col: "connection_termination_rate", maxPct: 0},
			"conn_churn_rate":  {col: "connection_churn_rate", maxPct: 0},
			"conn_fail_ratio":  {col: "failed_connection_ratio", maxPct: 1},

			"unique_src_ips":  {col: "unique_source_ips", maxPct: 0},
			"unique_dst_ips":  {col: "unique_dest_ips", maxPct: 0},
			"new_src_ips":     {col: "new_source_ips", maxPct: 0},
			"private_ip_conn": {col: "private_ip_connections", maxPct: 0},
			"public_ip_conn":  {col: "public_ip_connections", maxPct: 0},
			"external_ip_cnt": {col: "external_ip_count", maxPct: 0},
			"top_src_ip_cnt":  {col: "top_source_ip_count", maxPct: 0},

			"unique_local_ports":  {col: "unique_local_ports", maxPct: 0},
			"unique_remote_ports": {col: "unique_remote_ports", maxPct: 0},
			"well_known_ports":    {col: "well_known_port_connections", maxPct: 0},
			"ephemeral_ports":     {col: "ephemeral_port_connections", maxPct: 0},
			"suspicious_ports":    {col: "suspicious_port_connections", maxPct: 0},

			"tcp_ratio": {col: "tcp_ratio", maxPct: 1},
			"udp_ratio": {col: "udp_ratio", maxPct: 1},

			"process":          {col: "process_count", maxPct: 0},
			"proc_create_rate": {col: "process_creation_rate", maxPct: 0},
			"high_cpu_proc":    {col: "high_cpu_process_count", maxPct: 0},
			"high_mem_proc":    {col: "high_mem_process_count", maxPct: 0},
			"avg_proc_cpu":     {col: "avg_process_cpu", maxPct: 100},
			"avg_proc_mem":     {col: "avg_process_memory", maxPct: 100},
			"threads":          {col: "total_threads", maxPct: 0},
			"zombie":           {col: "zombie_process_count", maxPct: 0},
			"root_proc":        {col: "root_process_count", maxPct: 0},
			"suspicious_procs": {col: "suspicious_process_names", maxPct: 0},
			"file_descriptors": {col: "total_file_descriptors", maxPct: 0},

			"proc_with_net":     {col: "processes_with_net_activity", maxPct: 0},
			"avg_conn_per_proc": {col: "avg_connections_per_process", maxPct: 0},

			"security":       {col: "port_scanning_score + data_exfiltration_score + c2_communication_score", maxPct: 3},
			"port_scan":      {col: "port_scanning_score", maxPct: 1},
			"data_exfil":     {col: "data_exfiltration_score", maxPct: 1},
			"c2":             {col: "c2_communication_score", maxPct: 1},
			"port_scan_ind":  {col: "port_scan_indicators", maxPct: 0},
			"bandwidth_asym": {col: "bandwidth_asymmetry", maxPct: 1},
		}

		cfg, ok := metricMap[metricType]
		if !ok {
			cfg = metricMap["cpu"]
		}

		// Time range → SQL interval + truncation granularity
		type rangeCfg struct {
			interval   string
			trunc      string
			dateFormat string
		}
		rangeMap := map[string]rangeCfg{
			"10m": {"10 minutes", "minute", "2006-01-02 15:04"},
			"1h":  {"1 hour", "minute", "2006-01-02 15:04"},
			"1d":  {"1 day", "hour", "2006-01-02 15:00"},
			"7d":  {"7 days", "hour", "2006-01-02 15:00"},
			"30d": {"30 days", "day", "2006-01-02"},
			"1y":  {"365 days", "day", "2006-01-02"},
		}
		rc, ok := rangeMap[timeRange]
		if !ok {
			rc = rangeMap["1y"]
		}

		var query string
		var queryArgs []interface{}
		var col2Select string
		if cfg.col2 != "" {
			col2Select = fmt.Sprintf(", AVG(%s)::float8 AS avg_val2", cfg.col2)
		} else {
			col2Select = ", 0::float8 AS avg_val2"
		}

		if dateFrom != "" && dateTo != "" {
			// Custom date range
			// Determine granularity dynamically from span
			from, errF := time.Parse("2006-01-02", dateFrom)
			to, errT := time.Parse("2006-01-02", dateTo)
			if errF != nil || errT != nil {
				http.Error(w, "Invalid date format (use YYYY-MM-DD)", http.StatusBadRequest)
				return
			}
			span := to.Sub(from).Hours()
			var trunc, dateFormat string
			if span <= 24 {
				trunc = "minute"
				dateFormat = "2006-01-02 15:04"
			} else if span <= 7*24 {
				trunc = "hour"
				dateFormat = "2006-01-02 15:00"
			} else {
				trunc = "day"
				dateFormat = "2006-01-02"
			}
			rc.trunc = trunc
			rc.dateFormat = dateFormat

			query = fmt.Sprintf(`
				SELECT date_trunc('%s', time) AS the_date,
				       AVG(%s)::float8 AS avg_val
				       %s
				FROM rihno_metrics
				WHERE email = $1 AND agent_name = $2
				  AND time >= $3 AND time < $4 + INTERVAL '1 day'
				GROUP BY the_date
				ORDER BY the_date ASC;
			`, rc.trunc, cfg.col, col2Select)
			queryArgs = []interface{}{email, deviceName, from, to}
		} else {
			query = fmt.Sprintf(`
				SELECT date_trunc('%s', time) AS the_date,
				       AVG(%s)::float8 AS avg_val
				       %s
				FROM rihno_metrics
				WHERE email = $1 AND agent_name = $2
				  AND time > NOW() - INTERVAL '%s'
				GROUP BY the_date
				ORDER BY the_date ASC;
			`, rc.trunc, cfg.col, col2Select, rc.interval)
			queryArgs = []interface{}{email, deviceName}
		}

		rows, err := db.Query(context.Background(), query, queryArgs...)
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
			case normalized > 89:
				level = 4
			case normalized > 70:
				level = 3
			case normalized > 40:
				level = 2
			case normalized > 20:
				level = 1
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
		json.NewEncoder(w).Encode(history)
	}
}
