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
	"net/url"
	"os"
	"sync/atomic"
	"time"

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
