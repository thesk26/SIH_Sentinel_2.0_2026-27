#ifndef SENTINEL_TELEMETRY_TYPES_HPP
#define SENTINEL_TELEMETRY_TYPES_HPP

#include <string>
#include <vector>
#include <cstdint>

namespace sentinel {

struct NetworkConnection {
    std::string protocol;       // "tcp", "udp", "tcp6", "udp6"
    std::string local_address;
    uint16_t local_port;
    std::string remote_address;
    uint16_t remote_port;
    std::string state;          // "ESTABLISHED", "LISTEN", "SYN_SENT", "TIME_WAIT", etc.
    uint32_t process_id;
    std::string process_name;
    uint64_t bytes_sent{0};
    uint64_t bytes_recv{0};
};

struct ProcessInfo {
    uint32_t pid;
    uint32_t ppid;
    std::string name;
    std::string exe_path;
    std::string cmdline;
    double cpu_percent;
    double memory_percent;
    uint64_t memory_rss_bytes;
    uint64_t start_time;
    std::string user;
    uint32_t thread_count{0};
};

struct SecurityEvent {
    std::string event_id;
    std::string event_type;     // "AUTH_SUCCESS", "AUTH_FAILURE", "PRIV_ESCALATION", "FILE_INTEGRITY", "PORT_SCAN_ATTEMPT"
    std::string severity;       // "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    std::string source;         // "/var/log/auth.log", "auditd", "collector"
    std::string description;
    uint64_t timestamp;
    std::string raw_event;
};

struct SystemTelemetry {
    double cpu_percent;
    double memory_percent;
    uint64_t memory_total_bytes;
    uint64_t memory_used_bytes;
    double disk_percent;
    uint64_t disk_total_bytes;
    uint64_t disk_used_bytes;
    uint64_t uptime_seconds;
    double load_avg_1m;
    double load_avg_5m;
    double load_avg_15m;
    std::string hostname;
    std::string os_name;
    std::string os_version;
    std::string architecture;
    uint32_t active_processes_count;
    uint32_t active_connections_count;
};

struct DeviceTelemetry {
    std::string device_id;
    std::string collector_version;
    uint64_t timestamp;         // Milliseconds epoch
    bool is_simulated{false};
    SystemTelemetry system;
    std::vector<NetworkConnection> network_connections;
    std::vector<ProcessInfo> processes;
    std::vector<SecurityEvent> security_events;
    uint64_t total_network_bytes_sent{0};
    uint64_t total_network_bytes_recv{0};
};

enum class DeviceStatus {
    PENDING,
    AUTHORIZED,
    ACTIVE,
    REVOKED,
    EXPIRED
};

enum class AnomalyLevel {
    NORMAL,
    LOW_ANOMALY,
    MEDIUM_ANOMALY,
    HIGH_ANOMALY
};

enum class RiskLevel {
    LOW,        // 0-20
    GUARDED,    // 21-40
    MEDIUM,     // 41-60
    HIGH,       // 61-80
    CRITICAL    // 81-100
};

} // namespace sentinel

#endif // SENTINEL_TELEMETRY_TYPES_HPP
