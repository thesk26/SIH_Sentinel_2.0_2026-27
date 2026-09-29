#include "core/telemetry/telemetry_types.hpp"
#include "collector/system/system_collector.hpp"
#include "core/behaviour/behavioural_baseline.hpp"
#include "core/anomaly/anomaly_engine.hpp"
#include "core/forecasting/attack_forecasting.hpp"
#include "core/risk/risk_engine.hpp"
#include "core/evidence/sha256.hpp"

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main(int argc, char** argv) {
    std::string device_id = "SENTINEL-NODE-01";
    if (argc > 1) {
        device_id = argv[1];
    }

    std::cout << "[SENTINEL-COLLECTOR] Initializing Native C++ Collector for device: " << device_id << std::endl;

    // 1. Collect real host telemetry
    sentinel::SystemTelemetry sys = sentinel::RealSystemCollector::collect_system_telemetry();
    std::vector<sentinel::ProcessInfo> procs = sentinel::RealSystemCollector::collect_processes(20);
    std::vector<sentinel::NetworkConnection> conns = sentinel::RealSystemCollector::collect_network_connections(30);
    std::vector<sentinel::SecurityEvent> events = sentinel::RealSystemCollector::collect_security_events();

    uint64_t rx_bytes = 0, tx_bytes = 0;
    sentinel::RealSystemCollector::collect_network_io_bytes(rx_bytes, tx_bytes);

    sentinel::DeviceTelemetry telem{};
    telem.device_id = device_id;
    telem.collector_version = "1.4.0-cpp20";
    telem.timestamp = sentinel::RealSystemCollector::get_current_epoch_ms();
    telem.is_simulated = false;
    telem.system = sys;
    telem.processes = procs;
    telem.network_connections = conns;
    telem.security_events = events;
    telem.total_network_bytes_recv = rx_bytes;
    telem.total_network_bytes_sent = tx_bytes;

    // Build JSON output
    json j;
    j["device_id"] = telem.device_id;
    j["collector_version"] = telem.collector_version;
    j["timestamp"] = telem.timestamp;
    j["is_simulated"] = false;

    j["system"] = {
        {"hostname", sys.hostname},
        {"os_name", sys.os_name},
        {"os_version", sys.os_version},
        {"architecture", sys.architecture},
        {"cpu_percent", sys.cpu_percent},
        {"memory_percent", sys.memory_percent},
        {"memory_total_bytes", sys.memory_total_bytes},
        {"memory_used_bytes", sys.memory_used_bytes},
        {"disk_percent", sys.disk_percent},
        {"disk_total_bytes", sys.disk_total_bytes},
        {"disk_used_bytes", sys.disk_used_bytes},
        {"uptime_seconds", sys.uptime_seconds},
        {"load_avg_1m", sys.load_avg_1m},
        {"load_avg_5m", sys.load_avg_5m},
        {"load_avg_15m", sys.load_avg_15m}
    };

    j["processes"] = json::array();
    for (const auto& p : procs) {
        j["processes"].push_back({
            {"pid", p.pid},
            {"ppid", p.ppid},
            {"name", p.name},
            {"exe_path", p.exe_path},
            {"cmdline", p.cmdline},
            {"memory_rss_bytes", p.memory_rss_bytes},
            {"thread_count", p.thread_count}
        });
    }

    j["network_connections"] = json::array();
    for (const auto& c : conns) {
        j["network_connections"].push_back({
            {"protocol", c.protocol},
            {"local_address", c.local_address},
            {"local_port", c.local_port},
            {"remote_address", c.remote_address},
            {"remote_port", c.remote_port},
            {"state", c.state}
        });
    }

    j["security_events"] = json::array();
    for (const auto& ev : events) {
        j["security_events"].push_back({
            {"event_id", ev.event_id},
            {"event_type", ev.event_type},
            {"severity", ev.severity},
            {"source", ev.source},
            {"description", ev.description},
            {"timestamp", ev.timestamp}
        });
    }

    j["network_io"] = {
        {"bytes_received", rx_bytes},
        {"bytes_sent", tx_bytes}
    };

    // Calculate Canonical SHA256 Evidence Hash
    std::string canonical_payload = j.dump();
    std::string evidence_hash = sentinel::sha256(canonical_payload);
    j["evidence_hash"] = evidence_hash;

    // Output to stdout or file
    if (argc > 2) {
        std::ofstream out(argv[2]);
        out << j.dump(2);
        std::cout << "[SENTINEL-COLLECTOR] Written telemetry snapshot to " << argv[2] << std::endl;
    } else {
        std::cout << j.dump(2) << std::endl;
    }

    return 0;
}
