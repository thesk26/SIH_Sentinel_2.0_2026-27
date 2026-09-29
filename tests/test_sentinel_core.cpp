#include "core/telemetry/telemetry_types.hpp"
#include "core/behaviour/behavioural_baseline.hpp"
#include "core/anomaly/anomaly_engine.hpp"
#include "core/forecasting/attack_forecasting.hpp"
#include "core/risk/risk_engine.hpp"
#include "core/evidence/sha256.hpp"
#include "collector/system/system_collector.hpp"

#include <iostream>
#include <cassert>

void test_sha256() {
    std::cout << "[TEST] Running test_sha256..." << std::endl;
    std::string empty_hash = sentinel::sha256("");
    // SHA256 of empty string is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    assert(empty_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    std::string test_str = "SENTINEL_FORENSIC_EVIDENCE";
    std::string h1 = sentinel::sha256(test_str);
    std::string h2 = sentinel::sha256(test_str);
    assert(h1 == h2);
    assert(!h1.empty());
    std::cout << "  -> PASS: SHA256 verified (" << h1 << ")" << std::endl;
}

void test_baseline_and_anomaly() {
    std::cout << "[TEST] Running test_baseline_and_anomaly..." << std::endl;
    sentinel::DeviceBaseline baseline{};
    baseline.device_id = "TEST-DEVICE-01";
    baseline.total_telemetry_windows = 10;
    
    // Normal samples: CPU around 20%
    std::vector<double> cpu_samples = {18.0, 22.0, 19.5, 21.0, 20.0, 23.0, 19.0, 20.5, 21.2, 18.8};
    baseline.cpu_stats.update_from_samples(cpu_samples);
    assert(baseline.cpu_stats.mean > 18.0 && baseline.cpu_stats.mean < 23.0);
    assert(baseline.cpu_stats.stddev < 3.0);

    // Normal connections: 5
    std::vector<double> conn_samples = {5, 6, 4, 5, 5, 7, 5, 4, 6, 5};
    baseline.network_conn_count_stats.update_from_samples(conn_samples);

    baseline.known_remote_ips.insert("192.168.1.1");
    baseline.known_remote_ips.insert("8.8.8.8");

    // Test 1: Normal telemetry
    sentinel::DeviceTelemetry normal_telem{};
    normal_telem.device_id = "TEST-DEVICE-01";
    normal_telem.timestamp = 1700000000000ULL;
    normal_telem.system.cpu_percent = 21.5;
    sentinel::NetworkConnection nc1{"tcp", "192.168.1.50", 45000, "192.168.1.1", 443, "ESTABLISHED", 100, "browser"};
    normal_telem.network_connections.push_back(nc1);

    auto normal_res = sentinel::AnomalyDetectionEngine::analyze(normal_telem, baseline);
    assert(normal_res.anomaly_score < 25.0);
    assert(normal_res.level == sentinel::AnomalyLevel::NORMAL);
    std::cout << "  -> PASS: Normal telemetry scored low anomaly (" << normal_res.anomaly_score << ")" << std::endl;

    // Test 2: Anomalous telemetry (High CPU + Unseen destination + Auth failure)
    sentinel::DeviceTelemetry anomaly_telem = normal_telem;
    anomaly_telem.system.cpu_percent = 92.0;
    for (int i = 0; i < 30; ++i) {
        sentinel::NetworkConnection c{"tcp", "192.168.1.50", static_cast<uint16_t>(50000 + i), "185.220.101.5", 4444, "ESTABLISHED", 200, "malware_test"};
        anomaly_telem.network_connections.push_back(c);
    }
    sentinel::SecurityEvent ev{"EV-1", "AUTH_FAILURE", "HIGH", "auth.log", "Repeated failed login for root", 1700000000000ULL, "Failed password for root"};
    anomaly_telem.security_events.push_back(ev);

    auto anomaly_res = sentinel::AnomalyDetectionEngine::analyze(anomaly_telem, baseline);
    assert(anomaly_res.anomaly_score > 50.0);
    assert(!anomaly_res.contributing_factors.empty());
    std::cout << "  -> PASS: Anomalous telemetry detected with score " << anomaly_res.anomaly_score 
              << " (" << anomaly_res.contributing_factors.size() << " contributing factors)" << std::endl;

    // Test 3: Attack Forecasting
    auto forecast = sentinel::AttackForecaster::forecast(anomaly_telem, {}, anomaly_res);
    assert(forecast.current_stage != sentinel::MitreAttackStage::UNKNOWN_OR_BENIGN);
    assert(forecast.attack_risk_probability > 0.6);
    std::cout << "  -> PASS: Attack forecast produced stage " << sentinel::to_string(forecast.current_stage) 
              << " -> Next predicted: " << sentinel::to_string(forecast.predicted_next_stage) << std::endl;

    // Test 4: Risk Engine
    auto risk = sentinel::RiskEngine::compute_risk(anomaly_telem, anomaly_res, forecast, sentinel::DeviceStatus::AUTHORIZED);
    assert(risk.risk_score > 50.0);
    assert(risk.classification == "VERIFIED THREAT" || risk.classification == "POTENTIAL THREAT");
    std::cout << "  -> PASS: Risk engine calculated score " << risk.risk_score << " [" << risk.classification << "]" << std::endl;
}

void test_native_system_collector() {
    std::cout << "[TEST] Running test_native_system_collector..." << std::endl;
    sentinel::SystemTelemetry sys = sentinel::RealSystemCollector::collect_system_telemetry();
    assert(!sys.hostname.empty());
    assert(!sys.os_name.empty());
    assert(sys.memory_total_bytes > 0);
    std::cout << "  -> PASS: Real host detected: " << sys.hostname << " | " << sys.os_name 
              << " | Total RAM: " << (sys.memory_total_bytes / (1024 * 1024)) << " MB" << std::endl;

    auto procs = sentinel::RealSystemCollector::collect_processes(5);
    assert(!procs.empty());
    std::cout << "  -> PASS: Collected " << procs.size() << " native processes (e.g., " << procs[0].name << ")" << std::endl;
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "   SENTINEL C++ CORE VERIFICATION SUITE  " << std::endl;
    std::cout << "========================================" << std::endl;

    test_sha256();
    test_baseline_and_anomaly();
    test_native_system_collector();

    std::cout << "\nALL SENTINEL C++ TESTS COMPLETED SUCCESSFULLY!" << std::endl;
    return 0;
}
