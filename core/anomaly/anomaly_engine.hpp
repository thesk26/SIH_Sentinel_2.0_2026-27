#ifndef SENTINEL_ANOMALY_ENGINE_HPP
#define SENTINEL_ANOMALY_ENGINE_HPP

#include "core/telemetry/telemetry_types.hpp"
#include "core/behaviour/behavioural_baseline.hpp"
#include <string>
#include <vector>
#include <cmath>
#include <algorithm>

namespace sentinel {

struct ExplainableFeatureFactor {
    std::string feature_name;
    double baseline_value;
    double current_value;
    double deviation_ratio;
    double contribution_weight; // 0.0 - 1.0
    std::string explanation;
};

struct AnomalyResult {
    std::string device_id;
    uint64_t timestamp;
    double anomaly_score; // 0 - 100
    AnomalyLevel level;
    std::vector<ExplainableFeatureFactor> contributing_factors;
    std::vector<std::string> summary_reasons;
};

class AnomalyDetectionEngine {
public:
    static AnomalyResult analyze(const DeviceTelemetry& telemetry, const DeviceBaseline& baseline) {
        AnomalyResult res{};
        res.device_id = telemetry.device_id;
        res.timestamp = telemetry.timestamp;

        // If baseline has insufficient samples, we return low confidence / normal
        if (baseline.total_telemetry_windows < 3) {
            res.anomaly_score = 0.0;
            res.level = AnomalyLevel::NORMAL;
            res.summary_reasons.push_back("Baseline actively learning (insufficient historical data).");
            return res;
        }

        double score_accumulator = 0.0;

        // 1. CPU Anomaly (Z-score + threshold)
        double cpu_z = baseline.cpu_stats.calculate_z_score(telemetry.system.cpu_percent);
        if (cpu_z > 2.0 && telemetry.system.cpu_percent > 70.0) {
            double impact = std::min(25.0, (cpu_z - 2.0) * 8.0);
            score_accumulator += impact;
            ExplainableFeatureFactor factor{};
            factor.feature_name = "CPU Utilization";
            factor.baseline_value = baseline.cpu_stats.mean;
            factor.current_value = telemetry.system.cpu_percent;
            factor.deviation_ratio = baseline.cpu_stats.mean > 0.1 ? (telemetry.system.cpu_percent / baseline.cpu_stats.mean) : 1.0;
            factor.contribution_weight = impact / 100.0;
            factor.explanation = "CPU usage is " + format_deviation(factor.deviation_ratio) + "x baseline (z-score: " + format_decimal(cpu_z) + ").";
            res.contributing_factors.push_back(factor);
            res.summary_reasons.push_back(factor.explanation);
        }

        // 2. Active Connections Count Deviation
        double conn_count = static_cast<double>(telemetry.network_connections.size());
        double conn_z = baseline.network_conn_count_stats.calculate_z_score(conn_count);
        if (conn_z > 2.5 || (baseline.network_conn_count_stats.mean > 0 && conn_count > baseline.network_conn_count_stats.mean * 3.5)) {
            double impact = std::min(30.0, std::max(10.0, conn_z * 7.0));
            score_accumulator += impact;
            ExplainableFeatureFactor factor{};
            factor.feature_name = "Network Connection Frequency";
            factor.baseline_value = baseline.network_conn_count_stats.mean;
            factor.current_value = conn_count;
            factor.deviation_ratio = baseline.network_conn_count_stats.mean > 0.1 ? (conn_count / baseline.network_conn_count_stats.mean) : 2.0;
            factor.contribution_weight = impact / 100.0;
            factor.explanation = "Active network connections count increased " + format_deviation(factor.deviation_ratio) + "x from baseline.";
            res.contributing_factors.push_back(factor);
            res.summary_reasons.push_back(factor.explanation);
        }

        // 3. Novel External IP Communications (Relationship novelty)
        std::vector<std::string> novel_ips;
        for (const auto& conn : telemetry.network_connections) {
            if (conn.remote_address.empty() || conn.remote_address == "0.0.0.0" || conn.remote_address == "127.0.0.1") continue;
            // Check if IP was previously unseen
            if (baseline.known_remote_ips.find(conn.remote_address) == baseline.known_remote_ips.end()) {
                if (std::find(novel_ips.begin(), novel_ips.end(), conn.remote_address) == novel_ips.end()) {
                    novel_ips.push_back(conn.remote_address);
                }
            }
        }
        if (!novel_ips.empty()) {
            double impact = std::min(35.0, novel_ips.size() * 12.0);
            score_accumulator += impact;
            ExplainableFeatureFactor factor{};
            factor.feature_name = "Novel Destination IP Interaction";
            factor.baseline_value = static_cast<double>(baseline.known_remote_ips.size());
            factor.current_value = static_cast<double>(novel_ips.size());
            factor.deviation_ratio = static_cast<double>(novel_ips.size());
            factor.contribution_weight = impact / 100.0;
            factor.explanation = "Contacted " + std::to_string(novel_ips.size()) + " previously unseen remote IP addresses (e.g. " + novel_ips[0] + ").";
            res.contributing_factors.push_back(factor);
            res.summary_reasons.push_back(factor.explanation);
        }

        // 4. Security Events / Auth Failures
        uint32_t auth_failures = 0;
        for (const auto& ev : telemetry.security_events) {
            if (ev.event_type == "AUTH_FAILURE") auth_failures++;
        }
        if (auth_failures > 0) {
            double impact = std::min(40.0, auth_failures * 15.0);
            score_accumulator += impact;
            ExplainableFeatureFactor factor{};
            factor.feature_name = "Authentication Security Events";
            factor.baseline_value = 0.0;
            factor.current_value = static_cast<double>(auth_failures);
            factor.deviation_ratio = static_cast<double>(auth_failures);
            factor.contribution_weight = impact / 100.0;
            factor.explanation = "Observed " + std::to_string(auth_failures) + " authentication failures or privilege escalation attempts.";
            res.contributing_factors.push_back(factor);
            res.summary_reasons.push_back(factor.explanation);
        }

        // Cap score at 100
        res.anomaly_score = std::min(100.0, score_accumulator);

        if (res.anomaly_score < 25.0) {
            res.level = AnomalyLevel::NORMAL;
        } else if (res.anomaly_score < 50.0) {
            res.level = AnomalyLevel::LOW_ANOMALY;
        } else if (res.anomaly_score < 75.0) {
            res.level = AnomalyLevel::MEDIUM_ANOMALY;
        } else {
            res.level = AnomalyLevel::HIGH_ANOMALY;
        }

        if (res.summary_reasons.empty()) {
            res.summary_reasons.push_back("Telemetry aligned with historical baseline profiles.");
        }

        return res;
    }

private:
    static std::string format_deviation(double val) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%.1f", val);
        return std::string(buf);
    }
    static std::string format_decimal(double val) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%.2f", val);
        return std::string(buf);
    }
};

} // namespace sentinel

#endif // SENTINEL_ANOMALY_ENGINE_HPP
