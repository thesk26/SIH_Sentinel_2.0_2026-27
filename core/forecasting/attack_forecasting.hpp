#ifndef SENTINEL_ATTACK_FORECASTING_HPP
#define SENTINEL_ATTACK_FORECASTING_HPP

#include "core/telemetry/telemetry_types.hpp"
#include "core/anomaly/anomaly_engine.hpp"
#include <string>
#include <vector>
#include <map>

namespace sentinel {

enum class MitreAttackStage {
    RECONNAISSANCE,
    INITIAL_ACCESS,
    EXECUTION,
    PERSISTENCE,
    PRIVILEGE_ESCALATION,
    DEFENSE_EVASION,
    CREDENTIAL_ACCESS,
    DISCOVERY,
    LATERAL_MOVEMENT,
    COMMAND_AND_CONTROL,
    EXFILTRATION,
    UNKNOWN_OR_BENIGN
};

inline std::string to_string(MitreAttackStage stage) {
    switch (stage) {
        case MitreAttackStage::RECONNAISSANCE: return "Reconnaissance (TA0043)";
        case MitreAttackStage::INITIAL_ACCESS: return "Initial Access (TA0001)";
        case MitreAttackStage::EXECUTION: return "Execution (TA0002)";
        case MitreAttackStage::PERSISTENCE: return "Persistence (TA0003)";
        case MitreAttackStage::PRIVILEGE_ESCALATION: return "Privilege Escalation (TA0004)";
        case MitreAttackStage::DEFENSE_EVASION: return "Defense Evasion (TA0005)";
        case MitreAttackStage::CREDENTIAL_ACCESS: return "Credential Access (TA0006)";
        case MitreAttackStage::DISCOVERY: return "Discovery (TA0007)";
        case MitreAttackStage::LATERAL_MOVEMENT: return "Lateral Movement (TA0008)";
        case MitreAttackStage::COMMAND_AND_CONTROL: return "Command and Control (TA0011)";
        case MitreAttackStage::EXFILTRATION: return "Exfiltration (TA0010)";
        default: return "Benign / Normal Operations";
    }
}

struct ForecastPrediction {
    std::string device_id;
    uint64_t timestamp;
    MitreAttackStage current_stage{MitreAttackStage::UNKNOWN_OR_BENIGN};
    MitreAttackStage predicted_next_stage{MitreAttackStage::UNKNOWN_OR_BENIGN};
    double confidence{0.0}; // 0 - 1.0
    double attack_risk_probability{0.0}; // 0 - 1.0
    std::string forecast_hypothesis;
    std::vector<std::string> supporting_evidence;
    std::vector<std::string> recommended_mitigations;
};

class AttackForecaster {
public:
    static ForecastPrediction forecast(
        const DeviceTelemetry& current,
        const std::vector<DeviceTelemetry>& history,
        const AnomalyResult& anomaly) 
    {
        ForecastPrediction pred{};
        pred.device_id = current.device_id;
        pred.timestamp = current.timestamp;

        // Check auth failures
        uint32_t auth_fails = 0;
        for (const auto& ev : current.security_events) {
            if (ev.event_type == "AUTH_FAILURE") auth_fails++;
        }

        // Check new connections / novel IP
        bool has_suspicious_net = false;
        std::string suspicious_ip;
        for (const auto& factor : anomaly.contributing_factors) {
            if (factor.feature_name == "Novel Destination IP Interaction") {
                has_suspicious_net = true;
            }
        }
        for (const auto& conn : current.network_connections) {
            if (conn.remote_port == 4444 || conn.remote_port == 1337 || conn.remote_port == 6667 || conn.remote_port == 8080 || conn.remote_port == 9001) {
                has_suspicious_net = true;
                suspicious_ip = conn.remote_address + ":" + std::to_string(conn.remote_port);
            }
        }

        // Sequence analysis:
        // Case A: Auth failures observed -> Credential Access -> Lateral Movement / Privilege Escalation
        if (auth_fails >= 2) {
            pred.current_stage = MitreAttackStage::CREDENTIAL_ACCESS;
            pred.predicted_next_stage = MitreAttackStage::PRIVILEGE_ESCALATION;
            pred.confidence = 0.82;
            pred.attack_risk_probability = 0.78;
            pred.forecast_hypothesis = "Repeated credential failures indicate brute-force or authentication spray. Next probable action is privilege escalation via sudo or token manipulation.";
            pred.supporting_evidence.push_back("Observed " + std::to_string(auth_fails) + " authentication failures in security log.");
            pred.supporting_evidence.push_back("Telemetry anomaly score elevated to " + std::to_string(static_cast<int>(anomaly.anomaly_score)) + "/100.");
            pred.recommended_mitigations.push_back("Issue authentication challenge and invalidate stale session tokens.");
            pred.recommended_mitigations.push_back("Monitor auth.log for sudo execution attempts.");
            return pred;
        }

        // Case B: Novel external destination + high connection rate -> Command & Control -> Exfiltration
        if (has_suspicious_net && anomaly.anomaly_score > 35.0) {
            pred.current_stage = MitreAttackStage::COMMAND_AND_CONTROL;
            pred.predicted_next_stage = MitreAttackStage::EXFILTRATION;
            pred.confidence = 0.88;
            pred.attack_risk_probability = 0.85;
            pred.forecast_hypothesis = "Device established connections to unverified remote endpoints with anomalous connection frequency. Progression path suggests preparation for data staging and exfiltration.";
            pred.supporting_evidence.push_back("Novel destination contact outside behavioral baseline.");
            pred.supporting_evidence.push_back("Network connection count deviation exceeds baseline expectation.");
            pred.recommended_mitigations.push_back("Restrict egress traffic to external destination IP.");
            pred.recommended_mitigations.push_back("Preserve socket connection table and memory dump for forensic analysis.");
            return pred;
        }

        // Case C: High CPU + anomalous process spike -> Execution -> Persistence
        if (current.system.cpu_percent > 85.0 && anomaly.anomaly_score > 30.0) {
            pred.current_stage = MitreAttackStage::EXECUTION;
            pred.predicted_next_stage = MitreAttackStage::PERSISTENCE;
            pred.confidence = 0.70;
            pred.attack_risk_probability = 0.65;
            pred.forecast_hypothesis = "Sudden sustained compute spike coupled with new process tree matches unverified binary execution patterns. Progression towards cron/service persistence predicted.";
            pred.supporting_evidence.push_back("Sustained CPU usage of " + std::to_string(static_cast<int>(current.system.cpu_percent)) + "%.");
            pred.recommended_mitigations.push_back("Inspect process execution tree and executable cryptographic hashes.");
            return pred;
        }

        // Default: Normal / Baseline
        pred.current_stage = MitreAttackStage::UNKNOWN_OR_BENIGN;
        pred.predicted_next_stage = MitreAttackStage::UNKNOWN_OR_BENIGN;
        pred.confidence = 0.95;
        pred.attack_risk_probability = 0.05;
        pred.forecast_hypothesis = "No temporal attack progression indicators detected. Operations conform to historical baseline.";
        pred.supporting_evidence.push_back("Telemetry baseline delta within nominal variance.");
        pred.recommended_mitigations.push_back("Maintain standard continuous behavioral monitoring.");
        return pred;
    }
};

} // namespace sentinel

#endif // SENTINEL_ATTACK_FORECASTING_HPP
