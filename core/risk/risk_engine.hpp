#ifndef SENTINEL_RISK_ENGINE_HPP
#define SENTINEL_RISK_ENGINE_HPP

#include "core/telemetry/telemetry_types.hpp"
#include "core/anomaly/anomaly_engine.hpp"
#include "core/forecasting/attack_forecasting.hpp"
#include <string>
#include <vector>
#include <cmath>

namespace sentinel {

struct RiskAssessment {
    std::string device_id;
    uint64_t timestamp;
    double risk_score{0.0}; // 0 - 100
    RiskLevel risk_level{RiskLevel::LOW};
    std::string classification{"NORMAL"}; // NORMAL, ANOMALY, POTENTIAL THREAT, VERIFIED THREAT
    double confidence{0.9};
    std::vector<std::string> key_reasons;
    std::string primary_evidence;
    std::string recommended_response{"MONITOR"}; // MONITOR, INVESTIGATE, CHALLENGE, ISOLATE, PRESERVE_EVIDENCE
};

class RiskEngine {
public:
    static RiskAssessment compute_risk(
        const DeviceTelemetry& telemetry,
        const AnomalyResult& anomaly,
        const ForecastPrediction& forecast,
        DeviceStatus auth_status)
    {
        RiskAssessment risk{};
        risk.device_id = telemetry.device_id;
        risk.timestamp = telemetry.timestamp;

        // Configurable component weights:
        // W1: Authorization status (20%)
        // W2: Behavioral anomaly score (35%)
        // W3: Forecast attack probability (30%)
        // W4: Direct security events (15%)

        double auth_penalty = 0.0;
        if (auth_status == DeviceStatus::REVOKED) {
            auth_penalty = 100.0;
            risk.key_reasons.push_back("Device authorization has been explicitly REVOKED by administrator.");
        } else if (auth_status == DeviceStatus::PENDING) {
            auth_penalty = 60.0;
            risk.key_reasons.push_back("Device is in PENDING authorization state.");
        } else if (auth_status == DeviceStatus::EXPIRED) {
            auth_penalty = 70.0;
            risk.key_reasons.push_back("Device registration credentials have EXPIRED.");
        }

        double anomaly_component = anomaly.anomaly_score;
        double forecast_component = forecast.attack_risk_probability * 100.0;

        uint32_t auth_fails = 0;
        for (const auto& ev : telemetry.security_events) {
            if (ev.event_type == "AUTH_FAILURE") auth_fails++;
        }
        double sec_event_component = std::min(100.0, static_cast<double>(auth_fails * 35.0));

        // Weighted sum
        double total_score = 
            (auth_penalty * 0.20) +
            (anomaly_component * 0.35) +
            (forecast_component * 0.30) +
            (sec_event_component * 0.15);

        risk.risk_score = std::min(100.0, std::max(0.0, total_score));

        // Assign levels & response
        if (risk.risk_score <= 20.0) {
            risk.risk_level = RiskLevel::LOW;
            risk.classification = "NORMAL";
            risk.recommended_response = "MONITOR";
        } else if (risk.risk_score <= 40.0) {
            risk.risk_level = RiskLevel::GUARDED;
            risk.classification = (anomaly_component > 30.0) ? "ANOMALY" : "NORMAL";
            risk.recommended_response = "MONITOR";
        } else if (risk.risk_score <= 60.0) {
            risk.risk_level = RiskLevel::MEDIUM;
            risk.classification = "POTENTIAL THREAT";
            risk.recommended_response = "INVESTIGATE";
        } else if (risk.risk_score <= 80.0) {
            risk.risk_level = RiskLevel::HIGH;
            risk.classification = (auth_fails > 1 || forecast.confidence > 0.8) ? "VERIFIED THREAT" : "POTENTIAL THREAT";
            risk.recommended_response = "CHALLENGE";
        } else {
            risk.risk_level = RiskLevel::CRITICAL;
            risk.classification = "VERIFIED THREAT";
            risk.recommended_response = "PRESERVE_EVIDENCE_AND_ISOLATE";
        }

        // Aggregate reasons
        for (const auto& r : anomaly.summary_reasons) {
            if (r.find("insufficient") == std::string::npos && r.find("aligned") == std::string::npos) {
                risk.key_reasons.push_back(r);
            }
        }
        if (!forecast.forecast_hypothesis.empty() && forecast.attack_risk_probability > 0.3) {
            risk.key_reasons.push_back(forecast.forecast_hypothesis);
        }

        if (risk.key_reasons.empty()) {
            risk.key_reasons.push_back("Telemetry baseline confirms nominal security posture.");
        }

        risk.primary_evidence = "Telemetry timestamp: " + std::to_string(telemetry.timestamp) + 
            " | CPU: " + std::to_string(static_cast<int>(telemetry.system.cpu_percent)) + "%" +
            " | RAM: " + std::to_string(static_cast<int>(telemetry.system.memory_percent)) + "%" +
            " | Connections: " + std::to_string(telemetry.network_connections.size());

        return risk;
    }
};

} // namespace sentinel

#endif // SENTINEL_RISK_ENGINE_HPP
