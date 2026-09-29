#ifndef SENTINEL_BEHAVIOURAL_BASELINE_HPP
#define SENTINEL_BEHAVIOURAL_BASELINE_HPP

#include "core/telemetry/telemetry_types.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <cmath>
#include <numeric>
#include <algorithm>

namespace sentinel {

struct MetricStats {
    double mean{0.0};
    double stddev{0.0};
    double min_val{0.0};
    double max_val{0.0};
    double p25{0.0};
    double p50{0.0};
    double p75{0.0};
    double p95{0.0};
    double ewma{0.0};
    uint64_t sample_count{0};

    void update_from_samples(const std::vector<double>& samples, double ewma_alpha = 0.2) {
        if (samples.empty()) return;
        sample_count = samples.size();
        
        double sum = 0.0;
        min_val = samples[0];
        max_val = samples[0];
        for (double v : samples) {
            sum += v;
            if (v < min_val) min_val = v;
            if (v > max_val) max_val = v;
        }
        mean = sum / samples.size();

        double var_sum = 0.0;
        for (double v : samples) {
            var_sum += (v - mean) * (v - mean);
        }
        stddev = samples.size() > 1 ? std::sqrt(var_sum / (samples.size() - 1)) : 0.0;

        std::vector<double> sorted = samples;
        std::sort(sorted.begin(), sorted.end());
        p25 = percentile(sorted, 0.25);
        p50 = percentile(sorted, 0.50);
        p75 = percentile(sorted, 0.75);
        p95 = percentile(sorted, 0.95);

        // EWMA update
        ewma = samples[0];
        for (size_t i = 1; i < samples.size(); ++i) {
            ewma = (ewma_alpha * samples[i]) + ((1.0 - ewma_alpha) * ewma);
        }
    }

    double calculate_z_score(double current_val) const {
        if (stddev <= 0.0001 || sample_count < 3) return 0.0;
        return (current_val - mean) / stddev;
    }

private:
    static double percentile(const std::vector<double>& sorted, double p) {
        if (sorted.empty()) return 0.0;
        if (sorted.size() == 1) return sorted[0];
        double rank = p * (sorted.size() - 1);
        size_t low = static_cast<size_t>(std::floor(rank));
        size_t high = static_cast<size_t>(std::ceil(rank));
        double weight = rank - low;
        return (1.0 - weight) * sorted[low] + weight * sorted[high];
    }
};

struct DeviceBaseline {
    std::string device_id;
    uint64_t last_updated_epoch{0};
    uint64_t total_telemetry_windows{0};

    // Statistical profiles
    MetricStats cpu_stats;
    MetricStats memory_stats;
    MetricStats network_conn_count_stats;
    MetricStats network_bytes_tx_stats;
    MetricStats network_bytes_rx_stats;
    MetricStats active_proc_count_stats;

    // Normal discrete sets
    std::unordered_set<std::string> known_remote_ips;
    std::unordered_set<uint16_t> known_ports;
    std::unordered_set<std::string> known_process_names;
    std::unordered_map<std::string, uint64_t> ip_connection_frequency;
    std::unordered_map<int, double> hour_of_day_activity_ratio; // 0-23 hours
};

} // namespace sentinel

#endif // SENTINEL_BEHAVIOURAL_BASELINE_HPP
