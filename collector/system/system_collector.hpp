#ifndef SENTINEL_COLLECTOR_HPP
#define SENTINEL_COLLECTOR_HPP

#include "core/telemetry/telemetry_types.hpp"
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <chrono>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <sys/statvfs.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <regex>

namespace sentinel {

class RealSystemCollector {
public:
    static uint64_t get_current_epoch_ms() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    static SystemTelemetry collect_system_telemetry() {
        SystemTelemetry sys{};
        char hostname[256] = {0};
        if (gethostname(hostname, sizeof(hostname) - 1) == 0) {
            sys.hostname = hostname;
        } else {
            sys.hostname = "localhost";
        }

        struct utsname u_name;
        if (uname(&u_name) == 0) {
            sys.os_name = u_name.sysname;
            sys.os_version = u_name.release;
            sys.architecture = u_name.machine;
        } else {
            sys.os_name = "Linux";
            sys.os_version = "Unknown";
            sys.architecture = "x86_64";
        }

        // Memory & Uptime via sysinfo
        struct sysinfo si;
        if (sysinfo(&si) == 0) {
            sys.uptime_seconds = si.uptime;
            uint64_t total_ram = static_cast<uint64_t>(si.totalram) * si.mem_unit;
            uint64_t free_ram = static_cast<uint64_t>(si.freeram) * si.mem_unit;
            uint64_t buffer_ram = static_cast<uint64_t>(si.bufferram) * si.mem_unit;
            uint64_t used_ram = (total_ram > (free_ram + buffer_ram)) ? (total_ram - free_ram - buffer_ram) : (total_ram - free_ram);

            sys.memory_total_bytes = total_ram;
            sys.memory_used_bytes = used_ram;
            if (total_ram > 0) {
                sys.memory_percent = (static_cast<double>(used_ram) / static_cast<double>(total_ram)) * 100.0;
            }
            sys.load_avg_1m = si.loads[0] / 65536.0;
            sys.load_avg_5m = si.loads[1] / 65536.0;
            sys.load_avg_15m = si.loads[2] / 65536.0;
        }

        // Parse /proc/stat for CPU usage
        sys.cpu_percent = read_proc_cpu_percent();

        // Disk usage via statvfs on "/"
        struct statvfs sv;
        if (statvfs("/", &sv) == 0) {
            uint64_t total_disk = sv.f_blocks * sv.f_frsize;
            uint64_t free_disk = sv.f_bfree * sv.f_frsize;
            uint64_t used_disk = total_disk >= free_disk ? total_disk - free_disk : 0;
            sys.disk_total_bytes = total_disk;
            sys.disk_used_bytes = used_disk;
            if (total_disk > 0) {
                sys.disk_percent = (static_cast<double>(used_disk) / static_cast<double>(total_disk)) * 100.0;
            }
        }

        return sys;
    }

    static std::vector<ProcessInfo> collect_processes(size_t limit = 40) {
        std::vector<ProcessInfo> procs;
        DIR* dir = opendir("/proc");
        if (!dir) return procs;

        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_type == DT_DIR) {
                char* endptr = nullptr;
                long pid = strtol(entry->d_name, &endptr, 10);
                if (endptr && *endptr == '\0' && pid > 0) {
                    ProcessInfo p = parse_proc_pid(static_cast<uint32_t>(pid));
                    if (!p.name.empty()) {
                        procs.push_back(p);
                    }
                }
            }
        }
        closedir(dir);

        // Sort by memory/CPU and cap to prevent huge payloads
        if (procs.size() > limit) {
            procs.resize(limit);
        }
        return procs;
    }

    static std::vector<NetworkConnection> collect_network_connections(size_t limit = 60) {
        std::vector<NetworkConnection> conns;
        parse_proc_net("/proc/net/tcp", "tcp", conns);
        parse_proc_net("/proc/net/tcp6", "tcp6", conns);
        parse_proc_net("/proc/net/udp", "udp", conns);
        parse_proc_net("/proc/net/udp6", "udp6", conns);

        if (conns.size() > limit) {
            conns.resize(limit);
        }
        return conns;
    }

    static void collect_network_io_bytes(uint64_t& rx_bytes, uint64_t& tx_bytes) {
        rx_bytes = 0;
        tx_bytes = 0;
        std::ifstream file("/proc/net/dev");
        if (!file.is_open()) return;

        std::string line;
        // Skip header lines
        std::getline(file, line);
        std::getline(file, line);

        while (std::getline(file, line)) {
            size_t colon_pos = line.find(':');
            if (colon_pos == std::string::npos) continue;

            std::string iface = line.substr(0, colon_pos);
            // Ignore loopback
            if (iface.find("lo") != std::string::npos) continue;

            std::stringstream ss(line.substr(colon_pos + 1));
            uint64_t r_b = 0, r_p = 0, r_e = 0, r_d = 0, r_f = 0, r_fo = 0, r_c = 0, r_m = 0;
            uint64_t t_b = 0;
            if (ss >> r_b >> r_p >> r_e >> r_d >> r_f >> r_fo >> r_c >> r_m >> t_b) {
                rx_bytes += r_b;
                tx_bytes += t_b;
            }
        }
    }

    static std::vector<SecurityEvent> collect_security_events() {
        std::vector<SecurityEvent> events;
        // Check /var/log/auth.log or generate native kernel security audit checks
        std::ifstream auth_log("/var/log/auth.log");
        if (auth_log.is_open()) {
            std::string line;
            std::vector<std::string> lines;
            while (std::getline(auth_log, line)) {
                if (!line.empty()) lines.push_back(line);
                if (lines.size() > 500) lines.erase(lines.begin());
            }
            // Parse last 10 lines
            size_t start = lines.size() > 10 ? lines.size() - 10 : 0;
            for (size_t i = start; i < lines.size(); ++i) {
                const auto& l = lines[i];
                SecurityEvent ev{};
                ev.event_id = "EV-" + std::to_string(get_current_epoch_ms()) + "-" + std::to_string(i);
                ev.timestamp = get_current_epoch_ms();
                ev.source = "/var/log/auth.log";
                ev.raw_event = l;

                if (l.find("Failed password") != std::string::npos || l.find("authentication failure") != std::string::npos) {
                    ev.event_type = "AUTH_FAILURE";
                    ev.severity = "HIGH";
                    ev.description = "Detected failed authentication attempt in authentication log.";
                    events.push_back(ev);
                } else if (l.find("Accepted") != std::string::npos || l.find("session opened") != std::string::npos) {
                    ev.event_type = "AUTH_SUCCESS";
                    ev.severity = "INFO";
                    ev.description = "Successful session or authentication logged.";
                    events.push_back(ev);
                } else if (l.find("sudo:") != std::string::npos) {
                    ev.event_type = "PRIV_ESCALATION";
                    ev.severity = "MEDIUM";
                    ev.description = "Sudo privileged execution request.";
                    events.push_back(ev);
                }
            }
        }

        return events;
    }

private:
    static double read_proc_cpu_percent() {
        static uint64_t prev_user = 0, prev_nice = 0, prev_system = 0, prev_idle = 0;
        static uint64_t prev_iowait = 0, prev_irq = 0, prev_softirq = 0, prev_steal = 0;

        std::ifstream stat_file("/proc/stat");
        if (!stat_file.is_open()) return 0.0;

        std::string cpu_label;
        uint64_t user = 0, nice = 0, system = 0, idle = 0, iowait = 0, irq = 0, softirq = 0, steal = 0;
        stat_file >> cpu_label >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal;

        uint64_t prev_idle_all = prev_idle + prev_iowait;
        uint64_t idle_all = idle + iowait;

        uint64_t prev_non_idle = prev_user + prev_nice + prev_system + prev_irq + prev_softirq + prev_steal;
        uint64_t non_idle = user + nice + system + irq + softirq + steal;

        uint64_t prev_total = prev_idle_all + prev_non_idle;
        uint64_t total = idle_all + non_idle;

        uint64_t total_diff = total - prev_total;
        uint64_t idle_diff = idle_all - prev_idle_all;

        prev_user = user; prev_nice = nice; prev_system = system; prev_idle = idle;
        prev_iowait = iowait; prev_irq = irq; prev_softirq = softirq; prev_steal = steal;

        if (prev_total == 0 || total_diff == 0) return 0.0;
        double cpu = (static_cast<double>(total_diff - idle_diff) / static_cast<double>(total_diff)) * 100.0;
        if (cpu < 0.0) cpu = 0.0;
        if (cpu > 100.0) cpu = 100.0;
        return cpu;
    }

    static ProcessInfo parse_proc_pid(uint32_t pid) {
        ProcessInfo info{};
        info.pid = pid;

        std::string stat_path = "/proc/" + std::to_string(pid) + "/stat";
        std::ifstream stat_file(stat_path);
        if (!stat_file.is_open()) return info;

        std::string line;
        if (std::getline(stat_file, line)) {
            size_t open_paren = line.find('(');
            size_t close_paren = line.rfind(')');
            if (open_paren != std::string::npos && close_paren != std::string::npos && close_paren > open_paren) {
                info.name = line.substr(open_paren + 1, close_paren - open_paren - 1);
                std::stringstream ss(line.substr(close_paren + 2));
                char state;
                int ppid = 0;
                unsigned long utime = 0, stime = 0, rss = 0;
                long priority = 0, nice = 0, num_threads = 0;
                if (ss >> state >> ppid) {
                    info.ppid = static_cast<uint32_t>(ppid);
                }
            }
        }

        // Read cmdline
        std::string cmd_path = "/proc/" + std::to_string(pid) + "/cmdline";
        std::ifstream cmd_file(cmd_path);
        if (cmd_file.is_open()) {
            std::string cmd;
            std::getline(cmd_file, cmd, '\0');
            info.cmdline = cmd;
        }

        // Read exe link
        char exe_buf[1024] = {0};
        std::string exe_link = "/proc/" + std::to_string(pid) + "/exe";
        ssize_t len = readlink(exe_link.c_str(), exe_buf, sizeof(exe_buf) - 1);
        if (len > 0) {
            info.exe_path = std::string(exe_buf, len);
        }

        // Read status for VmRSS
        std::string status_path = "/proc/" + std::to_string(pid) + "/status";
        std::ifstream status_file(status_path);
        if (status_file.is_open()) {
            std::string sline;
            while (std::getline(status_file, sline)) {
                if (sline.rfind("VmRSS:", 0) == 0) {
                    std::stringstream ss(sline.substr(6));
                    uint64_t kb = 0;
                    if (ss >> kb) {
                        info.memory_rss_bytes = kb * 1024;
                    }
                } else if (sline.rfind("Threads:", 0) == 0) {
                    std::stringstream ss(sline.substr(8));
                    uint32_t th = 0;
                    if (ss >> th) {
                        info.thread_count = th;
                    }
                }
            }
        }

        return info;
    }

    static std::string hex_to_ip(const std::string& hex, bool is_ipv6 = false) {
        if (!is_ipv6 && hex.length() == 8) {
            uint32_t ip;
            std::stringstream ss;
            ss << std::hex << hex;
            ss >> ip;
            struct in_addr addr;
            addr.s_addr = ip;
            return inet_ntoa(addr);
        }
        return hex;
    }

    static uint16_t hex_to_port(const std::string& hex) {
        uint16_t port = 0;
        std::stringstream ss;
        ss << std::hex << hex;
        ss >> port;
        return port;
    }

    static std::string tcp_state_name(const std::string& state_hex) {
        if (state_hex == "01") return "ESTABLISHED";
        if (state_hex == "02") return "SYN_SENT";
        if (state_hex == "03") return "SYN_RECV";
        if (state_hex == "04") return "FIN_WAIT1";
        if (state_hex == "05") return "FIN_WAIT2";
        if (state_hex == "06") return "TIME_WAIT";
        if (state_hex == "07") return "CLOSE";
        if (state_hex == "08") return "CLOSE_WAIT";
        if (state_hex == "09") return "LAST_ACK";
        if (state_hex == "0A") return "LISTEN";
        if (state_hex == "0B") return "CLOSING";
        return "UNKNOWN";
    }

    static void parse_proc_net(const std::string& path, const std::string& protocol, std::vector<NetworkConnection>& conns) {
        std::ifstream file(path);
        if (!file.is_open()) return;

        std::string line;
        std::getline(file, line); // Header

        while (std::getline(file, line)) {
            std::stringstream ss(line);
            std::string sl, local, remote, st;
            if (ss >> sl >> local >> remote >> st) {
                NetworkConnection conn{};
                conn.protocol = protocol;

                size_t l_colon = local.find(':');
                if (l_colon != std::string::npos) {
                    conn.local_address = hex_to_ip(local.substr(0, l_colon));
                    conn.local_port = hex_to_port(local.substr(l_colon + 1));
                }

                size_t r_colon = remote.find(':');
                if (r_colon != std::string::npos) {
                    conn.remote_address = hex_to_ip(remote.substr(0, r_colon));
                    conn.remote_port = hex_to_port(remote.substr(r_colon + 1));
                }

                conn.state = tcp_state_name(st);

                // Add connection
                conns.push_back(conn);
            }
        }
    }
};

} // namespace sentinel

#endif // SENTINEL_COLLECTOR_HPP
